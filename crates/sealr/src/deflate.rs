//! Raw Deflate reads terminate only at the decoder's explicit stream end.
//!
//! Input EOF is not proof of a complete RFC 1951 stream, even when all expected
//! bytes have been emitted and their checksums match. Keep completion separate
//! from input consumption for both ZIP member verification and gzip framing.

use std::io::{self, BufRead, Read};

use flate2::{Decompress, FlushDecompress, Status};

pub(crate) struct DeflateDecoder<R> {
    input: R,
    decoder: Decompress,
    ended: bool,
    failed: bool,
}

impl<R: BufRead> DeflateDecoder<R> {
    pub(crate) fn new(input: R) -> Self {
        Self {
            input,
            decoder: Decompress::new(false),
            ended: false,
            failed: false,
        }
    }

    pub(crate) fn total_in(&self) -> u64 {
        self.decoder.total_in()
    }

    pub(crate) fn total_out(&self) -> u64 {
        self.decoder.total_out()
    }
}

impl<R: BufRead> Read for DeflateDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.ended {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Deflate decoder previously failed",
            ));
        }
        loop {
            let input = match self.input.fill_buf() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            let input_empty = input.is_empty();
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = match self
                .decoder
                .decompress(input, output, FlushDecompress::None)
            {
                Ok(status) => status,
                Err(_) => {
                    self.failed = true;
                    // Preserve the syntax-error diagnostic bound by historical
                    // evidence. Incomplete EOF has its own diagnostic.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "corrupt deflate stream",
                    ));
                }
            };
            // Both deltas are bounded by the supplied slices, including on
            // 32-bit targets. No hostile declared size drives an allocation.
            let consumed = (self.decoder.total_in() - before_in) as usize;
            let produced = (self.decoder.total_out() - before_out) as usize;
            self.input.consume(consumed);
            self.ended = status == Status::StreamEnd;
            if produced != 0 || self.ended {
                return Ok(produced);
            }
            if consumed == 0 {
                self.failed = true;
                return Err(io::Error::new(
                    if input_empty {
                        io::ErrorKind::UnexpectedEof
                    } else {
                        io::ErrorKind::InvalidData
                    },
                    "Deflate stream did not reach an explicit end",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    // CPython 3.12.10/zlib producer, fixed-Huffman block for LATIN = 1\n.
    const COMPLETE: &[u8] = &[
        0xf3, 0x71, 0x0c, 0xf1, 0xf4, 0x53, 0xb0, 0x55, 0x30, 0xe4, 0x02, 0x00,
    ];

    #[test]
    fn output_and_consumption_do_not_substitute_for_stream_completion() {
        let mut incomplete = COMPLETE.to_vec();
        incomplete[0] &= !1;
        let mut decoder = DeflateDecoder::new(incomplete.as_slice());
        let mut output = Vec::new();
        let error = decoder.read_to_end(&mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(output, b"LATIN = 1\n");
        assert_eq!(decoder.total_in(), COMPLETE.len() as u64);
        assert!(!decoder.ended);
        assert!(decoder.read(&mut [0; 1]).is_err());
    }

    #[test]
    fn every_truncated_prefix_is_denied_with_short_reads() {
        for end in 0..COMPLETE.len() {
            for input_cap in [1, 2, 64] {
                let mut decoder =
                    DeflateDecoder::new(BufReader::with_capacity(input_cap, &COMPLETE[..end]));
                let mut output = Vec::new();
                assert!(
                    decoder.read_to_end(&mut output).is_err(),
                    "end={end}, capacity={input_cap}"
                );
            }
        }
    }

    #[test]
    fn exact_end_preserves_trailing_input_with_tiny_buffers() {
        let source = [COMPLETE, b"trailer"].concat();
        for input_cap in [1, 2, 64] {
            for output_cap in [1, 2, 64] {
                let input = BufReader::with_capacity(input_cap, source.as_slice());
                let mut decoder = DeflateDecoder::new(input);
                assert_eq!(decoder.read(&mut []).unwrap(), 0);
                let mut output = Vec::new();
                let mut buffer = vec![0; output_cap];
                loop {
                    let read = decoder.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    output.extend_from_slice(&buffer[..read]);
                }
                assert_eq!(output, b"LATIN = 1\n");
                assert_eq!(decoder.total_in(), COMPLETE.len() as u64);
                assert_eq!(decoder.total_out(), output.len() as u64);
                let mut trailer = Vec::new();
                decoder.input.read_to_end(&mut trailer).unwrap();
                assert_eq!(trailer, b"trailer");
            }
        }
    }

    #[test]
    fn an_empty_member_still_requires_a_complete_stream() {
        let mut decoder = DeflateDecoder::new(&[3, 0][..]);
        assert_eq!(decoder.read(&mut [0; 1]).unwrap(), 0);
        assert!(decoder.ended);
        let mut decoder = DeflateDecoder::new(&[2, 0][..]);
        assert!(decoder.read(&mut [0; 1]).is_err());
    }
}
