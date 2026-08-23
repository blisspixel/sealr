use thiserror::Error;

pub(crate) const FRAME_LEN: usize = 96;
const MAGIC: &[u8; 8] = b"SLRAB001";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Kind {
    Bootstrap = 1,
    RestrictedReady = 2,
    Source = 3,
    Accepted = 4,
    Proceed = 5,
    Result = 6,
    ExitAck = 7,
    Error = 8,
    Checkpoint = 9,
}

impl TryFrom<u8> for Kind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::RestrictedReady),
            3 => Ok(Self::Source),
            4 => Ok(Self::Accepted),
            5 => Ok(Self::Proceed),
            6 => Ok(Self::Result),
            7 => Ok(Self::ExitAck),
            8 => Ok(Self::Error),
            9 => Ok(Self::Checkpoint),
            _ => Err(FrameError::Kind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Frame {
    pub(crate) kind: Kind,
    pub(crate) flags: u8,
    pub(crate) operation_id: [u8; 16],
    pub(crate) values: [u64; 4],
}

impl Frame {
    pub(crate) fn new(kind: Kind, operation_id: [u8; 16]) -> Self {
        Self {
            kind,
            flags: 0,
            operation_id,
            values: [0; 4],
        }
    }

    pub(crate) fn encode(self) -> [u8; FRAME_LEN] {
        let mut output = [0_u8; FRAME_LEN];
        output[..8].copy_from_slice(MAGIC);
        output[8..10].copy_from_slice(&VERSION.to_le_bytes());
        output[10] = self.kind as u8;
        output[11] = self.flags;
        output[12..28].copy_from_slice(&self.operation_id);
        for (index, value) in self.values.iter().enumerate() {
            let start = 28 + index * 8;
            output[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        output
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, FrameError> {
        if input.len() != FRAME_LEN {
            return Err(FrameError::Length(input.len()));
        }
        if &input[..8] != MAGIC {
            return Err(FrameError::Magic);
        }
        let version = u16::from_le_bytes([input[8], input[9]]);
        if version != VERSION {
            return Err(FrameError::Version(version));
        }
        if input[60..].iter().any(|byte| *byte != 0) {
            return Err(FrameError::Reserved);
        }

        let mut operation_id = [0_u8; 16];
        operation_id.copy_from_slice(&input[12..28]);
        if operation_id == [0; 16] {
            return Err(FrameError::ZeroOperationId);
        }

        let mut values = [0_u64; 4];
        for (index, value) in values.iter_mut().enumerate() {
            let start = 28 + index * 8;
            *value = u64::from_le_bytes(
                input[start..start + 8]
                    .try_into()
                    .expect("fixed frame value width"),
            );
        }

        Ok(Self {
            kind: Kind::try_from(input[10])?,
            flags: input[11],
            operation_id,
            values,
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum FrameError {
    #[error("bootstrap frame length {0} is not {FRAME_LEN}")]
    Length(usize),
    #[error("bootstrap frame magic is invalid")]
    Magic,
    #[error("bootstrap frame version {0} is unsupported")]
    Version(u16),
    #[error("bootstrap frame kind {0} is unsupported")]
    Kind(u8),
    #[error("bootstrap frame operation ID is zero")]
    ZeroOperationId,
    #[error("bootstrap frame reserved bytes are nonzero")]
    Reserved,
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    #[test]
    fn golden_bootstrap_frame_is_stable() {
        let mut frame = Frame::new(Kind::Bootstrap, OPERATION_ID);
        frame.flags = 1;
        frame.values = [0x0102_0304_0506_0708, 9, 10, 0o40700];
        let encoded = frame.encode();

        assert_eq!(&encoded[..12], b"SLRAB001\x01\x00\x01\x01");
        assert_eq!(&encoded[12..28], &OPERATION_ID);
        assert_eq!(
            &encoded[28..36],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(Frame::decode(&encoded), Ok(frame));
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in [
            Kind::Bootstrap,
            Kind::RestrictedReady,
            Kind::Source,
            Kind::Accepted,
            Kind::Proceed,
            Kind::Result,
            Kind::ExitAck,
            Kind::Error,
            Kind::Checkpoint,
        ] {
            let frame = Frame::new(kind, OPERATION_ID);
            assert_eq!(Frame::decode(&frame.encode()), Ok(frame));
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let encoded = Frame::new(Kind::Bootstrap, OPERATION_ID).encode();
        for length in 0..FRAME_LEN {
            assert_eq!(
                Frame::decode(&encoded[..length]),
                Err(FrameError::Length(length))
            );
        }
    }

    #[test]
    fn structural_mutations_are_rejected() {
        let encoded = Frame::new(Kind::Bootstrap, OPERATION_ID).encode();
        let cases = [
            (0, FrameError::Magic),
            (8, FrameError::Version(0)),
            (10, FrameError::Kind(0)),
            (12, FrameError::ZeroOperationId),
            (60, FrameError::Reserved),
        ];

        for (index, expected) in cases {
            let mut mutated = encoded;
            if index == 12 {
                mutated[12..28].fill(0);
            } else {
                mutated[index] ^= 1;
            }
            assert_eq!(Frame::decode(&mutated), Err(expected));
        }
    }

    #[test]
    fn trailing_input_is_rejected() {
        let mut input = Frame::new(Kind::Bootstrap, OPERATION_ID).encode().to_vec();
        input.push(0);
        assert_eq!(
            Frame::decode(&input),
            Err(FrameError::Length(FRAME_LEN + 1))
        );
    }
}
