use sealr::{apply, MemberReadErrorKind, Policy, Request, Source, VerifiedArchive};

// A canonical ZIP32 archive containing stored `hello.txt` with bytes `hello`.
const HELLO_ZIP: &[u8] = &[
    // Local file header.
    0x50, 0x4b, 0x03, 0x04, // signature
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    b'h', b'e', b'l', b'l', b'o', // payload
    // Central directory header.
    0x50, 0x4b, 0x01, 0x02, // signature
    0x14, 0x00, // version made by
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    0x00, 0x00, // comment length
    0x00, 0x00, // disk start
    0x00, 0x00, // internal attributes
    0x00, 0x00, 0x00, 0x00, // external attributes
    0x00, 0x00, 0x00, 0x00, // local-header offset
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    // End of central directory.
    0x50, 0x4b, 0x05, 0x06, // signature
    0x00, 0x00, 0x00, 0x00, // disk numbers
    0x01, 0x00, 0x01, 0x00, // entry counts
    0x37, 0x00, 0x00, 0x00, // central-directory size: 55
    0x2c, 0x00, 0x00, 0x00, // central-directory offset: 44
    0x00, 0x00, // comment length
];

fn main() {
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("hello.zip"),
            data: HELLO_ZIP,
        },
        policy: &policy,
        dest: None,
    });

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    let archive: &VerifiedArchive = outcome
        .verified_archive()
        .expect("admitted archive must expose verified authority");
    assert_eq!(archive.read_member("hello.txt", 5).unwrap(), b"hello");
    assert_eq!(
        archive.read_member("hello.txt", 4).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );

    let retained: VerifiedArchive = outcome
        .into_verified_archive()
        .expect("capability remains available when taken from the outcome");
    assert_eq!(retained.member("hello.txt").unwrap().canonical_path, "hello.txt");
}
