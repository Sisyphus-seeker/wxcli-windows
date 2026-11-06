use hmac::{Hmac, KeyInit, Mac};
use sha2_hmac::Sha512;

#[test]
fn hmac_sha512_matches_rfc4231() {
    let mut mac = Hmac::<Sha512>::new_from_slice(&[0x0b; 20]).unwrap();
    mac.update(b"Hi There");
    let actual: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual,
        concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        )
    );
}
