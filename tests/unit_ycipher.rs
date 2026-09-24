use zaic::ycipher::*;

use zaic::ycipher::*;

#[test]
fn digest_shape() {
    let d1 = y_digest("{\"TrackList\":{}}", "0000");
    assert_eq!(d1.len(), 32);
    assert!(d1.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(d1, y_digest("{\"TrackList\":{}}", "0000"));
    assert_ne!(d1, y_digest("{\"TrackList\":{} ", "0000"));
    assert_ne!(d1, y_digest("{\"TrackList\":{}}", "0001"));
}

#[test]
fn utf8_preprocessing() {
    let d = y_digest("µ", "0000");
    assert_eq!(d.len(), 32);
}
