use crate::crypto::Rng;
use crate::pop::Form;
use crate::rt::Intel;

pub fn cloudauth_form(intel: &Intel, rng: &mut Rng, action: &'static str, data: String) -> Form {
    let mut f = Form::new(intel.cloudauth_secret.as_bytes());
    f.push("AaduaneId", intel.cloudauth_duane.clone());
    f.push("Version", intel.cloudauth_version.clone());
    f.push("SignatureMethod", "HMAC-SHA1".into());
    f.push("SignatureVersion", "1.0".into());
    f.push("Format", "JSON".into());
    f.push("Action", action.into());
    f.push("Data", data);
    f.push("SignatureNonce", rng.uuid_v4());
    f
}
