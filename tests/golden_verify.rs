use zaic::crypto::b64_encode;
use zaic::keys::SessionKeys;
use zaic::verify::r_cipher;

fn golden_web_and_table() -> ([u8; 16], [u8; 64]) {
    let web: [u8; 16] = *b"3e627e1b4c63f913";
    let pe = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bundles/pe.js"),
    )
    .expect("bundles/pe.js");
    let table = zaic::rt::extract_r_table(&pe).expect("R-таблица из pe.js");
    (web, table)
}

#[test]
fn live_r_cipher_vector() {
    let (web, table) = golden_web_and_table();

    let deflate_b64 = "eJx1j0GLwkAMhf/KknOQZCYmM4LXZRUPguKea7d1ixSWtros4n932q6HHrzkJfkeL4RIHBVePDkRUTMqA2vhv7JgR47+Bvsmy8+bqu1gcYM6hwUEhzyPKGaKb8iA0PXrpPVlgu2Ji3/8M8FuhPV1pOd21LJKOoTzYGi7rOn2VZ1C2ELU6JSUjBLpnewCYSDCebo3DH1jjlDTUv1MoiP1zyqDB+44PrZ7GX4omqr8myKmIBEha07p8Mc7tevP/HfF4Xt7Wi7h/gBeKVDH";
    let deflate = zaic::crypto::b64_decode(deflate_b64).expect("deflate b64");
    assert_eq!(deflate.len(), 204, "deflate вектор");

    let expected_b64 = "JRMlgg1EDAVARgILRQRNM0T0U3gZByN+b34ZFFpTIx86iEWM63Z7Hy0WEYJf2uMVMrdifmqNKnC06LHur5J1JXcnCGcQW21iGTbtfQ8ybKYjdT8cD8tPdO5rc0h8GWb2qx5RPsJVTfIZYWhCeIok2Aykj3x1nyVg+A2sdHs1aslOhCALFDUoYQAVWzhHsjUANnUB3yewejx4ER5gISeLMVtzbD0XnwxbMXNdf2IjCCAUckhBUTGdA/GPrTULa2A2WSx8OGNlBjBOShsHNQ8+JwlzDztcGxw5sulZtTUZS81LTXVHtN05TU2Awxlxc2aeHENvjFs8GS99Ot92ZnBRRXU8KDVWCD4wU2cUb0VdNi0=";
    let expected = zaic::crypto::b64_decode(expected_b64).expect("blob b64");
    assert_eq!(expected.len(), 272, "блоб вектор");

    let got = r_cipher(deflate_b64, &web, &table);
    assert_eq!(got.len(), expected.len(), "длина R-шифра");
    let eq = got.iter().zip(expected.iter()).filter(|(a, b)| a == b).count();
    assert_eq!(eq, expected.len(), "R-шифр байт-в-байт против живого захвата (совпало {} из {})", eq, expected.len());
}

#[test]
fn r_cipher_determinism() {
    let (web, table) = golden_web_and_table();
    let a = r_cipher("AAAAAAAAAAAAAAAAAAAAAAAA", &web, &table);
    let b = r_cipher("AAAAAAAAAAAAAAAAAAAAAAAA", &web, &table);
    assert_eq!(a, b, "детерминизм при фиксированном ключе");
    assert_ne!(a, r_cipher("AAAAAAAAAAAAAAAAAAAAAAAB", &web, &table));
}

#[test]
fn verify_param_b64() {
    let p = zaic::verify::captcha_verify_param("AbCd123", "didk33e0");
    assert_eq!(p, b64_encode(br#"{"certifyId":"AbCd123","sceneId":"didk33e0","isSign":true}"#));
}
