use crate::Asn1Error;

pub(crate) fn validate_integer_octets(bytes: &[u8]) -> Result<(), Asn1Error> {
    match bytes {
        [] => Err(Asn1Error::MalformedValue),
        // 多餘的符號位元組（X.690 8.3.2），BER 也禁止。
        [0x00, next, ..] if next & 0x80 == 0 => Err(Asn1Error::MalformedValue),
        [0xFF, next, ..] if next & 0x80 != 0 => Err(Asn1Error::MalformedValue),
        _ => Ok(()),
    }
}

pub(crate) fn minimal_signed(mut bytes: &[u8]) -> &[u8] {
    while let [first, next, ..] = bytes {
        let redundant =
            (*first == 0x00 && next & 0x80 == 0) || (*first == 0xFF && next & 0x80 != 0);
        if !redundant {
            break;
        }
        bytes = &bytes[1..];
    }
    bytes
}
