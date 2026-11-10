//! RFC 5280 §4.2.1.12 `ExtendedKeyUsage`, the value of extension 2.5.29.37.
//!
//! ```text
//! ExtendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
//! KeyPurposeId ::= OBJECT IDENTIFIER
//! ```
//!
//! The applications a key may serve, where [`KeyUsage`](crate::ext::KeyUsage)
//! lists the cryptographic operations. Any OID is accepted and kept in
//! order; [`KeyPurposeId`] supplies names for the known ones. What
//! `anyExtendedKeyUsage` permits and how the list combines with KeyUsage
//! are validation questions, not this type's.

use alloc::vec::Vec;
use core::fmt;

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged,
};

use crate::ext::KeyPurposeId;

/// A non-empty list of key purposes.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{ExtendedKeyUsage, KeyPurposeId};
///
/// // A TLS certificate usable on both ends.
/// let eku = ExtendedKeyUsage::new(vec![
///     KeyPurposeId::SERVER_AUTH.oid(),
///     KeyPurposeId::CLIENT_AUTH.oid(),
/// ])?;
/// assert!(eku.contains(KeyPurposeId::SERVER_AUTH));
/// assert!(!eku.contains(KeyPurposeId::CODE_SIGNING));
/// println!("{eku}");   // serverAuth, clientAuth
///
/// let der = eku.encode_to_vec(&EncodingOptions::DER)?;
/// let (_, back) = ExtendedKeyUsage::decode(&der, &DecodingOptions::default())?;
/// assert_eq!(back, eku);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ExtendedKeyUsage {
    purposes: Asn1SequenceOf<Asn1Oid>,
}

impl ExtendedKeyUsage {
    /// An empty list violates `SIZE (1..MAX)` and is `MalformedValue`.
    pub fn new(purposes: Vec<Asn1Oid>) -> Result<Self, Asn1Error> {
        if purposes.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            purposes: Asn1SequenceOf::new(purposes),
        })
    }

    /// The purposes in order, never empty.
    pub fn purposes(&self) -> &[Asn1Oid] {
        self.purposes.elements()
    }

    /// Whether the purpose is listed; takes a [`KeyPurposeId`] constant or an
    /// `Asn1Oid`. `anyExtendedKeyUsage` is not treated specially.
    /// Variable time; for public values.
    pub fn contains(&self, purpose: impl PartialEq<Asn1Oid>) -> bool {
        self.purposes().iter().any(|oid| purpose == *oid)
    }
}

/// The purposes by name where [`KeyPurposeId`] knows them, as dotted OIDs
/// otherwise, comma separated, in order.
impl fmt::Display for ExtendedKeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, oid) in self.purposes().iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            match KeyPurposeId::from_oid(oid) {
                Some(known) => write!(f, "{known}")?,
                None => write!(f, "{oid}")?,
            }
        }
        Ok(())
    }
}

impl DecodeInner for ExtendedKeyUsage {
    /// An empty SEQUENCE is `MalformedValue`. Variable time: branches only
    /// on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, purposes) = Asn1SequenceOf::decode_inner(buff, context)?;
        if purposes.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((used, Self { purposes }))
    }
}

impl Decode for ExtendedKeyUsage {}

impl Tagged for ExtendedKeyUsage {
    const TAG: &'static [u8] = Asn1SequenceOf::<Asn1Oid>::TAG;
}

impl EncodeContent for ExtendedKeyUsage {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.purposes.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.purposes.encode_content(rules, out)
    }
}

impl EncodeTagged for ExtendedKeyUsage {}

impl Encode for ExtendedKeyUsage {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Error, Asn1Oid, Decode, DecodingContext, DecodingOptions, Encode, EncodingOptions,
    };

    use super::ExtendedKeyUsage;
    use crate::ext::{Extension, ExtensionId, KeyPurposeId};

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// serverAuth, clientAuth
    const TLS: &[u8] =
        b"\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02";

    #[test]
    fn purposes_round_trip_in_order_and_print_by_name() {
        let eku = ExtendedKeyUsage::new(Vec::from([
            KeyPurposeId::SERVER_AUTH.oid(),
            KeyPurposeId::CLIENT_AUTH.oid(),
        ]))
        .unwrap();
        assert_eq!(eku.encode_to_vec(&der()).unwrap(), TLS);
        let (used, decoded) = ExtendedKeyUsage::decode(TLS, &options()).unwrap();
        assert_eq!((used, &decoded), (TLS.len(), &eku));
        assert_eq!(decoded.to_string(), "serverAuth, clientAuth");
        assert_eq!(decoded.purposes()[0], KeyPurposeId::SERVER_AUTH);

        let reversed = ExtendedKeyUsage::new(Vec::from([
            KeyPurposeId::CLIENT_AUTH.oid(),
            KeyPurposeId::SERVER_AUTH.oid(),
        ]))
        .unwrap();
        assert_ne!(reversed, eku);
        assert_ne!(reversed.encode_to_vec(&der()).unwrap(), TLS);
    }

    #[test]
    fn unknown_purposes_are_kept_and_printed_as_oids() {
        let smart_card: Asn1Oid = "1.3.6.1.4.1.311.20.2.2".parse().unwrap();
        let private: Asn1Oid = "1.2.3.4".parse().unwrap();
        let eku = ExtendedKeyUsage::new(Vec::from([smart_card.clone(), private.clone()])).unwrap();
        let wire = eku.encode_to_vec(&der()).unwrap();
        let (_, decoded) = ExtendedKeyUsage::decode(&wire, &options()).unwrap();
        assert_eq!(decoded, eku);
        assert_eq!(decoded.to_string(), "smartcardLogon, 1.2.3.4");
        assert!(decoded.contains(KeyPurposeId::SMARTCARD_LOGON));
        assert!(decoded.contains(private));
        assert!(!decoded.contains(KeyPurposeId::ANY_EXTENDED_KEY_USAGE));
    }

    #[test]
    fn an_empty_list_is_rejected_when_built_or_decoded() {
        assert!(matches!(
            ExtendedKeyUsage::new(Vec::new()),
            Err(Asn1Error::MalformedValue)
        ));
        assert!(matches!(
            ExtendedKeyUsage::decode(b"\x30\x00", &options()),
            Err(Asn1Error::MalformedValue)
        ));
    }

    #[test]
    fn anything_but_oids_in_a_sequence_is_rejected() {
        let mut as_set: Vec<u8> = TLS.to_vec();
        as_set[0] = 0x31;
        assert!(matches!(
            ExtendedKeyUsage::decode(&as_set, &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
        assert!(matches!(
            ExtendedKeyUsage::decode(b"\x30\x03\x02\x01\x01", &options()),
            Err(Asn1Error::UnexpectedTag)
        ));
    }

    #[test]
    fn it_travels_inside_an_extension() {
        let eku = ExtendedKeyUsage::new(Vec::from([KeyPurposeId::OCSP_SIGNING.oid()])).unwrap();
        let extension = Extension::new(
            ExtensionId::EXT_KEY_USAGE,
            false,
            &eku.encode_to_vec(&der()).unwrap(),
        );
        assert_eq!(extension.extn_id().to_string(), "2.5.29.37");
        let (_, back) =
            Extension::decode(&extension.encode_to_vec(&der()).unwrap(), &options()).unwrap();
        let mut context = DecodingContext::new(options());
        assert_eq!(
            back.extn_value_as::<ExtendedKeyUsage>(&mut context)
                .unwrap(),
            eku
        );
    }
}
