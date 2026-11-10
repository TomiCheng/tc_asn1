//! RFC 5280 §4.1.2.9 `Extension`.
//!
//! ```text
//! Extension ::= SEQUENCE {
//!     extnID      OBJECT IDENTIFIER,
//!     critical    BOOLEAN DEFAULT FALSE,
//!     extnValue   OCTET STRING   -- contains the DER encoding of the value
//! }
//! ```
//!
//! `extnValue` wraps the extension's own DER encoding, so a value is read in
//! two steps: the `Extension`, then [`Extension::extn_value_as`] for the typed
//! contents once `extnID` says what they are.

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Decode, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// One certificate extension. `critical` is kept as the ASN.1 value so the
/// encoder can leave the DEFAULT out; the accessors speak `bool` and `&[u8]`.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_x509::ext::{Extension, ExtensionId};
///
/// // basicConstraints, critical, with value SEQUENCE { cA TRUE }
/// let ext = Extension::new(ExtensionId::BASIC_CONSTRAINTS, true, &[0x30, 0x03, 0x01, 0x01, 0xFF]);
/// let out = ext.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(
///     out,
///     [0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF],
/// );
/// let (_, back) = Extension::decode(&out, &DecodingOptions::default())?;
/// assert!(back.critical());
/// assert_eq!(back.extn_id().to_string(), "2.5.29.19");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extension {
    extn_id: Asn1Oid,
    critical: Asn1Boolean,
    extn_value: Asn1OctetString,
}

impl Extension {
    /// `extn_value` is the extension's **already encoded** inner DER value.
    pub fn new(extn_id: impl Into<Asn1Oid>, critical: bool, extn_value: &[u8]) -> Self {
        Self {
            extn_id: extn_id.into(),
            critical: critical.into(),
            extn_value: Asn1OctetString::new(extn_value),
        }
    }

    /// `new` with the value DER-encoded here, for values this crate has a
    /// type for.
    pub fn with_value(
        extn_id: impl Into<Asn1Oid>,
        critical: bool,
        value: &impl Encode,
    ) -> Result<Self, Asn1Error> {
        let der = value.encode_to_vec(&EncodingOptions::DER)?;
        Ok(Self::new(extn_id, critical, &der))
    }

    /// The extension's OID.
    pub fn extn_id(&self) -> &Asn1Oid {
        &self.extn_id
    }

    /// Whether a reader that does not know the extension must reject the
    /// certificate.
    pub fn critical(&self) -> bool {
        self.critical.is_true()
    }

    /// The raw inner DER, for values this crate has no type for.
    pub fn extn_value(&self) -> &[u8] {
        self.extn_value.as_bytes()
    }

    /// Decodes `extnValue` as `T`. RFC 5280 §4.1 requires the inner value to be
    /// DER, so the DER rules apply and the value must fill the octets exactly.
    /// Variable time: branches only on the encoding structure.
    pub fn extn_value_as<T: DecodeInner>(
        &self,
        context: &mut DecodingContext,
    ) -> Result<T, Asn1Error> {
        let bytes = self.extn_value.as_bytes();
        let mut der = context.enter_der();
        let (used, value) = T::decode_inner(bytes, der.context())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
}

impl DecodeInner for Extension {
    /// `critical` is taken only when a BOOLEAN comes next; an explicit FALSE
    /// is `NotDer` under DER. Variable time: branches only on the structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let extn_id: Asn1Oid = children.get()?;
        let critical = children.get_default(Asn1Boolean::from(false))?;
        let extn_value: Asn1OctetString = children.get()?;
        children.end()?;
        Ok((
            element.total_len(),
            Self {
                extn_id,
                critical,
                extn_value,
            },
        ))
    }
}

impl Decode for Extension {}
impl Tagged for Extension {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for Extension {
    /// `critical` is written only when TRUE: the DEFAULT is omitted under
    /// every rule set (mandatory for DER, X.690 §11.5).
    /// Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = self.extn_id.encoded_len(rules);
        len += if self.critical.is_true() {
            self.critical.encoded_len(rules)
        } else {
            0
        };
        len += self.extn_value.encoded_len(rules);
        len
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.extn_id.encode(rules, out)?;
        if self.critical.is_true() {
            at += self.critical.encode(rules, &mut out[at..])?;
        }
        at += self.extn_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for Extension {}

impl Encode for Extension {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(tag::SEQUENCE, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(tag::SEQUENCE, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1BitString, Asn1Error, Asn1Object, Asn1Oid, Decode, DecodingContext, DecodingOptions,
        Encode, EncodingOptions,
    };

    use super::Extension;

    /// basicConstraints (2.5.29.19), critical, value SEQUENCE { cA TRUE }.
    const CRITICAL: [u8; 17] = [
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xFF,
    ];
    /// keyUsage (2.5.29.15), critical omitted, value BIT STRING 05 A0.
    const PLAIN: [u8; 13] = [
        0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xA0,
    ];

    fn der() -> EncodingOptions {
        EncodingOptions::DER
    }

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    #[test]
    fn a_critical_extension_round_trips_with_the_boolean_written() {
        let (used, ext) = Extension::decode(&CRITICAL, &options()).unwrap();
        assert_eq!(used, CRITICAL.len());
        assert!(ext.critical());
        assert_eq!(ext.extn_id().to_string(), "2.5.29.19");
        assert_eq!(ext.extn_value(), [0x30, 0x03, 0x01, 0x01, 0xFF]);
        assert_eq!(ext.encode_to_vec(&der()).unwrap(), CRITICAL);
        assert_eq!(
            Extension::new(
                "2.5.29.19".parse::<Asn1Oid>().unwrap(),
                true,
                &[0x30, 0x03, 0x01, 0x01, 0xFF]
            ),
            ext
        );
    }

    #[test]
    fn an_omitted_critical_reads_as_false_and_stays_omitted() {
        let (_, ext) = Extension::decode(&PLAIN, &options()).unwrap();
        assert!(!ext.critical());
        assert_eq!(ext.encode_to_vec(&der()).unwrap(), PLAIN);
    }

    #[test]
    fn an_explicit_false_is_ber_only_and_is_normalized_away() {
        let mut explicit_false: Vec<u8> = PLAIN.to_vec();
        explicit_false.splice(7..7, [0x01, 0x01, 0x00]);
        explicit_false[1] += 3;
        let (_, ext) = Extension::decode(&explicit_false, &options()).unwrap();
        assert!(!ext.critical());
        assert_eq!(ext.encode_to_vec(&der()).unwrap(), PLAIN);
        assert!(matches!(
            Extension::decode_der(&explicit_false, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn a_ber_true_of_01_is_true_but_not_der() {
        let mut ber_true = CRITICAL;
        ber_true[9] = 0x01;
        assert!(
            Extension::decode(&ber_true, &options())
                .unwrap()
                .1
                .critical()
        );
        assert!(matches!(
            Extension::decode_der(&ber_true, &options()),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn the_inner_value_decodes_as_its_type_and_must_be_exact_der() {
        let mut context = DecodingContext::new(options());
        let (_, ext) = Extension::decode(&CRITICAL, &options()).unwrap();
        let tree: Asn1Object = ext.extn_value_as(&mut context).unwrap();
        assert_eq!(tree.to_string(), "SEQUENCE\n  BOOLEAN TRUE\n");
        let (_, ext) = Extension::decode(&PLAIN, &options()).unwrap();
        let bits: Asn1BitString = ext.extn_value_as(&mut context).unwrap();
        assert_eq!((bits.as_bytes(), bits.unused_bits()), (&[0xA0][..], 5));

        let padded = Extension::new(
            "2.5.29.15".parse::<Asn1Oid>().unwrap(),
            false,
            &[0x03, 0x02, 0x05, 0xA0, 0x00],
        );
        assert!(matches!(
            padded.extn_value_as::<Asn1BitString>(&mut context),
            Err(Asn1Error::TrailingData)
        ));
        let ber_inner = Extension::new(
            "2.5.29.15".parse::<Asn1Oid>().unwrap(),
            false,
            &[0x03, 0x80, 0x03, 0x02, 0x05, 0xA0, 0x00, 0x00],
        );
        assert!(matches!(
            ber_inner.extn_value_as::<Asn1BitString>(&mut context),
            Err(Asn1Error::NotDer)
        ));
    }

    #[test]
    fn missing_fields_and_extra_fields_are_rejected() {
        let no_value = [0x30, 0x05, 0x06, 0x03, 0x55, 0x1D, 0x0F];
        assert!(matches!(
            Extension::decode(&no_value, &options()),
            Err(Asn1Error::Truncated)
        ));
        let critical_only = [0x30, 0x08, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF];
        assert!(matches!(
            Extension::decode(&critical_only, &options()),
            Err(Asn1Error::Truncated)
        ));
        let mut extra: Vec<u8> = PLAIN.to_vec();
        extra.extend_from_slice(&[0x05, 0x00]);
        extra[1] += 2;
        assert!(matches!(
            Extension::decode(&extra, &options()),
            Err(Asn1Error::TrailingData)
        ));
    }
}
