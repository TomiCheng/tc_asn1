//! What an encoder is told about the form to produce.

use crate::{EncodingType, LengthForm};

/// The choices an encoding is made under, passed to every
/// [`Encode`](crate::Encode) and [`EncodeContent`](crate::EncodeContent)
/// call so that nested values follow the same rules as the outer one.
///
/// Today this is the [`EncodingType`] alone; it is a struct so that later
/// options (a segment size, say) do not change every signature. The values
/// of the struct are pure choices, never limits: an encoder writes whatever
/// it is given. [`DER`](Self::DER), [`BER`](Self::BER) and [`CER`](Self::CER)
/// are the usual choices ready made.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1SetOf, Asn1Integer, Encode, EncodingOptions, EncodingType, LengthForm};
///
/// let set = Asn1SetOf::new(vec![Asn1Integer::from(2), Asn1Integer::from(1)]);
///
/// // DER sorts the SET OF; plain BER writes the elements as given.
/// let der = set.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(der, [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
/// let ber = set.encode_to_vec(&EncodingOptions::BER)?;
/// assert_eq!(ber, [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]);
///
/// // Anything else goes through `new`: indefinite BER wraps the
/// // constructed value in `80 ... 00 00`.
/// let indefinite = set.encode_to_vec(&EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite)))?;
/// assert_eq!(indefinite, [0x31, 0x80, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x00, 0x00]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingOptions {
    encoding_type: EncodingType,
}

impl EncodingOptions {
    /// Definite-length BER: the elements as given, no sorting.
    pub const BER: Self = Self::new(EncodingType::Ber(LengthForm::Definite));
    /// Canonical Encoding Rules.
    pub const CER: Self = Self::new(EncodingType::Cer);
    /// Distinguished Encoding Rules, what X.509 and every signed structure
    /// want.
    pub const DER: Self = Self::new(EncodingType::Der);

    /// For a rule set the constants do not cover, such as indefinite BER.
    pub const fn new(encoding_type: EncodingType) -> Self {
        Self { encoding_type }
    }

    pub const fn encoding_type(&self) -> EncodingType {
        self.encoding_type
    }

    /// [`EncodingType::is_canonical`] of the chosen rules.
    pub const fn is_canonical(&self) -> bool {
        self.encoding_type.is_canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::EncodingOptions;
    use crate::{EncodingType, LengthForm};

    #[test]
    fn the_constants_are_the_three_usual_rule_sets() {
        assert_eq!(
            EncodingOptions::BER.encoding_type(),
            EncodingType::Ber(LengthForm::Definite)
        );
        assert_eq!(EncodingOptions::CER.encoding_type(), EncodingType::Cer);
        assert_eq!(EncodingOptions::DER.encoding_type(), EncodingType::Der);
        assert!(!EncodingOptions::BER.is_canonical());
        assert!(EncodingOptions::CER.is_canonical());
        assert!(EncodingOptions::DER.is_canonical());
        assert_eq!(
            EncodingOptions::new(EncodingType::Der),
            EncodingOptions::DER
        );
    }
}
