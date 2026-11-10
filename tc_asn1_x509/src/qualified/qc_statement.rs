//! RFC 3739 §3.2.6 qualified certificate statement.
//!
//! ```text
//! QCStatement ::= SEQUENCE {
//!     statementId   OBJECT IDENTIFIER,
//!     statementInfo ANY DEFINED BY statementId OPTIONAL }
//! ```
//!
//! The qcStatements extension value is `SEQUENCE OF QCStatement`, read as
//! `Asn1SequenceOf<QcStatement>`. The info is kept as a decoded
//! [`Asn1Object`]; which shape a statement requires belongs to the code that
//! knows its OID, for example [`SemanticsInformation`](crate::qualified::SemanticsInformation)
//! or [`MonetaryValue`](crate::qualified::MonetaryValue).

use tc_asn1::{
    Asn1Error, Asn1Object, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A statement OID with the info it defines.
///
/// ```
/// use tc_asn1::{Encode, EncodingOptions};
/// use tc_asn1_x509::qualified::{QcStatement, QcStatementId};
///
/// let compliance = QcStatement::new(QcStatementId::QC_COMPLIANCE.oid());
/// assert!(compliance.statement_info().is_none());
/// assert_eq!(
///     compliance.encode_to_vec(&EncodingOptions::DER)?,
///     b"\x30\x08\x06\x06\x04\x00\x8e\x46\x01\x01"
/// );
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct QcStatement {
    statement_id: Asn1Oid,
    statement_info: Option<Asn1Object>,
}

impl QcStatement {
    /// A statement without info.
    pub fn new(statement_id: Asn1Oid) -> Self {
        Self {
            statement_id,
            statement_info: None,
        }
    }

    /// A statement with info; every `tc_asn1` value type converts into
    /// [`Asn1Object`].
    pub fn with_info(statement_id: Asn1Oid, statement_info: impl Into<Asn1Object>) -> Self {
        Self {
            statement_id,
            statement_info: Some(statement_info.into()),
        }
    }

    /// Returns `statementId`.
    pub fn statement_id(&self) -> &Asn1Oid {
        &self.statement_id
    }

    /// Returns `statementInfo` as decoded, `None` when absent.
    pub fn statement_info(&self) -> Option<&Asn1Object> {
        self.statement_info.as_ref()
    }
}

impl DecodeContent for QcStatement {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let statement_id = fields.get()?;
        let statement_info = fields.get_any_opt()?;
        fields.end()?;
        Ok(Self {
            statement_id,
            statement_info,
        })
    }
}

impl DecodeInner for QcStatement {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        Ok((
            element.total_len(),
            Self::decode_content(element.value(), context)?,
        ))
    }
}

impl EncodeContent for QcStatement {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.statement_id.encoded_len(rules)
            + self
                .statement_info
                .as_ref()
                .map_or(0, |value| value.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.statement_id.encode(rules, out)?;
        if let Some(value) = &self.statement_info {
            at += value.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for QcStatement {}

impl Tagged for QcStatement {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for QcStatement {}

impl Encode for QcStatement {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use tc_asn1::{
        Asn1Integer, Asn1Object, Asn1SequenceOf, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::QcStatement;

    #[test]
    fn a_statement_with_info_round_trips_and_keeps_the_info_decoded() {
        let statement = QcStatement::with_info("1.2.3".parse().unwrap(), Asn1Integer::from(5));
        let wire = b"\x30\x07\x06\x02\x2a\x03\x02\x01\x05";
        assert_eq!(
            statement.encode_to_vec(&EncodingOptions::DER).unwrap(),
            wire
        );
        let back = QcStatement::decode_der(wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert!(matches!(
            back.statement_info(),
            Some(Asn1Object::Integer(_))
        ));
        assert_eq!(back, statement);
    }

    #[test]
    fn the_extension_value_is_a_sequence_of_statements() {
        let statements = Asn1SequenceOf::new(vec![
            QcStatement::new("1.2.3".parse().unwrap()),
            QcStatement::new("1.2.4".parse().unwrap()),
        ]);
        let wire = statements.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire,
            b"\x30\x0c\x30\x04\x06\x02\x2a\x03\x30\x04\x06\x02\x2a\x04"
        );
        let back = Asn1SequenceOf::<QcStatement>::decode_der(&wire, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(back, statements);
    }

    #[test]
    fn a_missing_id_or_a_third_field_is_rejected() {
        let options = DecodingOptions::default();
        assert!(QcStatement::decode_der(b"\x30\x00", &options).is_err());
        assert!(QcStatement::decode_der(b"\x30\x03\x02\x01\x05", &options).is_err());
        assert!(
            QcStatement::decode_der(b"\x30\x09\x06\x02\x2a\x03\x05\x00\x02\x01\x05", &options)
                .is_err()
        );
    }
}
