//! The X.690 encoding rules a value can be written under.

/// How a constructed value's length is written under BER (X.690 §8.1.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthForm {
    /// The length octets state the contents length, as DER requires.
    Definite,
    /// `80`, the contents, then the end-of-contents octets `00 00`, as CER
    /// requires. Only constructed values can take this form; primitives are
    /// always definite.
    Indefinite,
}

/// The rule set an encoder follows, X.690 §8 to §11. Decoding needs no
/// such choice: it accepts every form and can additionally insist on DER,
/// see [`DecodingContext::new_der`](crate::DecodingContext::new_der).
///
/// The three differ only where X.690 leaves the encoder a choice:
///
/// | | `Ber(Definite)` | `Ber(Indefinite)` | `Cer` | `Der` |
/// | --- | --- | --- | --- | --- |
/// | Length of a constructed value | definite | indefinite | indefinite | definite |
/// | SET OF elements | as given | as given | sorted | sorted |
/// | String over 1000 octets | primitive | primitive | segmented (§9.2) | primitive |
///
/// Everything else, the shortest length octets, TRUE as `FF`, minimal
/// INTEGERs, omitted DEFAULTs, is written the same way under every rule
/// set; this crate does not produce the looser forms BER permits. A value
/// written under `Der` and read back with the DER rules round-trips; one
/// written under `Ber(Definite)` differs from it only in an unsorted SET OF.
///
/// Segmenting under `Cer` is done by the constructed string types; the plain
/// string types refuse a value over 1000 octets with
/// [`Asn1Error::PrimitiveTooLong`](crate::Asn1Error::PrimitiveTooLong).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    /// Basic Encoding Rules with the chosen length form.
    Ber(LengthForm),
    /// Canonical Encoding Rules: indefinite lengths and segmented strings.
    Cer,
    /// Distinguished Encoding Rules: definite lengths, the form X.509 and
    /// every signed structure require.
    Der,
}

impl EncodingType {
    /// Whether the rules fix a single encoding for each value, which is
    /// what makes a SET OF sort its elements: `Cer` and `Der`.
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Cer | Self::Der)
    }
}
