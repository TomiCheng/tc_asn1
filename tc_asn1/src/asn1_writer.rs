//! Writing encoded values to a `std::io::Write`, after Bouncy Castle's
//! `Asn1OutputStream`.

use std::io;

use crate::{Encode, EncodingOptions};

/// Writes values one after another to `W` under one set of rules, as Bouncy
/// Castle's `Asn1OutputStream` does: a file, a socket or any other
/// `std::io::Write`.
///
/// Each value is written through [`Encode::encode_to_writer`], which for most
/// types encodes the value in memory first and then writes it whole. Writing is variable time, for public
/// values only: an encoding branches on its structure.
///
/// Available with the `std` feature.
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Integer, Asn1Writer, EncodingOptions};
///
/// let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
/// writer.write(&Asn1Integer::from(5))?;
/// writer.write(&Asn1Boolean::from(true))?;
/// assert_eq!(writer.into_inner(), [0x02, 0x01, 0x05, 0x01, 0x01, 0xFF]);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Writer<W> {
    inner: W,
    options: EncodingOptions,
}

impl<W: io::Write> Asn1Writer<W> {
    /// A writer to `inner` that encodes every value under `options`.
    /// Constant time.
    pub fn new(inner: W, options: EncodingOptions) -> Self {
        Self { inner, options }
    }

    /// Encodes `value` and writes its whole TLV, Bouncy Castle's
    /// `WriteObject`. An encoding failure is `io::ErrorKind::InvalidData`
    /// carrying the [`Asn1Error`](crate::Asn1Error), and nothing is written;
    /// a write failure is the writer's own error. Variable time, for public
    /// values only.
    pub fn write<T: Encode + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        value.encode_to_writer(&self.options, &mut self.inner)
    }

    /// Flushes the writer underneath. Constant time apart from the writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// The rules every value is encoded under. Constant time.
    pub fn options(&self) -> &EncodingOptions {
        &self.options
    }

    /// The writer underneath. Constant time.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The writer underneath, to write other data between values. Constant
    /// time.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Gives back the writer underneath, without flushing it. Constant time.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::io;

    use super::Asn1Writer;
    use crate::{
        Asn1Boolean, Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    #[test]
    fn values_are_written_back_to_back_and_decode_in_turn() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write(&Asn1Integer::from(300)).unwrap();
        writer.write(&Asn1OctetString::new(b"abc")).unwrap();
        let bytes = writer.into_inner();

        let options = DecodingOptions::default();
        let (used, integer) = Asn1Integer::decode(&bytes, &options).unwrap();
        assert_eq!(integer, Asn1Integer::from(300));
        let (_, octets) = Asn1OctetString::decode(&bytes[used..], &options).unwrap();
        assert_eq!(octets.as_bytes(), b"abc");
    }

    #[test]
    fn encode_to_writer_writes_what_encode_to_vec_gives_even_behind_dyn_encode() {
        use alloc::boxed::Box;

        let values: Vec<Box<dyn Encode>> = alloc::vec![
            Box::new(Asn1Integer::from(300)),
            Box::new(Asn1OctetString::new(b"abc")),
            Box::new(Asn1Boolean::from(true)),
        ];
        for rules in [EncodingOptions::BER, EncodingOptions::DER] {
            let mut written = Vec::new();
            let mut expected = Vec::new();
            for value in &values {
                value.encode_to_writer(&rules, &mut written).unwrap();
                expected.extend(value.encode_to_vec(&rules).unwrap());
            }
            assert_eq!(written, expected);
        }
    }

    #[test]
    fn the_rules_given_at_creation_apply_to_every_value() {
        let value = Asn1Boolean::from(true);
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write(&value).unwrap();
        assert_eq!(writer.options(), &EncodingOptions::DER);
        assert_eq!(
            writer.get_ref(),
            &value.encode_to_vec(&EncodingOptions::DER).unwrap()
        );
    }

    #[test]
    fn a_write_failure_is_the_writers_error() {
        let mut buffer = [0u8; 2];
        let mut writer = Asn1Writer::new(&mut buffer[..], EncodingOptions::DER);
        let error = writer.write(&Asn1Integer::from(300)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn an_encoding_failure_is_invalid_data_carrying_the_asn1_error() {
        struct Failing;
        const TAG: &[u8] = &[0x04];
        impl crate::EncodeTagged for Failing {}
        impl crate::EncodeContent for Failing {
            fn content_len(&self, _: &EncodingOptions) -> usize {
                0
            }
            fn encode_content(
                &self,
                _: &EncodingOptions,
                _: &mut [u8],
            ) -> Result<usize, Asn1Error> {
                Err(Asn1Error::MalformedValue)
            }
        }
        impl Encode for Failing {
            fn encoded_len(&self, rules: &EncodingOptions) -> usize {
                crate::EncodeTagged::encoded_len_tagged(self, TAG, rules)
            }
            fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
                crate::EncodeTagged::encode_tagged(self, TAG, rules, out)
            }
        }

        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        let error = writer.write(&Failing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let inner = error.into_inner().unwrap();
        assert_eq!(
            inner.downcast_ref::<Asn1Error>(),
            Some(&Asn1Error::MalformedValue)
        );
        assert!(writer.into_inner().is_empty());
    }
}
