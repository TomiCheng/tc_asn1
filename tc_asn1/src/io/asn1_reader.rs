//! Reading encoded values from a `std::io::Read`, after Bouncy Castle's
//! `Asn1InputStream`.

use alloc::vec::Vec;
use std::io::{self, Read};

use super::{Asn1Header, Asn1Length, Asn1Tag};
use crate::asn1_ref::{parse_len, parse_tag};
use crate::{Asn1Error, Asn1Object, Decode, DecodingOptions};

// Room for the identifier and length octets of the outermost value
const HEADER_ALLOWANCE: usize = 32;
// Identifier octets beyond this are refused rather than read without end
const MAX_TAG_LEN: usize = 16;

fn invalid(error: Asn1Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn unexpected_eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

/// Reads values one after another from `R`, as Bouncy Castle's
/// `Asn1InputStream` does: a file, a socket or any other `std::io::Read`.
///
/// It reads exactly the octets of each value and nothing past them, so what
/// follows a value stays in `R` for the next call or for other use. It reads
/// a header an octet at a time, so wrap an unbuffered source such as a file or
/// a socket in a `std::io::BufReader` and keep reading through that.
///
/// A value is read whole into memory, its header first, then its contents,
/// and decoded from there. A definite length is checked against
/// [`DecodingOptions::max_content_len`] before anything is read for it, and
/// memory grows with the octets that arrive rather than with the length a
/// peer claims; an indefinite length is followed to its end-of-contents
/// octets within [`DecodingOptions::depth`]. Values are decoded as BER.
/// Reading is variable time, for public values only: a decoding branches on
/// its structure.
///
/// Available with the `std` feature.
///
/// ```
/// use tc_asn1::io::Asn1Reader;
/// use tc_asn1::{Asn1Boolean, Asn1Integer, DecodingOptions};
///
/// let wire: &[u8] = &[0x02, 0x01, 0x05, 0x01, 0x01, 0xFF];
/// let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
/// assert_eq!(reader.read::<Asn1Integer>()?, Some(Asn1Integer::from(5)));
/// assert_eq!(reader.read::<Asn1Boolean>()?, Some(Asn1Boolean::from(true)));
/// assert_eq!(reader.read::<Asn1Integer>()?, None);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Reader<R> {
    inner: R,
    options: DecodingOptions,
}

impl<R: Read> Asn1Reader<R> {
    /// A reader from `inner` that decodes every value within `options`.
    /// Constant time.
    pub fn new(inner: R, options: DecodingOptions) -> Self {
        Self { inner, options }
    }

    /// Reads the identifier and length octets of the next value and leaves
    /// its contents unread; `None` when the input ends before a value starts.
    ///
    /// The header follows the rules [`Asn1Ref::parse`](crate::Asn1Ref::parse)
    /// applies: a non-minimal high tag number is `NonMinimalTag`, the
    /// reserved length octet `FF` is `MalformedValue`, and a length past
    /// `usize` is `LengthOverflow`, each as `io::ErrorKind::InvalidData`.
    /// Identifier octets beyond 16 are `MalformedValue`. Input that ends
    /// inside the header is `io::ErrorKind::UnexpectedEof`. Variable time,
    /// for public values only.
    pub fn read_header(&mut self) -> io::Result<Option<Asn1Header>> {
        self.read_header_into(&mut Vec::new())
    }

    /// Reads the next whole value and decodes it as `T`, Bouncy Castle's
    /// `ReadObject`; `None` when the input ends before a value starts.
    ///
    /// Input that ends inside a value is `io::ErrorKind::UnexpectedEof`. A
    /// value over the limits, or one that does not decode as `T`, is
    /// `io::ErrorKind::InvalidData` carrying the [`Asn1Error`]; the value has
    /// been read by then, so the next call starts after it. Variable time,
    /// for public values only.
    pub fn read<T: Decode>(&mut self) -> io::Result<Option<T>> {
        let mut buffer = Vec::new();
        let Some(header) = self.read_header_into(&mut buffer)? else {
            return Ok(None);
        };
        self.read_value(&header, &mut buffer, 0)?;
        let (used, value) = T::decode(&buffer, &self.options).map_err(invalid)?;
        if used != buffer.len() {
            return Err(invalid(Asn1Error::TrailingData));
        }
        Ok(Some(value))
    }

    /// Reads the next whole value as an [`Asn1Object`], for input whose
    /// type is not known; [`read`](Self::read) with `Asn1Object`. Variable
    /// time, for public values only.
    pub fn read_object(&mut self) -> io::Result<Option<Asn1Object>> {
        self.read::<Asn1Object>()
    }

    /// The limits every value is decoded within. Constant time.
    pub fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// The reader underneath. Constant time.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The reader underneath, to read other data between values. Constant
    /// time.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Gives back the reader underneath. Constant time.
    pub fn into_inner(self) -> R {
        self.inner
    }

    // The first octet of the next value, or None at the end of the input
    fn read_first_octet(&mut self) -> io::Result<Option<u8>> {
        let mut octet = [0u8; 1];
        loop {
            match self.inner.read(&mut octet) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(octet[0])),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn read_octet(&mut self, buffer: &mut Vec<u8>) -> io::Result<u8> {
        let mut octet = [0u8; 1];
        self.inner.read_exact(&mut octet)?;
        buffer.push(octet[0]);
        Ok(octet[0])
    }

    // Reads one header, appending its octets to `raw`; None when the input
    // ends before its first octet
    fn read_header_into(&mut self, raw: &mut Vec<u8>) -> io::Result<Option<Asn1Header>> {
        let start = raw.len();
        let Some(first) = self.read_first_octet()? else {
            return Ok(None);
        };
        raw.push(first);
        let tag_len = loop {
            match parse_tag(&raw[start..]) {
                Ok(tag) => break tag.len(),
                Err(Asn1Error::Truncated) if raw.len() - start < MAX_TAG_LEN => {
                    self.read_octet(raw)?;
                }
                Err(Asn1Error::Truncated) => return Err(invalid(Asn1Error::MalformedValue)),
                Err(error) => return Err(invalid(error)),
            }
        };

        let first_length = self.read_octet(raw)?;
        if first_length > 0x80 && first_length != 0xFF {
            for _ in 0..first_length & 0x7F {
                self.read_octet(raw)?;
            }
        }
        let (_, length) = parse_len(&raw[start + tag_len..]).map_err(invalid)?;
        let tag = Asn1Tag::new(raw[start..start + tag_len].to_vec());
        let length = length.map_or(Asn1Length::Indefinite, Asn1Length::Definite);
        Ok(Some(Asn1Header::new(tag, length)))
    }

    fn reserve(&self, buffer: &[u8], more: usize) -> io::Result<()> {
        let limit = self
            .options
            .max_content_len()
            .saturating_add(HEADER_ALLOWANCE);
        if buffer.len().saturating_add(more) > limit {
            return Err(invalid(Asn1Error::ContentLengthExceeded));
        }
        Ok(())
    }

    // Copies the contents of the value whose header is already in `buffer`,
    // following an indefinite length to its end-of-contents octets
    fn read_value(
        &mut self,
        header: &Asn1Header,
        buffer: &mut Vec<u8>,
        depth: u32,
    ) -> io::Result<()> {
        if depth > self.options.depth() {
            return Err(invalid(Asn1Error::DepthExceeded));
        }
        self.reserve(buffer, 0)?;
        match header.length() {
            Asn1Length::Definite(len) => {
                if len > self.options.max_content_len() {
                    return Err(invalid(Asn1Error::ContentLengthExceeded));
                }
                self.reserve(buffer, len)?;
                // Grows with the octets that arrive, not with the length claimed
                let read = (&mut self.inner).take(len as u64).read_to_end(buffer)?;
                if read != len {
                    return Err(unexpected_eof());
                }
                Ok(())
            }
            Asn1Length::Indefinite => {
                // Only a constructed value may have an indefinite length
                if !header.tag().is_constructed() {
                    return Err(invalid(Asn1Error::MalformedValue));
                }
                loop {
                    let child = self.read_header_into(buffer)?.ok_or_else(unexpected_eof)?;
                    if child.is_end_of_contents() {
                        return Ok(());
                    }
                    self.read_value(&child, buffer, depth + 1)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use std::io;

    use super::Asn1Reader;
    use crate::io::{Asn1Length, Asn1Writer};
    use crate::{
        Asn1Class, Asn1Error, Asn1Integer, Asn1OctetString, DecodingOptions, EncodingOptions,
    };

    fn error_of(error: io::Error) -> Asn1Error {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        *error.into_inner().unwrap().downcast::<Asn1Error>().unwrap()
    }

    #[test]
    fn what_the_writer_writes_the_reader_reads_back_in_turn() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write(&Asn1Integer::from(300)).unwrap();
        writer.write(&Asn1OctetString::new(&[7; 200])).unwrap();
        let bytes = writer.into_inner();

        let mut reader = Asn1Reader::new(&bytes[..], DecodingOptions::default());
        assert_eq!(
            reader.read::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(300))
        );
        let octets = reader.read::<Asn1OctetString>().unwrap().unwrap();
        assert_eq!(octets.as_bytes(), &[7; 200]);
        assert!(reader.read::<Asn1Integer>().unwrap().is_none());
    }

    #[test]
    fn an_indefinite_length_is_followed_to_its_end_of_contents() {
        // SEQUENCE (indefinite) { [0] (indefinite) { INTEGER 1 } INTEGER 2 }, then INTEGER 3
        let wire: &[u8] = &[
            0x30, 0x80, 0xA0, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00,
            0x02, 0x01, 0x03,
        ];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        let sequence = reader.read::<crate::Asn1Any>().unwrap().unwrap();
        assert_eq!(
            crate::Encode::encode_to_vec(&sequence, &EncodingOptions::BER).unwrap(),
            &wire[..14]
        );
        assert_eq!(
            reader.read::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(3))
        );
    }

    #[test]
    fn input_that_ends_inside_a_value_is_an_unexpected_end() {
        for wire in [
            &[0x02][..],
            &[0x02, 0x02, 0x01],
            &[0x30, 0x80, 0x02, 0x01, 0x01],
        ] {
            let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
            let error = reader.read::<crate::Asn1Any>().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{wire:02X?}");
        }
    }

    #[test]
    fn a_length_over_the_limit_is_refused_before_it_is_read() {
        let options = DecodingOptions::new(32, 16, 1024);
        // OCTET STRING of 4 GB, with no contents following
        let mut reader =
            Asn1Reader::new(&[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF][..], options.clone());
        assert_eq!(
            error_of(reader.read::<Asn1OctetString>().unwrap_err()),
            Asn1Error::ContentLengthExceeded
        );

        // Indefinite values that add up past the limit
        let mut wire = vec![0x30, 0x80];
        for _ in 0..10 {
            wire.extend_from_slice(&[0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        wire.extend_from_slice(&[0x00, 0x00]);
        let mut reader = Asn1Reader::new(&wire[..], options);
        assert_eq!(
            error_of(reader.read::<crate::Asn1Any>().unwrap_err()),
            Asn1Error::ContentLengthExceeded
        );
    }

    #[test]
    fn nesting_past_the_depth_limit_is_refused() {
        let options = DecodingOptions::new(3, 1024, 1024);
        let mut wire = Vec::new();
        for _ in 0..5 {
            wire.extend_from_slice(&[0x30, 0x80]);
        }
        let mut reader = Asn1Reader::new(&wire[..], options);
        assert_eq!(
            error_of(reader.read::<crate::Asn1Any>().unwrap_err()),
            Asn1Error::DepthExceeded
        );
    }

    #[test]
    fn a_primitive_value_with_an_indefinite_length_is_malformed() {
        let mut reader = Asn1Reader::new(&[0x04, 0x80, 0x00, 0x00][..], DecodingOptions::default());
        assert_eq!(
            error_of(reader.read::<crate::Asn1Any>().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn a_value_of_another_type_is_invalid_data_and_the_next_value_still_reads() {
        let wire: &[u8] = &[0x01, 0x01, 0xFF, 0x02, 0x01, 0x07];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        assert_eq!(
            error_of(reader.read::<Asn1Integer>().unwrap_err()),
            Asn1Error::UnexpectedTag
        );
        assert_eq!(
            reader.read::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(7))
        );
    }

    #[test]
    fn a_header_is_read_without_its_contents() {
        // [31] with a high tag number and 256 octets, then SEQUENCE (indefinite)
        let mut wire = vec![0x9F, 0x1F, 0x82, 0x01, 0x00];
        wire.extend_from_slice(&[0xAB; 256]);
        wire.extend_from_slice(&[0x30, 0x80]);
        let mut reader = Asn1Reader::new(&wire[..], DecodingOptions::default());

        let header = reader.read_header().unwrap().unwrap();
        assert_eq!(header.tag().as_bytes(), [0x9F, 0x1F]);
        assert_eq!(header.tag().class(), Asn1Class::ContextSpecific);
        assert!(!header.tag().is_constructed());
        assert_eq!(header.length(), Asn1Length::Definite(256));

        let mut contents = [0u8; 256];
        io::Read::read_exact(reader.get_mut(), &mut contents).unwrap();
        assert_eq!(contents, [0xAB; 256]);

        let header = reader.read_header().unwrap().unwrap();
        assert!(header.tag().is_constructed());
        assert_eq!(header.length(), Asn1Length::Indefinite);
        assert!(reader.read_header().unwrap().is_none());
    }

    #[test]
    fn nothing_past_a_value_is_read() {
        let wire: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, b't', b'a', b'i', b'l',
        ];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        reader.read_object().unwrap().unwrap();
        assert_eq!(reader.into_inner(), b"tail");
    }

    #[test]
    fn read_object_gives_the_tree_of_a_value_of_unknown_type() {
        let wire: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        let object = reader.read_object().unwrap().unwrap();
        assert_eq!(
            crate::Encode::encode_to_vec(&object, &EncodingOptions::DER).unwrap(),
            wire
        );
        assert!(reader.read_object().unwrap().is_none());
    }

    #[test]
    fn identifier_octets_without_end_are_refused() {
        let mut wire = vec![0x1F];
        wire.extend_from_slice(&[0x81; 32]);
        let mut reader = Asn1Reader::new(&wire[..], DecodingOptions::default());
        assert_eq!(
            error_of(reader.read_header().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn the_header_rules_are_those_of_asn1_ref() {
        for (wire, expected) in [
            (&[0x1F, 0x80, 0x01, 0x00][..], Asn1Error::NonMinimalTag),
            (&[0x1F, 0x05, 0x00], Asn1Error::NonMinimalTag),
            (&[0x04, 0xFF], Asn1Error::MalformedValue),
        ] {
            let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
            assert_eq!(
                error_of(reader.read_header().unwrap_err()),
                expected,
                "{wire:02X?}"
            );
        }
    }
}
