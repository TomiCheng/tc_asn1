//! Reading encoded values from a `std::io::Read`, after Bouncy Castle's
//! `Asn1InputStream`.

use alloc::vec::Vec;
use std::io::{self, Read};

use crate::{Asn1Error, Decode, DecodingOptions};

// The identifier octets of the end-of-contents marker
const END_OF_CONTENTS: u8 = 0x00;
// Bit 6 of the first identifier octet: constructed
const CONSTRUCTED: u8 = 0x20;
// Room for the identifier and length octets of the outermost value
const HEADER_ALLOWANCE: usize = 32;

fn invalid(error: Asn1Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Reads values one after another from `R`, as Bouncy Castle's
/// `Asn1InputStream` does: a file, a socket or any other `std::io::Read`.
///
/// Each value is read whole into memory, its tag and length first, then its
/// contents, and decoded from there; a definite length is checked against
/// [`DecodingOptions::max_content_len`] before anything is read for it, and
/// an indefinite length is followed to its end-of-contents octets within
/// [`DecodingOptions::depth`], so a peer cannot make it allocate without
/// bound. Values are decoded as BER. Reading is variable time, for public
/// values only: a decoding branches on its structure.
///
/// Available with the `std` feature.
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Integer, Asn1Reader, DecodingOptions};
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

    /// Reads the next whole value and decodes it as `T`, Bouncy Castle's
    /// `ReadObject`; `None` when the input ends before a value starts.
    ///
    /// Input that ends inside a value is `io::ErrorKind::UnexpectedEof`. A
    /// value over the limits, or one that does not decode as `T`, is
    /// `io::ErrorKind::InvalidData` carrying the [`Asn1Error`]; the value has
    /// been read by then, so the next call starts after it. Variable time,
    /// for public values only.
    pub fn read<T: Decode>(&mut self) -> io::Result<Option<T>> {
        let Some(first) = self.read_first_octet()? else {
            return Ok(None);
        };
        let mut buffer = Vec::new();
        self.read_value(first, &mut buffer, 0)?;
        let (used, value) = T::decode(&buffer, &self.options).map_err(invalid)?;
        if used != buffer.len() {
            return Err(invalid(Asn1Error::TrailingData));
        }
        Ok(Some(value))
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

    // Copies one TLV whose first identifier octet is `first` into `buffer`,
    // and returns whether it was the end-of-contents marker
    fn read_value(&mut self, first: u8, buffer: &mut Vec<u8>, depth: u32) -> io::Result<bool> {
        if depth > self.options.depth() {
            return Err(invalid(Asn1Error::DepthExceeded));
        }
        self.reserve(buffer, 1)?;
        buffer.push(first);
        // A high tag number continues while bit 8 is set
        if first & 0x1F == 0x1F {
            loop {
                self.reserve(buffer, 1)?;
                if self.read_octet(buffer)? & 0x80 == 0 {
                    break;
                }
            }
        }

        self.reserve(buffer, 1)?;
        let length = self.read_octet(buffer)?;
        let contents = match length {
            0x80 => None,
            0xFF => return Err(invalid(Asn1Error::MalformedValue)),
            short if short < 0x80 => Some(usize::from(short)),
            long => {
                let count = usize::from(long & 0x7F);
                if count > core::mem::size_of::<usize>() {
                    return Err(invalid(Asn1Error::LengthOverflow));
                }
                self.reserve(buffer, count)?;
                let mut value = 0usize;
                for _ in 0..count {
                    value = (value << 8) | usize::from(self.read_octet(buffer)?);
                }
                Some(value)
            }
        };

        match contents {
            Some(len) => {
                if len > self.options.max_content_len() {
                    return Err(invalid(Asn1Error::ContentLengthExceeded));
                }
                self.reserve(buffer, len)?;
                let start = buffer.len();
                buffer.resize(start + len, 0);
                self.inner.read_exact(&mut buffer[start..])?;
                Ok(first == END_OF_CONTENTS && len == 0)
            }
            None => {
                // Only a constructed value may have an indefinite length
                if first & CONSTRUCTED == 0 {
                    return Err(invalid(Asn1Error::MalformedValue));
                }
                loop {
                    let mut next = [0u8; 1];
                    self.inner.read_exact(&mut next)?;
                    if self.read_value(next[0], buffer, depth + 1)? {
                        return Ok(false);
                    }
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
    use crate::{
        Asn1Error, Asn1Integer, Asn1OctetString, Asn1Writer, DecodingOptions, EncodingOptions,
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
}
