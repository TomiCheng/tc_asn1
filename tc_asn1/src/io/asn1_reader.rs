//! Reading encoded values from a `std::io::Read`, after Bouncy Castle's
//! `Asn1InputStream`.

use alloc::vec::Vec;
use std::io::{self, Read};

use super::{Asn1Event, Asn1Header, Asn1Length, Asn1Tag};
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
/// To descend into a value too large to hold, walk it with
/// [`read`](Self::read) instead, and read its small parts whole with
/// [`read_value`](Self::read_value) on the way.
///
/// Available with the `std` feature.
///
/// ```
/// use tc_asn1::io::Asn1Reader;
/// use tc_asn1::{Asn1Boolean, Asn1Integer, DecodingOptions};
///
/// let wire: &[u8] = &[0x02, 0x01, 0x05, 0x01, 0x01, 0xFF];
/// let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
/// assert_eq!(reader.read_value::<Asn1Integer>()?, Some(Asn1Integer::from(5)));
/// assert_eq!(reader.read_value::<Asn1Boolean>()?, Some(Asn1Boolean::from(true)));
/// assert_eq!(reader.read_value::<Asn1Integer>()?, None);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Reader<R> {
    inner: R,
    options: DecodingOptions,
    // Octets read from `inner` through this reader
    position: u64,
    // The constructed values read has opened, innermost last
    frames: Vec<Frame>,
    // Where the contents of the primitive value read returned end
    body_end: Option<u64>,
    // End-of-contents octets read by read_value, for read to report
    end_of_contents: bool,
}

// An open constructed value: where its contents end, or None until its
// end-of-contents octets
#[derive(Debug)]
struct Frame {
    end: Option<u64>,
}

impl<R: Read> Asn1Reader<R> {
    /// A reader from `inner` that decodes every value within `options`.
    /// Constant time.
    pub fn new(inner: R, options: DecodingOptions) -> Self {
        Self {
            inner,
            options,
            position: 0,
            frames: Vec::new(),
            body_end: None,
            end_of_contents: false,
        }
    }

    /// The next step of a walk through the values, Bouncy Castle's
    /// `Asn1StreamParser`: the start of a constructed value, a primitive
    /// value whose contents follow, or the end of the innermost open one;
    /// `None` when the input ends between top-level values.
    ///
    /// Nothing is read whole, so a walk needs memory for its depth alone,
    /// whatever the size of the values. Contents of a primitive value left
    /// unread are skipped. A value reaching past the definite length of the
    /// one around it, end-of-contents octets where no indefinite length is
    /// open, and an indefinite primitive are `MalformedValue`; nesting past
    /// [`DecodingOptions::depth`] is `DepthExceeded`; each as
    /// `io::ErrorKind::InvalidData`. Input that ends inside an open value is
    /// `io::ErrorKind::UnexpectedEof`. Variable time, for public values only.
    pub fn read(&mut self) -> io::Result<Option<Asn1Event>> {
        self.skip_body()?;
        if self.end_of_contents {
            self.end_of_contents = false;
            self.frames.pop();
            return Ok(Some(Asn1Event::End));
        }
        if self.at_frame_end()? {
            self.frames.pop();
            return Ok(Some(Asn1Event::End));
        }

        let Some(header) = self.read_header_into(&mut Vec::new())? else {
            return self.end_of_input().map(|()| None);
        };
        if header.is_end_of_contents() {
            return match self.frames.last() {
                Some(Frame { end: None }) => {
                    self.frames.pop();
                    Ok(Some(Asn1Event::End))
                }
                _ => Err(invalid(Asn1Error::MalformedValue)),
            };
        }

        let end = match header.length() {
            Asn1Length::Definite(len) => Some(
                self.position
                    .checked_add(len as u64)
                    .ok_or_else(|| invalid(Asn1Error::LengthOverflow))?,
            ),
            Asn1Length::Indefinite if header.tag().is_constructed() => None,
            Asn1Length::Indefinite => return Err(invalid(Asn1Error::MalformedValue)),
        };
        self.check_within_frame(end.unwrap_or(self.position))?;

        if header.tag().is_constructed() {
            if self.depth() > self.options.depth() {
                return Err(invalid(Asn1Error::DepthExceeded));
            }
            self.frames.push(Frame { end });
            Ok(Some(Asn1Event::Start(header)))
        } else {
            self.body_end = end;
            Ok(Some(Asn1Event::Primitive(header)))
        }
    }

    /// The contents of the primitive value [`read`](Self::read) returned
    /// last, read as they arrive and never past their end; empty when there
    /// is none. Contents left unread are skipped by the next step. Variable
    /// time, for public values only.
    pub fn body(&mut self) -> impl Read + '_ {
        Body { reader: self }
    }

    /// Reads the identifier and length octets of the next value and leaves
    /// its contents unread; `None` when the input ends before a value starts.
    ///
    /// For use between top-level values: inside a value that
    /// [`read`](Self::read) opened it is `io::ErrorKind::InvalidInput`, since
    /// the walk could not follow contents read past it.
    ///
    /// The header follows the rules [`Asn1Ref::parse`](crate::Asn1Ref::parse)
    /// applies: a non-minimal high tag number is `NonMinimalTag`, the
    /// reserved length octet `FF` is `MalformedValue`, and a length past
    /// `usize` is `LengthOverflow`, each as `io::ErrorKind::InvalidData`.
    /// Identifier octets beyond 16 are `MalformedValue`. Input that ends
    /// inside the header is `io::ErrorKind::UnexpectedEof`. Variable time,
    /// for public values only.
    pub fn read_header(&mut self) -> io::Result<Option<Asn1Header>> {
        if !self.frames.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read_header inside a value opened by read",
            ));
        }
        self.skip_body()?;
        self.read_header_into(&mut Vec::new())
    }

    /// Reads the next whole value and decodes it as `T`, Bouncy Castle's
    /// `ReadObject`; `None` when no value follows, at the end of the input
    /// or, inside a value [`read`](Self::read) opened, at the end of that
    /// value, which `read` then reports as [`Asn1Event::End`].
    ///
    /// Input that ends inside a value is `io::ErrorKind::UnexpectedEof`. A
    /// value over the limits, or one that does not decode as `T`, is
    /// `io::ErrorKind::InvalidData` carrying the [`Asn1Error`]; the value has
    /// been read by then, so the next call starts after it. Variable time,
    /// for public values only.
    pub fn read_value<T: Decode>(&mut self) -> io::Result<Option<T>> {
        self.skip_body()?;
        if self.end_of_contents || self.at_frame_end()? {
            return Ok(None);
        }

        let mut buffer = Vec::new();
        let Some(header) = self.read_header_into(&mut buffer)? else {
            return self.end_of_input().map(|()| None);
        };
        if header.is_end_of_contents() && matches!(self.frames.last(), Some(Frame { end: None })) {
            self.end_of_contents = true;
            return Ok(None);
        }
        self.read_contents(&header, &mut buffer, self.depth())?;
        self.check_within_frame(self.position)?;

        let (used, value) = T::decode(&buffer, &self.options).map_err(invalid)?;
        if used != buffer.len() {
            return Err(invalid(Asn1Error::TrailingData));
        }
        Ok(Some(value))
    }

    /// Reads the next whole value as an [`Asn1Object`], for input whose
    /// type is not known; [`read_value`](Self::read_value) with `Asn1Object`. Variable
    /// time, for public values only.
    pub fn read_object(&mut self) -> io::Result<Option<Asn1Object>> {
        self.read_value::<Asn1Object>()
    }

    /// The limits every value is decoded within. Constant time.
    pub fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// The reader underneath. Constant time.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The reader underneath, to read other data between top-level values.
    /// What is read through it is not counted, so reading through it inside
    /// a value that [`read`](Self::read) opened breaks the walk. Constant
    /// time.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Gives back the reader underneath. Constant time.
    pub fn into_inner(self) -> R {
        self.inner
    }

    // The nesting of the next value: 0 at the top level
    fn depth(&self) -> u32 {
        u32::try_from(self.frames.len()).unwrap_or(u32::MAX)
    }

    // Whether the innermost open value has a definite length now used up
    fn at_frame_end(&self) -> io::Result<bool> {
        match self.frames.last() {
            Some(Frame { end: Some(end) }) if self.position > *end => {
                Err(invalid(Asn1Error::MalformedValue))
            }
            Some(Frame { end: Some(end) }) => Ok(self.position == *end),
            _ => Ok(false),
        }
    }

    // A value ending at `end` must end within the innermost open value
    fn check_within_frame(&self, end: u64) -> io::Result<()> {
        match self.frames.last() {
            Some(Frame {
                end: Some(frame_end),
            }) if end > *frame_end => Err(invalid(Asn1Error::MalformedValue)),
            _ => Ok(()),
        }
    }

    // The input ended before a value: the end of the walk at the top level,
    // and inside an open value an unexpected one
    fn end_of_input(&self) -> io::Result<()> {
        if self.frames.is_empty() {
            Ok(())
        } else {
            Err(unexpected_eof())
        }
    }

    // Skips what is left of the contents of the primitive value read returned
    fn skip_body(&mut self) -> io::Result<()> {
        if let Some(end) = self.body_end.take() {
            let left = end - self.position;
            let skipped = io::copy(&mut (&mut self.inner).take(left), &mut io::sink())?;
            self.position += skipped;
            if skipped != left {
                return Err(unexpected_eof());
            }
        }
        Ok(())
    }

    // The first octet of the next value, or None at the end of the input
    fn read_first_octet(&mut self) -> io::Result<Option<u8>> {
        let mut octet = [0u8; 1];
        loop {
            match self.inner.read(&mut octet) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    self.position += 1;
                    return Ok(Some(octet[0]));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn read_octet(&mut self, buffer: &mut Vec<u8>) -> io::Result<u8> {
        let mut octet = [0u8; 1];
        self.inner.read_exact(&mut octet)?;
        self.position += 1;
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
    fn read_contents(
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
                self.position += read as u64;
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
                    self.read_contents(&child, buffer, depth + 1)?;
                }
            }
        }
    }
}

// The contents of the primitive value read returned, counted as they are read
struct Body<'a, R> {
    reader: &'a mut Asn1Reader<R>,
}

impl<R: Read> Read for Body<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(end) = self.reader.body_end else {
            return Ok(0);
        };
        let left = end - self.reader.position;
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.reader.inner.read(&mut buf[..want])?;
        if read == 0 {
            return Err(unexpected_eof());
        }
        self.reader.position += read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use std::io;

    use super::Asn1Reader;
    use crate::io::{Asn1Event, Asn1Length, Asn1Writer};
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
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(300))
        );
        let octets = reader.read_value::<Asn1OctetString>().unwrap().unwrap();
        assert_eq!(octets.as_bytes(), &[7; 200]);
        assert!(reader.read_value::<Asn1Integer>().unwrap().is_none());
    }

    #[test]
    fn an_indefinite_length_is_followed_to_its_end_of_contents() {
        // SEQUENCE (indefinite) { [0] (indefinite) { INTEGER 1 } INTEGER 2 }, then INTEGER 3
        let wire: &[u8] = &[
            0x30, 0x80, 0xA0, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00,
            0x02, 0x01, 0x03,
        ];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        let sequence = reader.read_value::<crate::Asn1Any>().unwrap().unwrap();
        assert_eq!(
            crate::Encode::encode_to_vec(&sequence, &EncodingOptions::BER).unwrap(),
            &wire[..14]
        );
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
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
            let error = reader.read_value::<crate::Asn1Any>().unwrap_err();
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
            error_of(reader.read_value::<Asn1OctetString>().unwrap_err()),
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
            error_of(reader.read_value::<crate::Asn1Any>().unwrap_err()),
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
            error_of(reader.read_value::<crate::Asn1Any>().unwrap_err()),
            Asn1Error::DepthExceeded
        );
    }

    #[test]
    fn a_primitive_value_with_an_indefinite_length_is_malformed() {
        let mut reader = Asn1Reader::new(&[0x04, 0x80, 0x00, 0x00][..], DecodingOptions::default());
        assert_eq!(
            error_of(reader.read_value::<crate::Asn1Any>().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn a_value_of_another_type_is_invalid_data_and_the_next_value_still_reads() {
        let wire: &[u8] = &[0x01, 0x01, 0xFF, 0x02, 0x01, 0x07];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        assert_eq!(
            error_of(reader.read_value::<Asn1Integer>().unwrap_err()),
            Asn1Error::UnexpectedTag
        );
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
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

    fn events(wire: &[u8], options: DecodingOptions) -> io::Result<Vec<Asn1Event>> {
        let mut reader = Asn1Reader::new(wire, options);
        let mut events = Vec::new();
        while let Some(event) = reader.read()? {
            events.push(event);
        }
        Ok(events)
    }

    fn start_of(event: &Asn1Event) -> (&[u8], Asn1Length) {
        match event {
            Asn1Event::Start(header) | Asn1Event::Primitive(header) => {
                (header.tag().as_bytes(), header.length())
            }
            Asn1Event::End => panic!("End has no header"),
        }
    }

    #[test]
    fn read_walks_definite_and_indefinite_values_in_order() {
        // SEQUENCE (indefinite) { INTEGER 5, SET { BOOLEAN TRUE } }, then NULL
        let wire: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x05, 0x31, 0x03, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x05, 0x00,
        ];
        let events = events(wire, DecodingOptions::default()).unwrap();
        assert_eq!(events.len(), 7);
        assert!(matches!(events[0], Asn1Event::Start(_)));
        assert_eq!(start_of(&events[0]), (&[0x30][..], Asn1Length::Indefinite));
        assert!(matches!(events[1], Asn1Event::Primitive(_)));
        assert_eq!(start_of(&events[1]), (&[0x02][..], Asn1Length::Definite(1)));
        assert_eq!(start_of(&events[2]), (&[0x31][..], Asn1Length::Definite(3)));
        assert_eq!(start_of(&events[3]), (&[0x01][..], Asn1Length::Definite(1)));
        assert_eq!(events[4], Asn1Event::End);
        assert_eq!(events[5], Asn1Event::End);
        assert_eq!(start_of(&events[6]), (&[0x05][..], Asn1Length::Definite(0)));
    }

    #[test]
    fn a_body_streams_its_contents_and_what_is_left_is_skipped() {
        let wire: &[u8] = &[0x04, 0x05, b'h', b'e', b'l', b'l', b'o', 0x02, 0x01, 0x07];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        assert!(matches!(
            reader.read().unwrap(),
            Some(Asn1Event::Primitive(_))
        ));
        let mut start = [0u8; 2];
        io::Read::read_exact(&mut reader.body(), &mut start).unwrap();
        assert_eq!(&start, b"he");
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(7))
        );

        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        reader.read().unwrap();
        let mut whole = Vec::new();
        io::Read::read_to_end(&mut reader.body(), &mut whole).unwrap();
        assert_eq!(whole, b"hello");
    }

    #[test]
    fn read_value_inside_a_value_stops_at_its_end_and_read_reports_it() {
        for wire in [
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02][..],
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00],
        ] {
            let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
            assert!(matches!(reader.read().unwrap(), Some(Asn1Event::Start(_))));
            let mut integers = Vec::new();
            while let Some(integer) = reader.read_value::<Asn1Integer>().unwrap() {
                integers.push(integer);
            }
            assert_eq!(integers, [Asn1Integer::from(1), Asn1Integer::from(2)]);
            assert_eq!(reader.read().unwrap(), Some(Asn1Event::End));
            assert_eq!(reader.read().unwrap(), None);
        }
    }

    #[test]
    fn a_value_reaching_past_the_one_around_it_is_malformed() {
        let wire: &[u8] = &[0x30, 0x03, 0x04, 0x05, 1, 2, 3, 4, 5];
        let error = events(wire, DecodingOptions::default()).unwrap_err();
        assert_eq!(error_of(error), Asn1Error::MalformedValue);

        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        reader.read().unwrap();
        assert_eq!(
            error_of(reader.read_value::<Asn1OctetString>().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn end_of_contents_outside_an_indefinite_length_is_malformed() {
        for wire in [&[0x00, 0x00][..], &[0x30, 0x02, 0x00, 0x00]] {
            let error = events(wire, DecodingOptions::default()).unwrap_err();
            assert_eq!(error_of(error), Asn1Error::MalformedValue, "{wire:02X?}");
        }
    }

    #[test]
    fn input_ending_inside_an_open_value_is_an_unexpected_end() {
        for wire in [
            &[0x30, 0x05, 0x02, 0x01, 0x01][..],
            &[0x30, 0x80, 0x02, 0x01, 0x01],
            &[0x04, 0x05, b'h', b'e'],
        ] {
            let error = events(wire, DecodingOptions::default()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{wire:02X?}");
        }
    }

    #[test]
    fn read_refuses_nesting_past_the_depth_limit() {
        let wire = [0x30, 0x80].repeat(5);
        let error = events(&wire, DecodingOptions::new(3, 1024, 1024)).unwrap_err();
        assert_eq!(error_of(error), Asn1Error::DepthExceeded);
    }

    #[test]
    fn read_header_inside_a_value_opened_by_read_is_refused() {
        let wire: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
        let mut reader = Asn1Reader::new(wire, DecodingOptions::default());
        reader.read().unwrap();
        let error = reader.read_header().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
