//! Reading encoded values from a `std::io::Read`, after Bouncy Castle's
//! `Asn1InputStream` and `Asn1StreamParser`.

use alloc::vec::Vec;
use std::io::{self, Read};

use super::{Asn1Item, Asn1Length, Asn1Tag};
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

// A call the state of its level does not allow; nothing is read for it
fn misuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// Where the contents of a level end
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End {
    Input,
    At(u64),
    Eoc,
}

// Every step: a read of the next value closes the one in progress
const ALL_STEPS: &[Step] = &[
    Step::Header,
    Step::Len,
    Step::Body,
    Step::Opened,
    Step::Done,
];

// What read gives next, owned so that a body can borrow the reader after it
enum Part {
    Header(Asn1Tag),
    Len(Asn1Length),
    Body,
    End,
}

// What a level expects next
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Header,
    Len,
    Body,
    Opened,
    Done,
}

// The contents of one value being read, or the input itself at level 0
#[derive(Clone, Copy, Debug)]
struct Level {
    end: End,
    // Contents that are octets rather than values
    primitive: bool,
    step: Step,
    // The value whose header this level is reading
    constructed: bool,
    value_end: End,
}

impl Level {
    fn new(end: End, primitive: bool) -> Self {
        Self {
            end,
            primitive,
            step: Step::Header,
            constructed: false,
            value_end: End::Input,
        }
    }
}

// An error after which the position in the input is lost
#[derive(Clone, Copy, Debug)]
struct Failure {
    kind: io::ErrorKind,
    error: Option<Asn1Error>,
}

impl Failure {
    fn of(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            error: error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<Asn1Error>())
                .copied(),
        }
    }

    fn to_error(self) -> io::Error {
        match self.error {
            Some(error) => io::Error::new(self.kind, error),
            None => io::Error::from(self.kind),
        }
    }
}

/// Reads values from `R`, as Bouncy Castle's `Asn1InputStream` and
/// `Asn1StreamParser` do: a file, a socket or any other `std::io::Read`.
///
/// A value is read in steps, [`read_header`](Self::read_header) for its
/// identifier octets, [`read_len`](Self::read_len) for its length and
/// [`read_body`](Self::read_body) for its contents, or with
/// [`read`](Self::read), which gives whichever of them comes next as an
/// [`Asn1Item`], or whole in one, with
/// [`read_value`](Self::read_value) for a known type and
/// [`read_object`](Self::read_object) for an unknown one. `read_body` gives
/// an [`Asn1Body`] limited to the contents, with the same steps for the
/// values inside a constructed one and `std::io::Read` for the octets of a
/// primitive one, so a value too large to hold is read part by part. The next
/// read of the same level closes the value before it, skipping what was left
/// unread of it, so a value need not be read to its end.
///
/// Each level keeps a state machine: a call out of order is
/// `io::ErrorKind::InvalidInput` and reads nothing. An error in the input
/// leaves the position inside a value, so the reader fails from then on and
/// every call gives that error again. A value that does not decode as the
/// type asked for has been read whole by then and does not fail the reader.
///
/// It reads exactly the octets of each value and nothing past them. It reads
/// a header an octet at a time, so wrap an unbuffered source in a
/// `std::io::BufReader`. A value read whole is held to
/// [`DecodingOptions::max_content_len`], checked before its contents are
/// read, and memory grows with the octets that arrive rather than with the
/// length a peer claims; nesting is held to [`DecodingOptions::depth`].
/// Values are decoded as BER. Reading is variable time, for public values
/// only: it branches on the structure.
///
/// Available with the `std` feature.
///
/// Reading the values of a file one after another, here serial numbers
/// written as DER INTEGERs:
///
/// ```no_run
/// use std::fs::File;
/// use std::io::BufReader;
///
/// use tc_asn1::io::Asn1Reader;
/// use tc_asn1::{Asn1Integer, DecodingOptions};
///
/// let file = BufReader::new(File::open("serials.der")?);
/// let mut reader = Asn1Reader::new(file, DecodingOptions::default());
/// while let Some(serial) = reader.read_value::<Asn1Integer>()? {
///     println!("{serial}");
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Reader<R> {
    inner: R,
    options: DecodingOptions,
    // Octets read from `inner` through this reader
    position: u64,
    // Level 0 is the input; each body read pushes the next
    levels: Vec<Level>,
    failed: Option<Failure>,
}

impl<R: Read> Asn1Reader<R> {
    /// A reader from `inner` that reads every value within `options`.
    /// Constant time.
    pub fn new(inner: R, options: DecodingOptions) -> Self {
        Self {
            inner,
            options,
            position: 0,
            levels: alloc::vec![Level::new(End::Input, false)],
            failed: None,
        }
    }

    /// The next part of a value as an [`Asn1Item`]: its header when no value
    /// is in progress, then its length, then its body; `None` when the input
    /// ends before a value starts. The same steps as
    /// [`read_header`](Self::read_header), [`read_len`](Self::read_len) and
    /// [`read_body`](Self::read_body), with their errors, and the two can be
    /// mixed. Variable time, for public values only.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Read;
    ///
    /// use tc_asn1::io::{Asn1Item, Asn1Length, Asn1Reader};
    /// use tc_asn1::DecodingOptions;
    ///
    /// // SEQUENCE { OCTET STRING "abc" }
    /// let data: &[u8] = &[0x30, 0x05, 0x04, 0x03, b'a', b'b', b'c'];
    /// let mut reader = Asn1Reader::new(data, DecodingOptions::default());
    ///
    /// while let Some(item) = reader.read()? {
    ///     match item {
    ///         Asn1Item::Header(tag) => println!("tag {:02X?}", tag.as_bytes()),
    ///         Asn1Item::Len(Asn1Length::Definite(len)) => println!("len {len}"),
    ///         Asn1Item::Len(Asn1Length::Indefinite) => println!("len indefinite"),
    ///         Asn1Item::Body(mut body) => {
    ///             while let Some(inner) = body.read()? {
    ///                 match inner {
    ///                     Asn1Item::Header(tag) => println!("  tag {:02X?}", tag.as_bytes()),
    ///                     Asn1Item::Len(len) => println!("  len {len:?}"),
    ///                     Asn1Item::Body(mut octets) => {
    ///                         let mut contents = Vec::new();
    ///                         octets.read_to_end(&mut contents)?;
    ///                         println!("  body {contents:02X?}");
    ///                     }
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn read(&mut self) -> io::Result<Option<Asn1Item<'_, R>>> {
        Ok(match self.part_at(0)? {
            Part::Header(tag) => Some(Asn1Item::Header(tag)),
            Part::Len(length) => Some(Asn1Item::Len(length)),
            Part::Body => Some(Asn1Item::Body(Asn1Body {
                reader: self,
                level: 1,
            })),
            Part::End => None,
        })
    }

    /// Reads the identifier octets of the next value; `None` when the input
    /// ends before a value starts.
    ///
    /// A non-minimal high tag number is `NonMinimalTag`, identifier octets
    /// beyond 16 and end-of-contents octets out of place are
    /// `MalformedValue`, each as `io::ErrorKind::InvalidData`; input that
    /// ends inside them is `io::ErrorKind::UnexpectedEof`. It first closes the
    /// value before it, skipping what is left of it with the same errors.
    /// Variable time, for public values only.
    ///
    /// # Examples
    ///
    /// The steps of a value, here an OCTET STRING whose contents are copied
    /// out as they arrive:
    ///
    /// ```
    /// use std::io;
    ///
    /// use tc_asn1::io::{Asn1Length, Asn1Reader};
    /// use tc_asn1::DecodingOptions;
    ///
    /// let data: &[u8] = &[0x04, 0x05, b'h', b'e', b'l', b'l', b'o'];
    /// let mut reader = Asn1Reader::new(data, DecodingOptions::default());
    ///
    /// let tag = reader.read_header()?.expect("a value");
    /// assert_eq!(tag.as_bytes(), [0x04]);
    /// assert_eq!(reader.read_len()?, Asn1Length::Definite(5));
    /// let mut contents = Vec::new();
    /// io::copy(&mut reader.read_body()?, &mut contents)?;
    /// assert_eq!(contents, b"hello");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn read_header(&mut self) -> io::Result<Option<Asn1Tag>> {
        self.header_at(0)
    }

    /// Reads the length octets of the value whose header was just read.
    ///
    /// The reserved octet `FF`, an indefinite length on a primitive value
    /// and a length reaching past the value around it are `MalformedValue`,
    /// a length past `usize` is `LengthOverflow`, each as
    /// `io::ErrorKind::InvalidData`. Anywhere but right after
    /// [`read_header`](Self::read_header) it is `io::ErrorKind::InvalidInput`.
    /// Variable time, for public values only.
    pub fn read_len(&mut self) -> io::Result<Asn1Length> {
        self.len_at(0)
    }

    /// The contents of the value whose length was just read, as an
    /// [`Asn1Body`] that cannot read past them: values to read with the same
    /// steps when it is constructed, octets to read through `std::io::Read`
    /// when it is primitive.
    ///
    /// Nesting past [`DecodingOptions::depth`] is `DepthExceeded`, as
    /// `io::ErrorKind::InvalidData`. Anywhere but right after
    /// [`read_len`](Self::read_len) it is `io::ErrorKind::InvalidInput`.
    /// Variable time, for public values only.
    pub fn read_body(&mut self) -> io::Result<Asn1Body<'_, R>> {
        self.body_at(0)?;
        Ok(Asn1Body {
            reader: self,
            level: 1,
        })
    }

    /// Reads the next value whole and decodes it as `T`, Bouncy Castle's
    /// `ReadObject`; `None` when the input ends before a value starts.
    ///
    /// Input that ends inside the value is `io::ErrorKind::UnexpectedEof`;
    /// a value over the limits is `io::ErrorKind::InvalidData` carrying the
    /// [`Asn1Error`]. A value that does not decode as `T` is
    /// `io::ErrorKind::InvalidData` too, but it has been read, so the next
    /// call starts after it. It first closes the value before it, as
    /// [`read_header`](Self::read_header) does. Variable time, for public
    /// values only.
    ///
    /// # Examples
    ///
    /// A file sent over a socket in chunks, each chunk an OCTET STRING of at
    /// most 64 KiB; the limits bound what the peer can make it read:
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::{BufReader, Write};
    /// use std::net::TcpStream;
    ///
    /// use tc_asn1::io::Asn1Reader;
    /// use tc_asn1::{Asn1OctetString, DecodingOptions};
    ///
    /// let stream = TcpStream::connect("localhost:4000")?;
    /// let options = DecodingOptions::new(4, 64 * 1024, 16);
    /// let mut reader = Asn1Reader::new(BufReader::new(stream), options);
    /// let mut out = File::create("received.bin")?;
    /// while let Some(chunk) = reader.read_value::<Asn1OctetString>()? {
    ///     out.write_all(chunk.as_bytes())?;
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn read_value<T: Decode>(&mut self) -> io::Result<Option<T>> {
        self.value_at(0)
    }

    /// Reads the next value whole as an [`Asn1Object`], for input whose
    /// type is not known; [`read_value`](Self::read_value) with `Asn1Object`. Variable
    /// time, for public values only.
    ///
    /// # Examples
    ///
    /// Reading a file whose content is not known, each value as a tree:
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::BufReader;
    ///
    /// use tc_asn1::io::Asn1Reader;
    /// use tc_asn1::DecodingOptions;
    ///
    /// let file = BufReader::new(File::open("unknown.der")?);
    /// let mut reader = Asn1Reader::new(file, DecodingOptions::default());
    /// while let Some(object) = reader.read_object()? {
    ///     println!("{object:?}");
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn read_object(&mut self) -> io::Result<Option<Asn1Object>> {
        self.read_value::<Asn1Object>()
    }

    /// The limits every value is read within. Constant time.
    pub fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// The reader underneath. Constant time.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// The reader underneath, to read other data between values. What is
    /// read through it is not counted and a value in progress is not closed
    /// first, so use it only after the last value read was read to its end.
    /// Constant time.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Gives back the reader underneath. Constant time.
    pub fn into_inner(self) -> R {
        self.inner
    }

    // Runs one call, failing the reader on an error that loses the position
    fn guarded<T>(&mut self, call: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T> {
        if let Some(failure) = self.failed {
            return Err(failure.to_error());
        }
        let result = call(self);
        if let Err(error) = &result {
            if error.kind() != io::ErrorKind::InvalidInput {
                self.failed = Some(Failure::of(error));
            }
        }
        result
    }

    // The level `level` when it reads values and expects `step`
    fn expect(&self, level: usize, steps: &[Step], message: &'static str) -> io::Result<Level> {
        let current = self.levels[level];
        if current.primitive {
            return Err(misuse(
                "the contents of a primitive value are octets, read through io::Read",
            ));
        }
        if !steps.contains(&current.step) {
            return Err(misuse(message));
        }
        Ok(current)
    }

    fn part_at(&mut self, level: usize) -> io::Result<Part> {
        let current = self.expect(level, ALL_STEPS, "")?;
        Ok(match current.step {
            Step::Len => Part::Len(self.len_at(level)?),
            Step::Body => {
                self.body_at(level)?;
                Part::Body
            }
            _ => match self.header_at(level)? {
                Some(tag) => Part::Header(tag),
                None => Part::End,
            },
        })
    }

    fn header_at(&mut self, level: usize) -> io::Result<Option<Asn1Tag>> {
        self.guarded(|reader| {
            reader.expect(level, ALL_STEPS, "")?;
            reader.close(level)?;
            if reader.levels[level].step == Step::Done {
                return Ok(None);
            }
            let mut raw = Vec::new();
            let Some(tag) = reader.next_tag(level, &mut raw)? else {
                reader.levels[level].step = Step::Done;
                return Ok(None);
            };
            let current = &mut reader.levels[level];
            current.step = Step::Len;
            current.constructed = tag.is_constructed();
            Ok(Some(tag))
        })
    }

    fn len_at(&mut self, level: usize) -> io::Result<Asn1Length> {
        self.guarded(|reader| {
            let current = reader.expect(level, &[Step::Len], "read_len right after read_header")?;
            let length = reader.read_length(&mut Vec::new())?;
            let value_end = reader.value_end(current.constructed, length)?;
            let current = &mut reader.levels[level];
            current.value_end = value_end;
            current.step = Step::Body;
            Ok(length)
        })
    }

    fn body_at(&mut self, level: usize) -> io::Result<()> {
        self.guarded(|reader| {
            reader.expect(level, &[Step::Body], "read_body right after read_len, once")?;
            reader.open_body(level)
        })
    }

    // Closes the value in progress at `level`, if any, skipping what is
    // left of it and reading its end-of-contents octets
    fn close(&mut self, level: usize) -> io::Result<()> {
        if self.levels[level].step == Step::Len {
            let constructed = self.levels[level].constructed;
            let length = self.read_length(&mut Vec::new())?;
            let value_end = self.value_end(constructed, length)?;
            let current = &mut self.levels[level];
            current.value_end = value_end;
            current.step = Step::Body;
        }
        if self.levels[level].step == Step::Body {
            self.open_body(level)?;
        }
        while self.levels.len() > level + 1 {
            self.finish_innermost()?;
        }
        Ok(())
    }

    fn value_at<T: Decode>(&mut self, level: usize) -> io::Result<Option<T>> {
        let buffer = self.guarded(|reader| {
            reader.expect(level, ALL_STEPS, "")?;
            reader.close(level)?;
            if reader.levels[level].step == Step::Done {
                return Ok(None);
            }
            let mut buffer = Vec::new();
            let Some(tag) = reader.next_tag(level, &mut buffer)? else {
                reader.levels[level].step = Step::Done;
                return Ok(None);
            };
            let length = reader.read_length(&mut buffer)?;
            reader.value_end(tag.is_constructed(), length)?;
            let depth = u32::try_from(level).unwrap_or(u32::MAX);
            reader.read_contents(tag.is_constructed(), length, &mut buffer, depth)?;
            Ok(Some(buffer))
        })?;
        let Some(buffer) = buffer else {
            return Ok(None);
        };
        let (used, value) = T::decode(&buffer, &self.options).map_err(invalid)?;
        if used != buffer.len() {
            return Err(invalid(Asn1Error::TrailingData));
        }
        Ok(Some(value))
    }

    fn raw_at(&mut self, level: usize, buf: &mut [u8]) -> io::Result<usize> {
        self.guarded(|reader| {
            if reader.levels.len() != level + 1 || reader.levels[level].step != Step::Header {
                return Err(misuse(
                    "io::Read on a body between its values, not inside the steps of one",
                ));
            }
            let End::At(end) = reader.levels[level].end else {
                return Err(misuse(
                    "io::Read on a body of definite length; an indefinite one ends at end-of-contents octets",
                ));
            };
            let left = end - reader.position;
            if left == 0 || buf.is_empty() {
                return Ok(0);
            }
            let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let read = loop {
                match reader.inner.read(&mut buf[..want]) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            };
            if read == 0 {
                return Err(unexpected_eof());
            }
            reader.position += read as u64;
            Ok(read)
        })
    }

    // Pushes the level of the contents of the value whose length was read
    fn open_body(&mut self, level: usize) -> io::Result<()> {
        let current = self.levels[level];
        let depth = u32::try_from(level + 1).unwrap_or(u32::MAX);
        if current.constructed && depth > self.options.depth() {
            return Err(invalid(Asn1Error::DepthExceeded));
        }
        self.levels[level].step = Step::Opened;
        self.levels
            .push(Level::new(current.value_end, !current.constructed));
        Ok(())
    }

    // Reads the innermost level to its end and closes it in its parent
    fn finish_innermost(&mut self) -> io::Result<()> {
        let index = self.levels.len() - 1;
        let current = self.levels[index];
        match current.step {
            Step::Len => {
                let length = self.read_length(&mut Vec::new())?;
                let value_end = self.value_end(current.constructed, length)?;
                let current = &mut self.levels[index];
                current.value_end = value_end;
                current.step = Step::Body;
            }
            Step::Body => self.open_body(index)?,
            Step::Header if current.end == End::Eoc => {
                let tag = self.next_tag(index, &mut Vec::new())?;
                let current = &mut self.levels[index];
                match tag {
                    Some(tag) => {
                        current.step = Step::Len;
                        current.constructed = tag.is_constructed();
                    }
                    None => current.step = Step::Done,
                }
            }
            Step::Header | Step::Done => {
                if let End::At(end) = current.end {
                    self.skip(end - self.position)?;
                }
                self.levels.pop();
                if let Some(parent) = self.levels.last_mut() {
                    parent.step = Step::Header;
                }
            }
            Step::Opened => unreachable!("a level with an opened body has that body above it"),
        }
        Ok(())
    }

    // The innermost definite end around the position
    fn limit(&self) -> Option<u64> {
        self.levels.iter().rev().find_map(|level| match level.end {
            End::At(end) => Some(end),
            _ => None,
        })
    }

    // Where the contents of a value whose header ends here end, within the
    // values around it
    fn value_end(&self, constructed: bool, length: Asn1Length) -> io::Result<End> {
        let end = match length {
            Asn1Length::Definite(len) => End::At(
                self.position
                    .checked_add(len as u64)
                    .ok_or_else(|| invalid(Asn1Error::LengthOverflow))?,
            ),
            Asn1Length::Indefinite if constructed => End::Eoc,
            Asn1Length::Indefinite => return Err(invalid(Asn1Error::MalformedValue)),
        };
        if let (Some(limit), End::At(end)) = (self.limit(), end) {
            if end > limit {
                return Err(invalid(Asn1Error::MalformedValue));
            }
        }
        Ok(end)
    }

    // The identifier octets of the next value of `level`, appended to `raw`;
    // None at the end of the level, its end-of-contents octets read
    fn next_tag(&mut self, level: usize, raw: &mut Vec<u8>) -> io::Result<Option<Asn1Tag>> {
        let end = self.levels[level].end;
        if end == End::At(self.position) {
            return Ok(None);
        }
        let Some(tag) = self.read_tag(raw)? else {
            return match end {
                End::Input => Ok(None),
                _ => Err(unexpected_eof()),
            };
        };
        if tag.as_bytes() == [0x00] {
            if end != End::Eoc || self.read_octet(raw)? != 0x00 {
                return Err(invalid(Asn1Error::MalformedValue));
            }
            return Ok(None);
        }
        Ok(Some(tag))
    }

    fn read_tag(&mut self, raw: &mut Vec<u8>) -> io::Result<Option<Asn1Tag>> {
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
        Ok(Some(Asn1Tag::new(raw[start..start + tag_len].to_vec())))
    }

    fn read_length(&mut self, raw: &mut Vec<u8>) -> io::Result<Asn1Length> {
        let start = raw.len();
        let first = self.read_octet(raw)?;
        if first > 0x80 && first != 0xFF {
            for _ in 0..first & 0x7F {
                self.read_octet(raw)?;
            }
        }
        let (_, length) = parse_len(&raw[start..]).map_err(invalid)?;
        Ok(length.map_or(Asn1Length::Indefinite, Asn1Length::Definite))
    }

    // Refuses to read past the innermost definite end
    fn check_room(&self, more: u64) -> io::Result<()> {
        match self.limit() {
            Some(limit) if self.position + more > limit => Err(invalid(Asn1Error::MalformedValue)),
            _ => Ok(()),
        }
    }

    // The first octet of a value, or None at the end of the input
    fn read_first_octet(&mut self) -> io::Result<Option<u8>> {
        self.check_room(1)?;
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

    fn read_octet(&mut self, raw: &mut Vec<u8>) -> io::Result<u8> {
        self.check_room(1)?;
        let mut octet = [0u8; 1];
        self.inner.read_exact(&mut octet)?;
        self.position += 1;
        raw.push(octet[0]);
        Ok(octet[0])
    }

    fn skip(&mut self, count: u64) -> io::Result<()> {
        let skipped = io::copy(&mut (&mut self.inner).take(count), &mut io::sink())?;
        self.position += skipped;
        if skipped != count {
            return Err(unexpected_eof());
        }
        Ok(())
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

    // Appends the contents of a value whose header is already in `buffer`,
    // following an indefinite length to its end-of-contents octets
    fn read_contents(
        &mut self,
        constructed: bool,
        length: Asn1Length,
        buffer: &mut Vec<u8>,
        depth: u32,
    ) -> io::Result<()> {
        if depth > self.options.depth() {
            return Err(invalid(Asn1Error::DepthExceeded));
        }
        self.reserve(buffer, 0)?;
        match length {
            Asn1Length::Definite(len) => {
                if len > self.options.max_content_len() {
                    return Err(invalid(Asn1Error::ContentLengthExceeded));
                }
                self.reserve(buffer, len)?;
                self.check_room(len as u64)?;
                // Grows with the octets that arrive, not with the length claimed
                let read = (&mut self.inner).take(len as u64).read_to_end(buffer)?;
                self.position += read as u64;
                if read != len {
                    return Err(unexpected_eof());
                }
                Ok(())
            }
            Asn1Length::Indefinite => {
                if !constructed {
                    return Err(invalid(Asn1Error::MalformedValue));
                }
                loop {
                    let tag = self.read_tag(buffer)?.ok_or_else(unexpected_eof)?;
                    let length = self.read_length(buffer)?;
                    if tag.as_bytes() == [0x00] {
                        if length != Asn1Length::Definite(0) {
                            return Err(invalid(Asn1Error::MalformedValue));
                        }
                        return Ok(());
                    }
                    self.read_contents(tag.is_constructed(), length, buffer, depth + 1)?;
                }
            }
        }
    }
}

/// The contents of one value, from [`Asn1Reader::read_body`] or
/// [`Asn1Body::read_body`], which cannot be read past.
///
/// The contents of a constructed value are values, read with the same steps
/// as on [`Asn1Reader`]: [`read`](Self::read), [`read_header`](Self::read_header),
/// [`read_len`](Self::read_len) and [`read_body`](Self::read_body), or
/// whole with [`read_value`](Self::read_value) and
/// [`read_object`](Self::read_object); `None` from `read_header` or `read_value`
/// is the end of the contents. The contents of a primitive value are
/// octets, read through `std::io::Read`, which also copies the contents of a
/// constructed value of definite length as they are. While a body is held,
/// the reader it came from cannot be used; what it leaves unread is skipped
/// by the next read on that reader.
///
/// # Examples
///
/// Printing the structure of data whose content is not known, as
/// `openssl asn1parse` does, with the first octets of each primitive value:
///
/// ```
/// use std::io::{self, Read};
///
/// use tc_asn1::io::{Asn1Body, Asn1Reader};
/// use tc_asn1::DecodingOptions;
///
/// fn dump<R: Read>(body: &mut Asn1Body<'_, R>, indent: usize) -> io::Result<()> {
///     while let Some(tag) = body.read_header()? {
///         let length = body.read_len()?;
///         if tag.is_constructed() {
///             println!("{:indent$}{:02X?} {length:?}", "", tag.as_bytes());
///             dump(&mut body.read_body()?, indent + 2)?;
///         } else {
///             // A primitive value may be large: look at its first octets only
///             let mut head = Vec::new();
///             body.read_body()?.take(16).read_to_end(&mut head)?;
///             println!("{:indent$}{:02X?} {head:02X?}", "", tag.as_bytes());
///         }
///     }
///     Ok(())
/// }
///
/// // SEQUENCE (indefinite) { INTEGER 5, OCTET STRING "abc" }, as from a file
/// let data: &[u8] = &[
///     0x30, 0x80, 0x02, 0x01, 0x05, 0x04, 0x03, b'a', b'b', b'c', 0x00, 0x00,
/// ];
/// let mut reader = Asn1Reader::new(data, DecodingOptions::default());
/// while let Some(tag) = reader.read_header()? {
///     let length = reader.read_len()?;
///     println!("{:02X?} {length:?}", tag.as_bytes());
///     if tag.is_constructed() {
///         dump(&mut reader.read_body()?, 2)?;
///     }
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// A SEQUENCE OF too many entries to hold at once, such as the serial
/// numbers of a large CRL, taken one entry at a time:
///
/// ```
/// use tc_asn1::io::Asn1Reader;
/// use tc_asn1::{Asn1Integer, DecodingOptions};
///
/// // SEQUENCE OF INTEGER, as from a file
/// let data: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
/// let mut reader = Asn1Reader::new(data, DecodingOptions::default());
///
/// reader.read_header()?;
/// reader.read_len()?;
/// {
///     let mut entries = reader.read_body()?;
///     while let Some(serial) = entries.read_value::<Asn1Integer>()? {
///         println!("{serial}");
///     }
/// }
/// assert!(reader.read_header()?.is_none());
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Body<'a, R> {
    reader: &'a mut Asn1Reader<R>,
    level: usize,
}

impl<R: Read> Asn1Body<'_, R> {
    /// [`Asn1Reader::read`] for the values of this body; `None` at its end.
    pub fn read(&mut self) -> io::Result<Option<Asn1Item<'_, R>>> {
        Ok(match self.reader.part_at(self.level)? {
            Part::Header(tag) => Some(Asn1Item::Header(tag)),
            Part::Len(length) => Some(Asn1Item::Len(length)),
            Part::Body => Some(Asn1Item::Body(Asn1Body {
                reader: &mut *self.reader,
                level: self.level + 1,
            })),
            Part::End => None,
        })
    }

    /// [`Asn1Reader::read_header`] for the values of this body; `None` at
    /// its end.
    pub fn read_header(&mut self) -> io::Result<Option<Asn1Tag>> {
        self.reader.header_at(self.level)
    }

    /// [`Asn1Reader::read_len`] for the values of this body.
    pub fn read_len(&mut self) -> io::Result<Asn1Length> {
        self.reader.len_at(self.level)
    }

    /// [`Asn1Reader::read_body`] for the values of this body.
    pub fn read_body(&mut self) -> io::Result<Asn1Body<'_, R>> {
        self.reader.body_at(self.level)?;
        Ok(Asn1Body {
            reader: &mut *self.reader,
            level: self.level + 1,
        })
    }

    /// [`Asn1Reader::read_value`] for the values of this body; `None` at its end.
    pub fn read_value<T: Decode>(&mut self) -> io::Result<Option<T>> {
        self.reader.value_at(self.level)
    }

    /// [`Asn1Reader::read_object`] for the values of this body; `None` at
    /// its end.
    pub fn read_object(&mut self) -> io::Result<Option<Asn1Object>> {
        self.read_value::<Asn1Object>()
    }
}

/// The octets of the contents, never past their end: those of a primitive
/// value, or those of a constructed value of definite length as they are,
/// between its values. On an indefinite length, or inside the steps of a
/// value, it is `io::ErrorKind::InvalidInput`. Variable time, for public
/// values only.
impl<R: Read> Read for Asn1Body<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.raw_at(self.level, buf)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use std::io::{self, Read};

    use super::{Asn1Body, Asn1Reader};
    use crate::io::{Asn1Item, Asn1Length, Asn1Writer};
    use crate::{
        Asn1Any, Asn1Class, Asn1Error, Asn1Integer, Asn1OctetString, DecodingOptions,
        EncodingOptions,
    };

    fn error_of(error: io::Error) -> Asn1Error {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        *error.into_inner().unwrap().downcast::<Asn1Error>().unwrap()
    }

    fn open(wire: &[u8]) -> Asn1Reader<&[u8]> {
        Asn1Reader::new(wire, DecodingOptions::default())
    }

    // Reads every value of a body in steps, collecting tags and primitive contents
    fn walk<R: Read>(body: &mut Asn1Body<'_, R>, seen: &mut Vec<Vec<u8>>) -> io::Result<()> {
        while let Some(tag) = body.read_header()? {
            body.read_len()?;
            seen.push(tag.as_bytes().to_vec());
            let mut contents = body.read_body()?;
            if tag.is_constructed() {
                walk(&mut contents, seen)?;
            } else {
                let mut octets = Vec::new();
                contents.read_to_end(&mut octets)?;
                seen.push(octets);
            }
        }
        Ok(())
    }

    #[test]
    fn what_the_writer_writes_the_reader_reads_back_in_turn() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write(&Asn1Integer::from(300)).unwrap();
        writer.write(&Asn1OctetString::new(&[7; 200])).unwrap();
        let bytes = writer.into_inner();

        let mut reader = open(&bytes);
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(300))
        );
        let octets = reader.read_value::<Asn1OctetString>().unwrap().unwrap();
        assert_eq!(octets.as_bytes(), &[7; 200]);
        assert!(reader.read_value::<Asn1Integer>().unwrap().is_none());
    }

    #[test]
    fn a_value_is_read_in_steps() {
        let wire: &[u8] = &[0x04, 0x05, b'h', b'e', b'l', b'l', b'o', 0x02, 0x01, 0x07];
        let mut reader = open(wire);

        let tag = reader.read_header().unwrap().unwrap();
        assert_eq!(tag.as_bytes(), [0x04]);
        assert_eq!(tag.class(), Asn1Class::Universal);
        assert!(!tag.is_constructed());
        assert_eq!(reader.read_len().unwrap(), Asn1Length::Definite(5));
        let mut contents = Vec::new();
        reader
            .read_body()
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"hello");

        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(7))
        );
        assert!(reader.read_header().unwrap().is_none());
    }

    // The same walk as `walk`, through read
    fn walk_items<R: Read>(body: &mut Asn1Body<'_, R>, seen: &mut Vec<Vec<u8>>) -> io::Result<()> {
        let mut constructed = false;
        while let Some(item) = body.read()? {
            match item {
                Asn1Item::Header(tag) => {
                    constructed = tag.is_constructed();
                    seen.push(tag.as_bytes().to_vec());
                }
                Asn1Item::Len(_) => {}
                Asn1Item::Body(mut contents) if constructed => walk_items(&mut contents, seen)?,
                Asn1Item::Body(mut contents) => {
                    let mut octets = Vec::new();
                    contents.read_to_end(&mut octets)?;
                    seen.push(octets);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn read_gives_header_len_and_body_in_turn_and_mixes_with_the_steps() {
        // SEQUENCE (indefinite) { INTEGER 5, SET { BOOLEAN TRUE } }, then NULL
        let wire: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x05, 0x31, 0x03, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x05, 0x00,
        ];
        let mut reader = open(wire);
        let mut seen = Vec::new();
        let tag = match reader.read().unwrap() {
            Some(Asn1Item::Header(tag)) => tag,
            other => panic!("{other:?}"),
        };
        seen.push(tag.as_bytes().to_vec());
        assert_eq!(reader.read_len().unwrap(), Asn1Length::Indefinite);
        match reader.read().unwrap() {
            Some(Asn1Item::Body(mut body)) => walk_items(&mut body, &mut seen).unwrap(),
            other => panic!("{other:?}"),
        }
        assert_eq!(reader.read_header().unwrap().unwrap().as_bytes(), [0x05]);
        assert!(matches!(
            reader.read().unwrap(),
            Some(Asn1Item::Len(Asn1Length::Definite(0)))
        ));
        assert!(reader.read().unwrap().is_some());
        assert!(reader.read().unwrap().is_none());

        let expected: [&[u8]; 6] = [&[0x30], &[0x02], &[0x05], &[0x31], &[0x01], &[0xFF]];
        assert_eq!(seen, expected);
    }

    #[test]
    fn read_closes_the_value_left_in_progress() {
        let wire: &[u8] = &[0x04, 0x03, b'a', b'b', b'c', 0x02, 0x01, 0x07];
        let mut reader = open(wire);
        assert!(matches!(reader.read().unwrap(), Some(Asn1Item::Header(_))));
        assert!(matches!(reader.read().unwrap(), Some(Asn1Item::Len(_))));
        assert!(matches!(reader.read().unwrap(), Some(Asn1Item::Body(_))));
        match reader.read().unwrap() {
            Some(Asn1Item::Header(tag)) => assert_eq!(tag.as_bytes(), [0x02]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bodies_walk_definite_and_indefinite_values_alike() {
        // SEQUENCE (indefinite) { INTEGER 5, SET { BOOLEAN TRUE } }, then NULL
        let wire: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x05, 0x31, 0x03, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x05, 0x00,
        ];
        let mut reader = open(wire);
        let mut seen = Vec::new();
        while let Some(tag) = reader.read_header().unwrap() {
            reader.read_len().unwrap();
            seen.push(tag.as_bytes().to_vec());
            if tag.is_constructed() {
                walk(&mut reader.read_body().unwrap(), &mut seen).unwrap();
            }
        }
        let expected: [&[u8]; 7] = [
            &[0x30],
            &[0x02],
            &[0x05],
            &[0x31],
            &[0x01],
            &[0xFF],
            &[0x05],
        ];
        assert_eq!(seen, expected);
    }

    #[test]
    fn the_next_read_skips_what_was_left_unread() {
        // SEQUENCE (indefinite) { SEQUENCE (indefinite) { OCTET STRING "abc" } INTEGER 1 }, then INTEGER 9
        let wire: &[u8] = &[
            0x30, 0x80, 0x30, 0x80, 0x04, 0x03, b'a', b'b', b'c', 0x00, 0x00, 0x02, 0x01, 0x01,
            0x00, 0x00, 0x02, 0x01, 0x09,
        ];
        // Only its header read
        let mut reader = open(wire);
        reader.read_header().unwrap();
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(9))
        );

        // Never opened
        let mut reader = open(wire);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(9))
        );

        // Left in the middle of an inner value
        let mut reader = super::Asn1Reader::new(wire, DecodingOptions::default());
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        {
            let mut outer = reader.read_body().unwrap();
            outer.read_header().unwrap();
            outer.read_len().unwrap();
            let mut inner = outer.read_body().unwrap();
            inner.read_header().unwrap();
            inner.read_len().unwrap();
            let mut octet = [0u8; 1];
            inner.read_body().unwrap().read_exact(&mut octet).unwrap();
        }
        assert_eq!(
            reader.read_value::<Asn1Integer>().unwrap(),
            Some(Asn1Integer::from(9))
        );
    }

    #[test]
    fn read_inside_a_body_stops_at_its_end() {
        for wire in [
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02][..],
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00],
        ] {
            let mut reader = open(wire);
            reader.read_header().unwrap();
            reader.read_len().unwrap();
            let mut integers = Vec::new();
            {
                let mut body = reader.read_body().unwrap();
                while let Some(integer) = body.read_value::<Asn1Integer>().unwrap() {
                    integers.push(integer);
                }
            }
            assert_eq!(integers, [Asn1Integer::from(1), Asn1Integer::from(2)]);
            assert!(reader.read_header().unwrap().is_none());
        }
    }

    #[test]
    fn a_constructed_body_of_definite_length_reads_as_octets_too() {
        let wire: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x05, 0x00];
        let mut reader = open(wire);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let mut contents = Vec::new();
        reader
            .read_body()
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, &wire[2..8]);

        let mut reader =
            super::Asn1Reader::new(&[0x30, 0x80, 0x00, 0x00][..], DecodingOptions::default());
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let error = reader
            .read_body()
            .unwrap()
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn calls_out_of_order_are_refused_without_reading() {
        let wire: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
        let mut reader = open(wire);
        let refused = |result: io::Result<()>| {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        };
        refused(reader.read_len().map(drop));
        refused(reader.read_body().map(drop));
        reader.read_header().unwrap();
        refused(reader.read_body().map(drop));
        reader.read_len().unwrap();
        refused(reader.read_len().map(drop));
        reader.read_body().unwrap();
        refused(reader.read_body().map(drop));
        refused(reader.read_len().map(drop));
        // The next read closes the value
        assert!(reader.read_header().unwrap().is_none());
    }

    #[test]
    fn primitive_contents_are_not_read_as_values() {
        let mut reader = open(&[0x04, 0x03, 0x02, 0x01, 0x01]);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let mut body = reader.read_body().unwrap();
        assert_eq!(
            body.read_header().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn after_an_error_in_the_input_the_reader_fails_from_then_on() {
        let mut reader = open(&[0x04, 0xFF, 0x02, 0x01, 0x05]);
        reader.read_header().unwrap();
        assert_eq!(
            error_of(reader.read_len().unwrap_err()),
            Asn1Error::MalformedValue
        );
        assert_eq!(
            error_of(reader.read_header().unwrap_err()),
            Asn1Error::MalformedValue
        );
        assert_eq!(
            error_of(reader.read_value::<Asn1Integer>().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn a_value_of_another_type_is_invalid_data_and_the_next_value_still_reads() {
        let wire: &[u8] = &[0x01, 0x01, 0xFF, 0x02, 0x01, 0x07];
        let mut reader = open(wire);
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
    fn a_value_reaching_past_the_one_around_it_is_malformed() {
        let wire: &[u8] = &[0x30, 0x03, 0x04, 0x05, 1, 2, 3, 4, 5];
        let mut reader = open(wire);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let mut body = reader.read_body().unwrap();
        body.read_header().unwrap();
        assert_eq!(
            error_of(body.read_len().unwrap_err()),
            Asn1Error::MalformedValue
        );

        let mut reader = super::Asn1Reader::new(wire, DecodingOptions::default());
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let mut body = reader.read_body().unwrap();
        assert_eq!(
            error_of(body.read_value::<Asn1OctetString>().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn end_of_contents_outside_an_indefinite_length_is_malformed() {
        let mut reader = open(&[0x00, 0x00]);
        assert_eq!(
            error_of(reader.read_header().unwrap_err()),
            Asn1Error::MalformedValue
        );

        let mut reader = open(&[0x30, 0x02, 0x00, 0x00]);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        assert_eq!(
            error_of(reader.read_body().unwrap().read_header().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn an_indefinite_length_is_followed_to_its_end_of_contents() {
        // SEQUENCE (indefinite) { [0] (indefinite) { INTEGER 1 } INTEGER 2 }, then INTEGER 3
        let wire: &[u8] = &[
            0x30, 0x80, 0xA0, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00,
            0x02, 0x01, 0x03,
        ];
        let mut reader = open(wire);
        let sequence = reader.read_value::<Asn1Any>().unwrap().unwrap();
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
            let error = open(wire).read_value::<Asn1Any>().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{wire:02X?}");
        }

        let mut reader = open(&[0x30, 0x05, 0x02, 0x01, 0x01]);
        reader.read_header().unwrap();
        reader.read_len().unwrap();
        let error = reader.read_header().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
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
            error_of(reader.read_value::<Asn1Any>().unwrap_err()),
            Asn1Error::ContentLengthExceeded
        );
    }

    #[test]
    fn nesting_past_the_depth_limit_is_refused() {
        let options = DecodingOptions::new(3, 1024, 1024);
        let wire = [0x30, 0x80].repeat(5);
        let mut reader = Asn1Reader::new(&wire[..], options.clone());
        assert_eq!(
            error_of(reader.read_value::<Asn1Any>().unwrap_err()),
            Asn1Error::DepthExceeded
        );

        let mut reader = Asn1Reader::new(&wire[..], options);
        let error = (|| -> io::Result<()> {
            reader.read_header()?;
            reader.read_len()?;
            let mut body = reader.read_body()?;
            let mut seen = Vec::new();
            walk(&mut body, &mut seen)
        })()
        .unwrap_err();
        assert_eq!(error_of(error), Asn1Error::DepthExceeded);
    }

    #[test]
    fn a_primitive_value_with_an_indefinite_length_is_malformed() {
        let mut reader = open(&[0x04, 0x80, 0x00, 0x00]);
        assert_eq!(
            error_of(reader.read_value::<Asn1Any>().unwrap_err()),
            Asn1Error::MalformedValue
        );

        let mut reader = open(&[0x04, 0x80, 0x00, 0x00]);
        reader.read_header().unwrap();
        assert_eq!(
            error_of(reader.read_len().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn nothing_past_a_value_is_read() {
        let wire: &[u8] = &[
            0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, b't', b'a', b'i', b'l',
        ];
        let mut reader = open(wire);
        reader.read_object().unwrap().unwrap();
        assert_eq!(reader.into_inner(), b"tail");
    }

    #[test]
    fn read_object_gives_the_tree_of_a_value_of_unknown_type() {
        let wire: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xFF];
        let mut reader = open(wire);
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
        assert_eq!(
            error_of(open(&wire).read_header().unwrap_err()),
            Asn1Error::MalformedValue
        );
    }

    #[test]
    fn the_header_rules_are_those_of_asn1_ref() {
        for (wire, expected) in [
            (&[0x1F, 0x80, 0x01, 0x00][..], Asn1Error::NonMinimalTag),
            (&[0x1F, 0x05, 0x00], Asn1Error::NonMinimalTag),
        ] {
            assert_eq!(
                error_of(open(wire).read_header().unwrap_err()),
                expected,
                "{wire:02X?}"
            );
        }
        let mut high = open(&[0x9F, 0x1F, 0x82, 0x01, 0x00]);
        assert_eq!(
            high.read_header().unwrap().unwrap().as_bytes(),
            [0x9F, 0x1F]
        );
        assert_eq!(high.read_len().unwrap(), Asn1Length::Definite(256));
    }
}
