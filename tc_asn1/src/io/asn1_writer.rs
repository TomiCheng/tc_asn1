//! Writing encoded values to a `std::io::Write`, after Bouncy Castle's
//! `Asn1OutputStream` and its generators.

use alloc::vec::Vec;
use std::io::{self, Write};

use super::Asn1Length;
use crate::asn1_ref::parse_tag;
use crate::traits::encode::write_len;
use crate::{Encode, EncodingOptions, EncodingType};

// A call the state of its level does not allow; nothing is written for it
fn misuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// Where the contents of a level end
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum End {
    Output,
    At(u64),
    Eoc,
}

// What a level expects next
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Header,
    Len,
    Body,
}

// The contents of one value being written, or the output itself at level 0
#[derive(Clone, Copy, Debug)]
struct Level {
    end: End,
    // Contents that are octets rather than values
    primitive: bool,
    step: Step,
    // The value whose header this level has written
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
            value_end: End::Output,
        }
    }
}

// Counts what an encoding writes through it
struct Counting<'a, W> {
    inner: &'a mut W,
    count: u64,
}

impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes values to `W` under one set of rules, as Bouncy Castle's
/// `Asn1OutputStream` and its generators do: a file, a socket or any other
/// `std::io::Write`.
///
/// A value is written whole with [`write_value`](Self::write_value), or in
/// steps: [`write_header`](Self::write_header) for its identifier octets,
/// [`write_len`](Self::write_len) for its length and
/// [`write_body`](Self::write_body) for its contents, an [`Asn1BodyWriter`]
/// that takes the same steps for the values of a constructed value and
/// octets through `std::io::Write` for a primitive one. A definite length
/// closes the value once its contents are written; an indefinite one is
/// closed with [`write_foot`](Self::write_foot). Writing in steps lets a
/// value larger than memory be written part by part. [`flush`](Self::flush)
/// comes last: it checks that every value is closed.
///
/// Each level keeps a state machine: a call out of order, a length or
/// contents past the value around them, identifier octets that are not
/// valid, and an indefinite length where it is not allowed are
/// `io::ErrorKind::InvalidInput` and write nothing. An encoding failure is
/// `io::ErrorKind::InvalidData` carrying the
/// [`Asn1Error`](crate::Asn1Error), with nothing written. A failure of the
/// writer underneath leaves the output cut inside a value, so the writer
/// fails from then on and every call gives that error again. Writing is
/// variable time, for public values only: it branches on the structure.
///
/// Available with the `std` feature.
///
/// ```
/// use tc_asn1::io::Asn1Writer;
/// use tc_asn1::{Asn1Boolean, Asn1Integer, EncodingOptions};
///
/// let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
/// writer.write_value(&Asn1Integer::from(5))?;
/// writer.write_value(&Asn1Boolean::from(true))?;
/// writer.flush()?;
/// assert_eq!(writer.into_inner(), [0x02, 0x01, 0x05, 0x01, 0x01, 0xFF]);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1Writer<W> {
    inner: W,
    options: EncodingOptions,
    // Octets written to `inner` through this writer
    position: u64,
    // Level 0 is the output; each body written pushes the next
    levels: Vec<Level>,
    failed: Option<io::ErrorKind>,
}

impl<W: Write> Asn1Writer<W> {
    /// A writer to `inner` that writes every value under `options`.
    /// Constant time.
    pub fn new(inner: W, options: EncodingOptions) -> Self {
        Self {
            inner,
            options,
            position: 0,
            levels: alloc::vec![Level::new(End::Output, false)],
            failed: None,
        }
    }

    /// Writes the identifier octets of the next value, such as
    /// [`Asn1OctetString::TAG`](crate::Asn1OctetString::TAG).
    ///
    /// Identifier octets that are not one valid tag, end-of-contents octets
    /// among them, are `io::ErrorKind::InvalidInput`, as is a value before it
    /// that is not finished: a definite length whose contents are short, or
    /// an indefinite one not closed with [`write_foot`](Self::write_foot).
    /// Variable time, for public values only.
    ///
    /// # Examples
    ///
    /// A large OCTET STRING whose size is known, written as its contents
    /// arrive, here from a file:
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io;
    ///
    /// use tc_asn1::io::{Asn1Length, Asn1Writer};
    /// use tc_asn1::{Asn1OctetString, EncodingOptions};
    ///
    /// let mut source = File::open("content.bin")?;
    /// let size = source.metadata()?.len() as usize;
    ///
    /// let mut writer = Asn1Writer::new(File::create("content.der")?, EncodingOptions::DER);
    /// writer.write_header(Asn1OctetString::TAG)?;
    /// writer.write_len(Asn1Length::Definite(size))?;
    /// io::copy(&mut source, &mut writer.write_body()?)?;
    /// writer.flush()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn write_header(&mut self, tag: &[u8]) -> io::Result<()> {
        self.header_at(0, tag)
    }

    /// Writes the length octets of the value whose header was just written.
    ///
    /// A length that cannot hold its contents within the value around it,
    /// an indefinite length on a primitive value, and an indefinite length
    /// under DER are `io::ErrorKind::InvalidInput`, as is a call anywhere but
    /// right after [`write_header`](Self::write_header). The contents are
    /// checked against the length as they are written. Variable time, for
    /// public values only.
    pub fn write_len(&mut self, length: Asn1Length) -> io::Result<()> {
        self.len_at(0, length)
    }

    /// The contents of the value whose length was just written, as an
    /// [`Asn1BodyWriter`] that cannot write past them: values written with
    /// the same steps when it is constructed, octets written through
    /// `std::io::Write` when it is primitive. Called again before the value
    /// is closed, it goes on where the last body stopped.
    ///
    /// Before [`write_len`](Self::write_len) it is
    /// `io::ErrorKind::InvalidInput`. Variable time, for public values only.
    ///
    /// # Examples
    ///
    /// A SEQUENCE of indefinite length whose entries come one at a time, as
    /// from a database too large to hold, closed with
    /// [`write_foot`](Self::write_foot):
    ///
    /// ```
    /// use tc_asn1::io::{Asn1Length, Asn1Writer};
    /// use tc_asn1::{Asn1Integer, EncodingOptions};
    ///
    /// let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
    /// writer.write_header(&[0x30])?;
    /// writer.write_len(Asn1Length::Indefinite)?;
    /// {
    ///     let mut entries = writer.write_body()?;
    ///     for serial in 1..=3 {
    ///         entries.write_value(&Asn1Integer::from(serial))?;
    ///     }
    /// }
    /// writer.write_foot()?;
    /// writer.flush()?;
    ///
    /// assert_eq!(
    ///     writer.into_inner(),
    ///     [0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00]
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn write_body(&mut self) -> io::Result<Asn1BodyWriter<'_, W>> {
        self.body_at(0)?;
        Ok(Asn1BodyWriter {
            writer: self,
            level: 1,
        })
    }

    /// Closes the value of indefinite length whose body was written, writing
    /// its end-of-contents octets.
    ///
    /// On a value of definite length, which closes itself, before its body,
    /// or while a value inside its body is not finished, it is
    /// `io::ErrorKind::InvalidInput`. Variable time, for public values only.
    pub fn write_foot(&mut self) -> io::Result<()> {
        self.foot_at(0)
    }

    /// Encodes `value` and writes its whole TLV, Bouncy Castle's
    /// `WriteObject`.
    ///
    /// An encoding failure is `io::ErrorKind::InvalidData` carrying the
    /// [`Asn1Error`](crate::Asn1Error), with nothing written; a value that
    /// does not fit within the value around it, or one written while the
    /// value before it is not finished, is `io::ErrorKind::InvalidInput`.
    /// Variable time, for public values only.
    ///
    /// # Examples
    ///
    /// Messages to a peer, one value each:
    ///
    /// ```no_run
    /// use std::io::BufWriter;
    /// use std::net::TcpStream;
    ///
    /// use tc_asn1::io::Asn1Writer;
    /// use tc_asn1::{Asn1OctetString, EncodingOptions};
    ///
    /// let stream = BufWriter::new(TcpStream::connect("localhost:4000")?);
    /// let mut writer = Asn1Writer::new(stream, EncodingOptions::DER);
    /// for chunk in [&b"first"[..], b"second"] {
    ///     writer.write_value(&Asn1OctetString::new(chunk))?;
    ///     writer.flush()?;
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn write_value<T: Encode + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        self.value_at(0, value)
    }

    /// Checks that every value is closed, then flushes the writer
    /// underneath; the last call of a writing. A value not finished is
    /// `io::ErrorKind::InvalidInput`. To push out what is written while a
    /// value is still open, flush its body instead. Variable time, for public
    /// values only.
    pub fn flush(&mut self) -> io::Result<()> {
        self.guarded(|writer| {
            writer.settle(0);
            if writer.levels.len() != 1 || writer.levels[0].step != Step::Header {
                return Err(misuse("flush with a value not finished"));
            }
            writer.inner.flush()
        })
    }

    /// The rules every value is written under. Constant time.
    pub fn options(&self) -> &EncodingOptions {
        &self.options
    }

    /// The writer underneath. Constant time.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The writer underneath, to write other data between values. What is
    /// written through it is not counted, so use it only when every value
    /// is closed. Constant time.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Gives back the writer underneath, without flushing it. Constant time.
    pub fn into_inner(self) -> W {
        self.inner
    }

    // Runs one call, failing the writer when the writer underneath fails
    fn guarded<T>(&mut self, call: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T> {
        if let Some(kind) = self.failed {
            return Err(io::Error::from(kind));
        }
        let result = call(self);
        if let Err(error) = &result {
            if !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData
            ) {
                self.failed = Some(error.kind());
            }
        }
        result
    }

    // Closes the value in progress at `level`, and those above it, whose
    // definite length is used up
    fn settle(&mut self, level: usize) {
        if self.levels.len() > level + 1 {
            self.settle(level + 1);
        }
        let current = self.levels[level];
        if current.step == Step::Body && current.value_end == End::At(self.position) {
            let child_open = self
                .levels
                .get(level + 1)
                .is_some_and(|child| child.step != Step::Header);
            if !child_open {
                self.levels.truncate(level + 1);
                self.levels[level].step = Step::Header;
            }
        }
    }

    // The level `level` ready for its next value
    fn ready(&mut self, level: usize) -> io::Result<()> {
        if self.levels[level].primitive {
            return Err(misuse(
                "the contents of a primitive value are octets, written through io::Write",
            ));
        }
        self.settle(level);
        match self.levels[level] {
            Level {
                step: Step::Header, ..
            } => Ok(()),
            Level {
                step: Step::Len, ..
            } => Err(misuse("write_len before the next value")),
            Level {
                value_end: End::Eoc,
                ..
            } => Err(misuse("write_foot before the next value")),
            _ => Err(misuse(
                "the contents of the value before are shorter than its length",
            )),
        }
    }

    // The innermost definite end around the position
    fn limit(&self) -> Option<u64> {
        self.levels.iter().rev().find_map(|level| match level.end {
            End::At(end) => Some(end),
            _ => None,
        })
    }

    fn check_room(&self, more: u64) -> io::Result<()> {
        match self.limit() {
            Some(limit) if self.position + more > limit => {
                Err(misuse("past the length of the value around it"))
            }
            _ => Ok(()),
        }
    }

    fn put(&mut self, octets: &[u8]) -> io::Result<()> {
        self.inner.write_all(octets)?;
        self.position += octets.len() as u64;
        Ok(())
    }

    fn header_at(&mut self, level: usize, tag: &[u8]) -> io::Result<()> {
        self.guarded(|writer| {
            writer.ready(level)?;
            if tag == [0x00] || !parse_tag(tag).is_ok_and(|parsed| parsed.len() == tag.len()) {
                return Err(misuse("identifier octets that are not one valid tag"));
            }
            writer.check_room(tag.len() as u64)?;
            writer.put(tag)?;
            let current = &mut writer.levels[level];
            current.step = Step::Len;
            current.constructed = tag[0] & 0x20 != 0;
            Ok(())
        })
    }

    fn len_at(&mut self, level: usize, length: Asn1Length) -> io::Result<()> {
        self.guarded(|writer| {
            let current = writer.levels[level];
            if current.primitive || current.step != Step::Len {
                return Err(misuse("write_len right after write_header"));
            }
            let mut octets = [0u8; 1 + core::mem::size_of::<usize>()];
            let (count, value_end) = match length {
                Asn1Length::Definite(len) => {
                    let count = write_len(len, &mut octets);
                    writer.check_room(count as u64 + len as u64)?;
                    (count, End::At(writer.position + count as u64 + len as u64))
                }
                Asn1Length::Indefinite => {
                    if !current.constructed {
                        return Err(misuse("an indefinite length on a primitive value"));
                    }
                    if matches!(writer.options.encoding_type(), EncodingType::Der) {
                        return Err(misuse("an indefinite length under DER"));
                    }
                    // Room for the end-of-contents octets at least
                    writer.check_room(3)?;
                    octets[0] = 0x80;
                    (1, End::Eoc)
                }
            };
            writer.put(&octets[..count])?;
            let current = &mut writer.levels[level];
            current.value_end = value_end;
            current.step = Step::Body;
            Ok(())
        })
    }

    fn body_at(&mut self, level: usize) -> io::Result<()> {
        self.guarded(|writer| {
            let current = writer.levels[level];
            if current.primitive || current.step != Step::Body {
                return Err(misuse("write_body after write_len"));
            }
            if writer.levels.len() == level + 1 {
                writer
                    .levels
                    .push(Level::new(current.value_end, !current.constructed));
            }
            Ok(())
        })
    }

    fn foot_at(&mut self, level: usize) -> io::Result<()> {
        self.guarded(|writer| {
            let current = writer.levels[level];
            if current.primitive || current.step != Step::Body || current.value_end != End::Eoc {
                return Err(misuse(
                    "write_foot on a value of indefinite length after its body",
                ));
            }
            if writer.levels.len() > level + 1 {
                writer.settle(level + 1);
                let child = writer.levels[level + 1];
                if child.step != Step::Header || writer.levels.len() > level + 2 {
                    return Err(misuse("write_foot with a value inside not finished"));
                }
            }
            writer.check_room(2)?;
            writer.put(&[0x00, 0x00])?;
            writer.levels.truncate(level + 1);
            writer.levels[level].step = Step::Header;
            Ok(())
        })
    }

    fn value_at<T: Encode + ?Sized>(&mut self, level: usize, value: &T) -> io::Result<()> {
        self.guarded(|writer| {
            writer.ready(level)?;
            let len = value.encoded_len(&writer.options) as u64;
            writer.check_room(len)?;
            let mut counting = Counting {
                inner: &mut writer.inner,
                count: 0,
            };
            let result = value.encode_to_writer(&writer.options, &mut counting);
            let written = counting.count;
            writer.position += written;
            if let Err(error) = result {
                // An encoding failure writes nothing; anything else cut the output
                if written > 0 {
                    writer.failed = Some(error.kind());
                }
                return Err(error);
            }
            debug_assert_eq!(written, len, "encoded_len and the encoding disagree");
            Ok(())
        })
    }

    fn raw_at(&mut self, level: usize, buf: &[u8]) -> io::Result<usize> {
        self.guarded(|writer| {
            if writer.levels.len() != level + 1 || writer.levels[level].step != Step::Header {
                return Err(misuse(
                    "io::Write on a body between its values, not inside the steps of one",
                ));
            }
            writer.check_room(buf.len() as u64)?;
            writer.put(buf)?;
            Ok(buf.len())
        })
    }
}

/// The contents of one value being written, from
/// [`Asn1Writer::write_body`] or [`Asn1BodyWriter::write_body`], which
/// cannot be written past.
///
/// The contents of a constructed value are values, written with the same
/// steps as on [`Asn1Writer`]: [`write_value`](Self::write_value), or
/// [`write_header`](Self::write_header), [`write_len`](Self::write_len),
/// [`write_body`](Self::write_body) and, for an indefinite length,
/// [`write_foot`](Self::write_foot). The contents of a primitive value are
/// octets, written through `std::io::Write`, which also copies octets
/// encoded beforehand into a constructed value, unchecked, between its
/// values. While a body is held, the writer it came from cannot be used.
///
/// # Examples
///
/// The revoked certificates of a CRL, encoded to a file one at a time and
/// later copied into a SEQUENCE whose length is the size of that file:
///
/// ```no_run
/// use std::fs::File;
/// use std::io::{self, BufWriter};
///
/// use tc_asn1::io::{Asn1Length, Asn1Writer};
/// use tc_asn1::EncodingOptions;
///
/// let entries = "entries.der";
/// let size = std::fs::metadata(entries)?.len() as usize;
///
/// let out = BufWriter::new(File::create("revoked.der")?);
/// let mut writer = Asn1Writer::new(out, EncodingOptions::DER);
/// writer.write_header(&[0x30])?;
/// writer.write_len(Asn1Length::Definite(size))?;
/// io::copy(&mut File::open(entries)?, &mut writer.write_body()?)?;
/// writer.flush()?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Asn1BodyWriter<'a, W> {
    writer: &'a mut Asn1Writer<W>,
    level: usize,
}

impl<W: Write> Asn1BodyWriter<'_, W> {
    /// [`Asn1Writer::write_header`] for the values of this body.
    pub fn write_header(&mut self, tag: &[u8]) -> io::Result<()> {
        self.writer.header_at(self.level, tag)
    }

    /// [`Asn1Writer::write_len`] for the values of this body.
    pub fn write_len(&mut self, length: Asn1Length) -> io::Result<()> {
        self.writer.len_at(self.level, length)
    }

    /// [`Asn1Writer::write_body`] for the values of this body.
    pub fn write_body(&mut self) -> io::Result<Asn1BodyWriter<'_, W>> {
        self.writer.body_at(self.level)?;
        Ok(Asn1BodyWriter {
            writer: &mut *self.writer,
            level: self.level + 1,
        })
    }

    /// [`Asn1Writer::write_foot`] for the values of this body.
    pub fn write_foot(&mut self) -> io::Result<()> {
        self.writer.foot_at(self.level)
    }

    /// [`Asn1Writer::write_value`] for the values of this body.
    pub fn write_value<T: Encode + ?Sized>(&mut self, value: &T) -> io::Result<()> {
        self.writer.value_at(self.level, value)
    }
}

/// The octets of the contents, never past their end: those of a primitive
/// value, or octets encoded beforehand copied into a constructed value,
/// unchecked, between its values. Octets past the length are
/// `io::ErrorKind::InvalidInput` and none of them is written. `flush`
/// flushes the writer underneath without checking that values are closed,
/// to push out what is written while a value is still open. Variable time,
/// for public values only.
impl<W: Write> Write for Asn1BodyWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.raw_at(self.level, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.guarded(|writer| writer.inner.flush())
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use std::io::{self, Read, Write};

    use super::Asn1Writer;
    use crate::io::{Asn1Length, Asn1Reader};
    use crate::{
        Asn1Boolean, Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode,
        EncodingOptions,
    };

    fn refused(result: io::Result<()>) {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn values_are_written_back_to_back_and_decode_in_turn() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_value(&Asn1Integer::from(300)).unwrap();
        writer.write_value(&Asn1OctetString::new(b"abc")).unwrap();
        writer.flush().unwrap();
        let bytes = writer.into_inner();

        let options = DecodingOptions::default();
        let (used, integer) = Asn1Integer::decode(&bytes, &options).unwrap();
        assert_eq!(integer, Asn1Integer::from(300));
        let (_, octets) = Asn1OctetString::decode(&bytes[used..], &options).unwrap();
        assert_eq!(octets.as_bytes(), b"abc");
    }

    #[test]
    fn encode_to_writer_writes_what_encode_to_vec_gives_even_behind_dyn_encode() {
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
    fn the_steps_write_what_the_encoding_of_the_whole_gives() {
        // SEQUENCE { OCTET STRING "abc", INTEGER 5 }
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(&[0x30]).unwrap();
        writer.write_len(Asn1Length::Definite(8)).unwrap();
        {
            let mut body = writer.write_body().unwrap();
            body.write_header(Asn1OctetString::TAG).unwrap();
            body.write_len(Asn1Length::Definite(3)).unwrap();
            body.write_body().unwrap().write_all(b"abc").unwrap();
            body.write_value(&Asn1Integer::from(5)).unwrap();
        }
        writer.write_value(&Asn1Boolean::from(true)).unwrap();
        writer.flush().unwrap();
        assert_eq!(
            writer.into_inner(),
            [
                0x30, 0x08, 0x04, 0x03, b'a', b'b', b'c', 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF
            ]
        );
    }

    #[test]
    fn an_indefinite_length_is_closed_by_write_foot() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
        writer.write_header(&[0x30]).unwrap();
        writer.write_len(Asn1Length::Indefinite).unwrap();
        {
            let mut body = writer.write_body().unwrap();
            body.write_header(&[0x24]).unwrap();
            body.write_len(Asn1Length::Indefinite).unwrap();
            {
                let mut segments = body.write_body().unwrap();
                segments.write_value(&Asn1OctetString::new(b"ab")).unwrap();
                segments.write_value(&Asn1OctetString::new(b"c")).unwrap();
            }
            body.write_foot().unwrap();
        }
        refused(writer.flush());
        writer.write_foot().unwrap();
        writer.flush().unwrap();
        assert_eq!(
            writer.into_inner(),
            [
                0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0x00, 0x00, 0x00,
                0x00
            ]
        );
    }

    #[test]
    fn what_the_steps_write_the_reader_reads_back_in_steps() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
        writer.write_header(&[0x30]).unwrap();
        writer.write_len(Asn1Length::Indefinite).unwrap();
        {
            let mut body = writer.write_body().unwrap();
            for serial in 1..=3 {
                body.write_value(&Asn1Integer::from(serial)).unwrap();
            }
        }
        writer.write_foot().unwrap();
        writer.flush().unwrap();
        let bytes = writer.into_inner();

        let mut reader = Asn1Reader::new(&bytes[..], DecodingOptions::default());
        assert_eq!(reader.read_header().unwrap().unwrap().as_bytes(), [0x30]);
        assert_eq!(reader.read_len().unwrap(), Asn1Length::Indefinite);
        let mut serials = Vec::new();
        let mut body = reader.read_body().unwrap();
        while let Some(serial) = body.read_value::<Asn1Integer>().unwrap() {
            serials.push(serial);
        }
        assert_eq!(serials, [1, 2, 3].map(Asn1Integer::from));
    }

    #[test]
    fn a_definite_length_closes_itself_once_its_contents_are_written() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(Asn1OctetString::TAG).unwrap();
        writer.write_len(Asn1Length::Definite(3)).unwrap();
        writer.write_body().unwrap().write_all(b"ab").unwrap();
        // Short: the next value and flush are refused, and the body goes on
        refused(writer.write_value(&Asn1Integer::from(1)));
        refused(writer.flush());
        writer.write_body().unwrap().write_all(b"c").unwrap();
        refused(writer.write_foot());
        writer.write_value(&Asn1Integer::from(1)).unwrap();
        writer.flush().unwrap();
        assert_eq!(
            writer.into_inner(),
            [0x04, 0x03, b'a', b'b', b'c', 0x02, 0x01, 0x01]
        );

        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(Asn1OctetString::TAG).unwrap();
        writer.write_len(Asn1Length::Definite(0)).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.into_inner(), [0x04, 0x00]);
    }

    #[test]
    fn nothing_is_written_past_a_length() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(&[0x30]).unwrap();
        writer.write_len(Asn1Length::Definite(3)).unwrap();
        {
            let mut body = writer.write_body().unwrap();
            refused(body.write_value(&Asn1Integer::from(300)));
            body.write_header(&[0x04]).unwrap();
            refused(body.write_len(Asn1Length::Definite(2)));
            body.write_len(Asn1Length::Definite(1)).unwrap();
            let mut octets = body.write_body().unwrap();
            assert_eq!(
                octets.write(b"xy").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            octets.write_all(b"x").unwrap();
        }
        writer.flush().unwrap();
        assert_eq!(writer.into_inner(), [0x30, 0x03, 0x04, 0x01, b'x']);
    }

    #[test]
    fn calls_out_of_order_are_refused_without_writing() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
        refused(writer.write_len(Asn1Length::Definite(0)));
        refused(writer.write_body().map(drop));
        refused(writer.write_foot());
        writer.write_header(&[0x30]).unwrap();
        refused(writer.write_header(&[0x30]));
        refused(writer.write_value(&Asn1Integer::from(1)));
        refused(writer.write_body().map(drop));
        writer.write_len(Asn1Length::Indefinite).unwrap();
        refused(writer.write_len(Asn1Length::Indefinite));
        // An indefinite length needs write_foot before the next value
        refused(writer.write_header(&[0x02]));
        writer.write_foot().unwrap();
        refused(writer.write_foot());
        writer.flush().unwrap();
        assert_eq!(writer.into_inner(), [0x30, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn identifier_octets_that_are_not_one_tag_are_refused() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
        for tag in [&[][..], &[0x00], &[0x1F], &[0x1F, 0x05], &[0x04, 0x04]] {
            refused(writer.write_header(tag));
        }
        writer.write_header(&[0x9F, 0x1F]).unwrap();
        writer.write_len(Asn1Length::Definite(0)).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.into_inner(), [0x9F, 0x1F, 0x00]);
    }

    #[test]
    fn an_indefinite_length_is_refused_on_a_primitive_value_and_under_der() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::BER);
        writer.write_header(&[0x04]).unwrap();
        refused(writer.write_len(Asn1Length::Indefinite));

        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(&[0x30]).unwrap();
        refused(writer.write_len(Asn1Length::Indefinite));
        assert_eq!(writer.into_inner(), [0x30]);
    }

    #[test]
    fn primitive_contents_are_not_written_as_values() {
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(&[0x04]).unwrap();
        writer.write_len(Asn1Length::Definite(3)).unwrap();
        let mut body = writer.write_body().unwrap();
        refused(body.write_value(&Asn1Integer::from(1)));
        refused(body.write_header(&[0x02]));
    }

    #[test]
    fn octets_encoded_beforehand_are_copied_into_a_constructed_body() {
        let entries: Vec<u8> = [1, 2, 3]
            .iter()
            .flat_map(|serial| {
                Asn1Integer::from(*serial)
                    .encode_to_vec(&EncodingOptions::DER)
                    .unwrap()
            })
            .collect();
        let mut writer = Asn1Writer::new(Vec::new(), EncodingOptions::DER);
        writer.write_header(&[0x30]).unwrap();
        writer
            .write_len(Asn1Length::Definite(entries.len()))
            .unwrap();
        io::copy(&mut &entries[..], &mut writer.write_body().unwrap()).unwrap();
        writer.flush().unwrap();
        let bytes = writer.into_inner();

        let mut reader = Asn1Reader::new(&bytes[..], DecodingOptions::default());
        let sequence = reader.read_object().unwrap().unwrap();
        let mut again = Vec::new();
        sequence
            .encode_to_writer(&EncodingOptions::DER, &mut again)
            .unwrap();
        assert_eq!(again, bytes);
        let mut rest = Vec::new();
        reader.into_inner().read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn a_failure_of_the_writer_underneath_fails_the_writer_for_good() {
        let mut buffer = [0u8; 2];
        let mut writer = Asn1Writer::new(&mut buffer[..], EncodingOptions::DER);
        let error = writer.write_value(&Asn1Integer::from(300)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(
            writer
                .write_value(&Asn1Integer::from(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
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
        let error = writer.write_value(&Failing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.into_inner().unwrap().downcast_ref::<Asn1Error>(),
            Some(&Asn1Error::MalformedValue)
        );
        // Nothing was written, so the writer goes on
        writer.write_value(&Asn1Integer::from(1)).unwrap();
        assert_eq!(writer.into_inner(), [0x02, 0x01, 0x01]);
    }
}
