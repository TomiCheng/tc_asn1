# Reading and writing over `std::io`

The `io` module, behind the `std` feature, reads and writes encoded values
over `std::io::Read` and `std::io::Write`. The rest of the crate works on
`&[u8]`, which needs the whole encoding in memory; the `io` module is for
what that cannot do:

- reading exactly one value from a stream, a socket or a file of values one
  after another, and leaving what follows it unread;
- data larger than memory, such as a CRL of millions of entries;
- input that is not trusted, whose lengths are checked before anything is
  held for them;
- output produced as it goes.

```toml
[dependencies]
tc_asn1 = { version = "0.1", features = ["std"] }
```

## Reading

### One value at a time

`read_value` reads the next value whole and decodes it; `None` means the
input ended between values. Nothing past the value is read, so the next call,
or other code, starts right after it.

```rust
use std::fs::File;
use std::io::BufReader;

use tc_asn1::io::Asn1Reader;
use tc_asn1::{Asn1Integer, DecodingOptions};

let file = BufReader::new(File::open("serials.der")?);
let mut reader = Asn1Reader::new(file, DecodingOptions::default());
while let Some(serial) = reader.read_value::<Asn1Integer>()? {
    println!("{serial}");
}
```

`read_value_der` reads the same way but refuses anything that is not DER, as
a certificate requires. `read_object` reads a value whose type is not known,
as an `Asn1Object` tree.

The reader reads a header an octet at a time: wrap a file or a socket in a
`BufReader`, as above.

### Limits for input that is not trusted

`DecodingOptions` bounds every read: nesting depth, the length of a value,
and the number of children of a value decoded whole. Every definite length is
checked when it is read, before anything is held for it, and the contents of
an indefinite length are held to the same limit in total. Set the limits to
what the input should be:

```rust
// Messages of at most 64 KiB, nested 16 deep
let options = DecodingOptions::new(16, 64 * 1024, 256);
let mut reader = Asn1Reader::new(BufReader::new(stream), options);
```

A larger value is refused with `ContentLengthExceeded` before its contents
are read. To stream a value larger than the default, raise the limit.

### In steps

A value is made of a header, a length and a body. `read_header`, `read_len`
and `read_body` read them one at a time; `read_body` gives an `Asn1Body`
that cannot read past the value, with the same methods for the values
inside it and `std::io::Read` for its octets.

```rust
let tag = reader.read_header()?.expect("a value");
let length = reader.read_len()?;
let mut body = reader.read_body()?;
std::io::copy(&mut body, &mut out)?;
```

`read` gives whichever part comes next, for a loop that matches on them:

```rust
use tc_asn1::io::Asn1Item;

while let Some(item) = reader.read()? {
    match item {
        Asn1Item::Header(tag) => println!("tag {:02X?}", tag.as_bytes()),
        Asn1Item::Len(length) => println!("len {length:?}"),
        Asn1Item::Body(mut body) => { /* values or octets */ }
    }
}
```

A value need not be read to its end: the next read of the same level skips
what is left of it.

### Helpers

`read_sequence`, `read_set`, `read_constructed`, `read_octet` and
`read_bit_string` read the header and length of a value that must carry the
expected tag and give its body. Another tag is `UnexpectedTag`, and the
reader goes on past that value.

A SEQUENCE OF too many entries to hold, taken one at a time:

```rust
let mut entries = reader.read_sequence()?.expect("a SEQUENCE");
while let Some(serial) = entries.read_value::<Asn1Integer>()? {
    println!("{serial}");
}
```

A large OCTET STRING copied to a file without holding it:

```rust
let mut contents = reader.read_octet()?.expect("an OCTET STRING");
std::io::copy(&mut contents, &mut File::create("content.bin")?)?;
```

### Encodings inside OCTET STRING and BIT STRING

An OCTET STRING or a BIT STRING often carries an encoding of its own, such
as the value of an X.509 extension or the public key of a certificate. Its
body reads as values too. `read_bit_string` reads the count of unused bits
first:

```rust
let (unused, mut key) = spki.read_bit_string()?.expect("a BIT STRING");
let mut rsa = key.read_sequence()?.expect("an RSAPublicKey");
let modulus = rsa.read_value::<Asn1Integer>()?;
let exponent = rsa.read_value::<Asn1Integer>()?;
```

### Data of unknown structure

Walking every value, as `openssl asn1parse` does:

```rust
use std::io::Read;

use tc_asn1::io::Asn1Body;

fn dump<R: Read>(body: &mut Asn1Body<'_, R>, indent: usize) -> std::io::Result<()> {
    while let Some(tag) = body.read_header()? {
        let length = body.read_len()?;
        println!("{:indent$}{:02X?} {length:?}", "", tag.as_bytes());
        if tag.is_constructed() {
            dump(&mut body.read_body()?, indent + 2)?;
        }
    }
    Ok(())
}
```

## Writing

### One value at a time

`write_value` encodes a value under the rules the writer was created with and
writes it whole. `flush` comes last: it checks that every value is closed.

```rust
use tc_asn1::io::Asn1Writer;
use tc_asn1::{Asn1Integer, EncodingOptions};

let mut writer = Asn1Writer::new(BufWriter::new(file), EncodingOptions::DER);
writer.write_value(&Asn1Integer::from(5))?;
writer.flush()?;
```

### In steps

`write_header`, `write_len` and `write_body` write a value part by part, and
the helpers `write_sequence`, `write_set`, `write_constructed`,
`write_octet` and `write_bit_string` take the three steps at once. A body
writes values with the same methods and octets through `std::io::Write`.

A definite length closes its value once its contents are written, and
nothing is written past it:

```rust
let mut sequence = writer.write_sequence(Asn1Length::Definite(6))?;
sequence.write_value(&Asn1Integer::from(1))?;
sequence.write_value(&Asn1Integer::from(2))?;
```

An indefinite length, BER or CER only, is closed with `write_foot`, so the
size need not be known in advance:

```rust
{
    let mut entries = writer.write_sequence(Asn1Length::Indefinite)?;
    for entry in source {
        entries.write_value(&entry)?;
    }
}
writer.write_foot()?;
```

DER needs every length in advance. When the contents were encoded
beforehand, say to a file, the length is the size of that file, and the
octets are copied in as they are:

```rust
let size = std::fs::metadata("entries.der")?.len() as usize;
let mut sequence = writer.write_sequence(Asn1Length::Definite(size))?;
std::io::copy(&mut File::open("entries.der")?, &mut sequence)?;
```

A BIT STRING carrying an encoding:

```rust
let mut key = writer.write_bit_string(0, 8)?;
let mut rsa = key.write_sequence(Asn1Length::Definite(6))?;
rsa.write_value(&Asn1Integer::from(5))?;
rsa.write_value(&Asn1Integer::from(3))?;
```

## Errors

Every level of a reader or a writer keeps a state machine.

- A call out of order, such as `read_len` before `read_header` or contents
  past a length, is `InvalidInput`, and nothing is read or written for it.
- Input that is malformed or over a limit is `InvalidData` carrying the
  `Asn1Error`; input that ends inside a value is `UnexpectedEof`.
- After an error in the input, or a failure of the writer underneath, the
  position is lost inside a value, so the reader or writer fails for good and
  every call gives that error again.
- A value read whole that does not decode as the type asked for, or a value
  that fails to encode, does not fail the reader or writer: the value has
  been read, or nothing was written, and the next call goes on.
