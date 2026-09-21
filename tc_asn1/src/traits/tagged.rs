/// The tag a type reads and writes on its own, as the identifier octets.
///
/// A caller that must recognize the type before decoding it, such as
/// [`Children::get_opt`](crate::Children::get_opt) on an OPTIONAL field,
/// compares this with the next tag on the wire. [`Encode`](crate::Encode)
/// implementations pass it to [`EncodeTagged`](crate::EncodeTagged).
pub trait Tagged {
    /// The identifier octets: the universal tag for the built-in types, the
    /// outer SEQUENCE tag for a structure defined on top of them.
    const TAG: &'static [u8];
}
