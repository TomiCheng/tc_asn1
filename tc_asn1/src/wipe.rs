//! Shared erasure steps for the `Zeroize` implementations.

use alloc::string::String;
use alloc::vec::Vec;

use tc_zeroize::Zeroize;

/// Wipes the whole allocation of `octets`, then leaves `rest` in it: the
/// shortest valid contents of a type that cannot be empty.
pub(crate) fn wipe_leaving(octets: &mut Vec<u8>, rest: &[u8]) {
    octets.zeroize();
    octets.extend_from_slice(rest);
}

/// Wipes the whole allocation of `text` and leaves it empty.
pub(crate) fn wipe_string(text: &mut String) {
    // `into_bytes` hands over the same allocation, so the wipe reaches the
    // original buffer rather than a copy.
    core::mem::take(text).into_bytes().zeroize();
}
