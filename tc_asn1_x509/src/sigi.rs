//! Common PKI (SigI) structures.

mod name_or_pseudonym;
mod personal_data;
mod sigi_id;

pub use name_or_pseudonym::{NameOrPseudonym, SurAndGivenName};
pub use personal_data::PersonalData;
pub use sigi_id::SigiId;
