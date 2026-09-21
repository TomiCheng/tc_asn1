//! The state a decoding carries from the outermost TLV down to every field.

use crate::{Asn1Error, DecodingOptions};

/// What a decoding in progress knows: the [`DecodingOptions`] with the
/// limits, how deep in constructed values it currently is and whether the
/// DER rules are being enforced.
///
/// One context is created per standalone [`Decode`](crate::Decode) call
/// and threaded through every [`DecodeInner`](crate::DecodeInner) below
/// it; a caller decoding piece by piece creates its own. Both the depth and
/// the DER flag are scoped: [`Asn1Ref::children`](crate::Asn1Ref::children)
/// raises the depth for as long as the children are being read, and
/// [`enter_der`](Self::enter_der) raises the DER flag for as long as the
/// returned guard lives. Either is restored when its guard drops, on the
/// error path as well, so a `?` inside a nested decode cannot leave the
/// context in the inner state.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Boolean, Asn1Error, DecodeInner, DecodingContext, DecodingOptions};
///
/// // A BER context accepts `01 01 01` as TRUE; DER writes TRUE only as FF.
/// let mut context = DecodingContext::new(DecodingOptions::default());
/// assert!(Asn1Boolean::decode_inner(&[0x01, 0x01, 0x01], &mut context).is_ok());
///
/// // A value that must be DER, such as an extension's contents, is read
/// // under a guard; the context is BER again once the guard is gone.
/// {
///     let mut der = context.enter_der();
///     assert!(matches!(
///         Asn1Boolean::decode_inner(&[0x01, 0x01, 0x01], der.context()),
///         Err(Asn1Error::NotDer)
///     ));
/// }
/// assert!(!context.is_der());
/// ```
#[derive(Debug)]
pub struct DecodingContext {
    options: DecodingOptions,
    depth: u32,
    is_der: bool,
}

impl DecodingContext {
    /// A context that accepts any BER, at depth 0.
    pub const fn new(options: DecodingOptions) -> Self {
        Self {
            options,
            depth: 0,
            is_der: false,
        }
    }

    /// A context that applies the DER rules from the start.
    pub const fn new_der(options: DecodingOptions) -> Self {
        Self {
            options,
            depth: 0,
            is_der: true,
        }
    }

    /// The limits every decode below checks against.
    pub const fn options(&self) -> &DecodingOptions {
        &self.options
    }

    /// The number of constructed values currently open above the point
    /// being decoded, 0 at the outermost TLV. Bounded by
    /// [`DecodingOptions::depth`].
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Whether a non-canonical encoding is [`Asn1Error::NotDer`] here
    /// rather than accepted.
    pub const fn is_der(&self) -> bool {
        self.is_der
    }

    /// Opens one more level of nesting: [`Asn1Error::DepthExceeded`] when
    /// the limit is already reached, else a guard through which the
    /// children are decoded. Called by [`Asn1Ref::children`](crate::Asn1Ref::children)
    /// and by the indefinite-length scan in [`Asn1Ref::parse`](crate::Asn1Ref::parse).
    pub(crate) fn enter(&mut self) -> Result<DepthScope<'_>, Asn1Error> {
        if self.depth >= self.options.depth() {
            return Err(Asn1Error::DepthExceeded);
        }
        let parent_depth = self.depth;
        self.depth += 1;
        Ok(DepthScope {
            context: self,
            parent_depth,
        })
    }

    /// Enforces DER until the returned guard drops, then restores whatever
    /// the flag was: for a value the surrounding structure requires to be
    /// DER, such as the contents of an X.509 extension. Nesting guards is
    /// fine; there is no way to turn DER off inside a DER context.
    pub fn enter_der(&mut self) -> DerScope<'_> {
        let old_value = self.is_der;
        self.is_der = true;
        DerScope {
            context: self,
            old_value,
        }
    }
}

/// The guard from [`DecodingContext::enter`]: the depth is one higher while
/// it lives and back to the parents when it drops.
pub(crate) struct DepthScope<'c> {
    context: &'c mut DecodingContext,
    parent_depth: u32,
}

impl<'c> DepthScope<'c> {
    pub(crate) fn context(&mut self) -> &mut DecodingContext {
        self.context
    }

    pub(crate) fn options(&self) -> &DecodingOptions {
        self.context.options()
    }
}

impl Drop for DepthScope<'_> {
    fn drop(&mut self) {
        self.context.depth = self.parent_depth;
    }
}

/// The guard from [`DecodingContext::enter_der`]: the context is DER while
/// it lives and back to its previous setting when it drops.
pub struct DerScope<'c> {
    context: &'c mut DecodingContext,
    old_value: bool,
}

impl<'c> DerScope<'c> {
    /// The context to pass to the decodes that must be DER.
    pub fn context(&mut self) -> &mut DecodingContext {
        self.context
    }

    pub fn options(&self) -> &DecodingOptions {
        self.context.options()
    }
}

impl<'c> Drop for DerScope<'c> {
    fn drop(&mut self) {
        self.context.is_der = self.old_value;
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::DecodingContext;
    use crate::{Asn1Boolean, Asn1Error, Asn1Object, Decode, DecodeInner, DecodingOptions};

    fn options() -> DecodingOptions {
        DecodingOptions::default()
    }

    /// `levels` SEQUENCEs nested inside one another, the innermost empty.
    fn nested(levels: usize) -> Vec<u8> {
        let mut out = Vec::from([0x30, 0x00]);
        for _ in 1..levels {
            let mut outer = Vec::from([0x30, out.len() as u8]);
            outer.extend_from_slice(&out);
            out = outer;
        }
        out
    }

    #[test]
    fn a_fresh_context_starts_at_depth_zero_with_the_chosen_rules() {
        let ber = DecodingContext::new(options());
        assert_eq!((ber.depth(), ber.is_der()), (0, false));
        let der = DecodingContext::new_der(options());
        assert_eq!((der.depth(), der.is_der()), (0, true));
        assert_eq!(ber.options(), &options());
    }

    #[test]
    fn enter_raises_the_depth_until_the_guard_drops() {
        let mut context = DecodingContext::new(DecodingOptions::new(2, 1024, 16));
        {
            let mut outer = context.enter().unwrap();
            assert_eq!(outer.context().depth(), 1);
            {
                let mut inner = outer.context().enter().unwrap();
                assert_eq!(inner.context().depth(), 2);
                assert!(matches!(
                    inner.context().enter(),
                    Err(Asn1Error::DepthExceeded)
                ));
                // the failed enter changed nothing
                assert_eq!(inner.context().depth(), 2);
            }
            assert_eq!(outer.context().depth(), 1);
        }
        assert_eq!(context.depth(), 0);
    }

    #[test]
    fn the_depth_is_restored_on_the_error_path_too() {
        fn fails_two_levels_down(context: &mut DecodingContext) -> Result<(), Asn1Error> {
            let mut outer = context.enter()?;
            let _inner = outer.context().enter()?;
            Err(Asn1Error::MalformedValue)
        }
        let mut context = DecodingContext::new(options());
        assert!(fails_two_levels_down(&mut context).is_err());
        assert_eq!(context.depth(), 0);
    }

    #[test]
    fn enter_der_enforces_der_until_the_guard_drops_and_never_relaxes_it() {
        let mut context = DecodingContext::new(options());
        {
            let mut der = context.enter_der();
            assert!(der.context().is_der());
            {
                let nested = der.context().enter_der();
                assert!(nested.options().depth() > 0);
            }
            // a nested guard restores DER, not BER
            assert!(der.context().is_der());
        }
        assert!(!context.is_der());

        let mut already_der = DecodingContext::new_der(options());
        drop(already_der.enter_der());
        assert!(already_der.is_der());
    }

    #[test]
    fn the_der_flag_changes_what_a_decode_accepts() {
        let non_canonical_true = [0x01, 0x01, 0x01];
        let mut context = DecodingContext::new(options());
        assert!(Asn1Boolean::decode_inner(&non_canonical_true, &mut context).is_ok());
        {
            let mut der = context.enter_der();
            assert!(matches!(
                Asn1Boolean::decode_inner(&non_canonical_true, der.context()),
                Err(Asn1Error::NotDer)
            ));
        }
        assert!(Asn1Boolean::decode_inner(&non_canonical_true, &mut context).is_ok());
    }

    #[test]
    fn nesting_deeper_than_the_limit_is_depth_exceeded() {
        let three = nested(3);
        assert!(Asn1Object::decode(&three, &DecodingOptions::new(3, 1024, 16)).is_ok());
        assert!(matches!(
            Asn1Object::decode(&three, &DecodingOptions::new(2, 1024, 16)),
            Err(Asn1Error::DepthExceeded)
        ));
        // the failed decode leaves a reusable context behind
        let mut context = DecodingContext::new(DecodingOptions::new(2, 1024, 16));
        assert!(Asn1Object::decode_inner(&three, &mut context).is_err());
        assert_eq!(context.depth(), 0);
        assert!(Asn1Object::decode_inner(&nested(2), &mut context).is_ok());
    }
}
