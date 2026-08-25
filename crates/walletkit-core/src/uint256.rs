//! Foreign-friendly 256-bit unsigned integer.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;

/// A 256-bit unsigned integer represented as a hexadecimal string across FFI.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Uint256(pub ruint::Uint<256, 4>);

impl Uint256 {
    /// Converts the integer to a `0x`-prefixed, zero-padded hexadecimal string.
    #[must_use]
    pub fn to_padded_hex_string(&self) -> String {
        format!("{:#066x}", self.0)
    }
}

impl Deref for Uint256 {
    type Target = ruint::Uint<256, 4>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Uint256 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<ruint::Uint<256, 4>> for Uint256 {
    fn from(value: ruint::Uint<256, 4>) -> Self {
        Self(value)
    }
}

impl From<Uint256> for ruint::Uint<256, 4> {
    fn from(value: Uint256) -> Self {
        value.0
    }
}

impl fmt::Display for Uint256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Uint256 {
    type Err = ruint::ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ruint::Uint::from_str(value).map(Self)
    }
}

impl TryFrom<String> for Uint256 {
    type Error = ruint::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ruint::Uint::from_str_radix(&value, 16).map(Self)
    }
}
