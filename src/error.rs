//! Contains error types and other error handling tools.

use std::fmt;
use crate::hex::HexToArrayError;
pub use crate::parse::ParseIntError;

/// Impls std::error::Error for the specified type with appropriate attributes, possibly returning
/// source.
macro_rules! impl_std_error {
    // No source available
    ($type:ty) => {
        impl std::error::Error for $type {}
    };
    // Struct with $field as source
    ($type:ty, $field:ident) => {
        impl std::error::Error for $type {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.$field)
            }
        }
    };
}
pub(crate) use impl_std_error;

/// Formats error. If `std` feature is OFF appends error source (delimited by `: `). We do this
/// because `e.source()` is only available in std builds, without this macro the error source is
/// lost for no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            let _ = &$source;   // Prevents clippy warnings.
            write!($writer, $string $(, $args)*)
        }
    }
}
pub(crate) use write_err;

/// Hex decoding error for Elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexDecodeError {
    /// The byte data decoded from the hex string cannot be converted into the final data structure
    InvalidData,
    /// Error converting the hex string to bytes
    HexError(HexToArrayError)
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HexDecodeError::InvalidData => write!(f, "invalid data"),
            HexDecodeError::HexError(e) => write!(f, "{}", e),
        }
    }
}

impl From<HexToArrayError> for HexDecodeError {
    fn from(e: HexToArrayError) -> Self {
        HexDecodeError::HexError(e)
    }
}