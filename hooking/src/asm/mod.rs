pub mod error;
mod x86;

pub use error::{AssemblyError, Result};
pub use x86::*;
