pub mod config;
pub mod parser;
pub mod analyzer;
pub mod blockchain;
pub mod cli;
pub mod utils;
pub mod types;

pub use config::*;
pub use parser::*;
pub use analyzer::*;
pub use blockchain::*;
pub use cli::*;
pub use utils::*;
pub use types::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
