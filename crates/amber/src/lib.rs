#![forbid(unsafe_code)]

pub mod binary;
pub mod builder;
pub mod dedupe;
pub mod diagnostic;
pub mod export;
pub mod filter;
pub mod history;
pub mod model;
pub mod search;
pub mod trim;
pub mod write;

pub use binary::FileSource;
pub use builder::{Entry, load};
pub use diagnostic::{Error, Result, SourceRange};
pub use export::{ExportOptions, ExportSummary, export};
pub use dedupe::{DedupeMode, Deduper};
pub use filter::{HistoryFilter, HostScope};
pub use history::Project;
pub use model::{HistoryEntry, HistoryInput};
pub use search::{EntryMatches, Matcher, Part, PartMatches, SearchOptions, search_entry};
pub use trim::{Decision, HostTally, TrimOptions, TrimSummary, trim};
pub use write::{WriteOptions, WriteSummary, append, create};
