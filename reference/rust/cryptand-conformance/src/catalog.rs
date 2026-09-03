//! `05-catalog.md` — the constants a second implementation has to agree on
//! before it can read anyone else's catalog.

pub mod tree_id {
    pub const CATALOG: u32 = 0;
    pub const FREE_SPACE: u32 = 1;
    pub const ATTRIBUTES: u32 = 2;
    pub const TREE_INDEX: u32 = 3;
    pub const REPAIR_LOG: u32 = 4;
    pub const USERS: u32 = 5;
    pub const MANIFEST: u32 = 6;
    pub const VLOG_STATS: u32 = 7;
    pub const CHECKPOINTS: u32 = 8;
    pub const CHANGE_FEED: u32 = 9;
    pub const FIRST_USER_TREE: u32 = 16;
}

/// §10 — lower snake case, no hyphens. These five are the only portable names.
pub const PORTABLE_INDEX_TYPES: [&str; 5] =
    ["full_text", "non_unique", "spatial", "unique", "vector"];

/// §3 — the kinds whose data lives in manifest segments rather than in a
/// copy-on-write tree rooted at `root`.
pub const LEVELLED_KINDS: [&str; 8] = [
    "data",
    "index",
    "kv",
    "name_dict",
    "postings",
    "term_dict",
    "term_index",
    "vector_graph",
];
