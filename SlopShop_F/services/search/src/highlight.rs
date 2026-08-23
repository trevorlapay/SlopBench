//! Snippet extraction for search results.
//!
//! A result carries a short window of the document around the first match, with
//! the matched span marked.

/// Longest document this module will scan.
pub const MAX_SCANNED_BYTES: usize = 64 * 1024;

/// Bytes of context kept either side of the match.
pub const DEFAULT_WINDOW_BYTES: usize = 96;

/// A snippet and the position of the match inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    pub text: String,
    /// Offset of the match within `text`, in bytes.
    pub match_offset: u32,
    /// Length of the match, in bytes.
    pub match_length: u32,
}

/// Walks `index` down until it sits on a character boundary of `text`.
fn floor_boundary(text: &str, mut index: usize) -> usize {
    if index > text.len() {
        index = text.len();
    }
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Walks `index` up until it sits on a character boundary of `text`.
fn ceil_boundary(text: &str, mut index: usize) -> usize {
    if index > text.len() {
        return text.len();
    }
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Extracts a snippet of `text` around the first occurrence of `term`.
///
/// Both arguments have already been folded by the query parser, so the search
/// is a plain byte comparison. Returns `None` when the term does not occur.
#[must_use]
pub fn snippet(text: &str, term: &str, window: usize) -> Option<Snippet> {
    if term.is_empty() {
        return None;
    }

    let limit = floor_boundary(text, MAX_SCANNED_BYTES.min(text.len()));
    let scanned = &text[..limit];

    let found = scanned.find(term)?;
    let match_end = found + term.len();

    let window = window.min(MAX_SCANNED_BYTES);

    let raw_start = found.saturating_sub(window);
    let raw_end = match_end.saturating_add(window).min(scanned.len());

    let start = floor_boundary(scanned, raw_start);
    let end = ceil_boundary(scanned, raw_end);

    let extracted = &scanned[start..end];

    let match_offset = (found - start) as u32;
    let match_length = term.len() as u32;

    Some(Snippet {
        text: extracted.to_owned(),
        match_offset,
        match_length,
    })
}

/// Convenience wrapper using the default window.
#[must_use]
pub fn default_snippet(text: &str, term: &str) -> Option<Snippet> {
    snippet(text, term, DEFAULT_WINDOW_BYTES)
}

/// Builds a snippet for the first of `terms` that occurs in `text`.
#[must_use]
pub fn first_match(text: &str, terms: &[String]) -> Option<Snippet> {
    terms.iter().find_map(|term| default_snippet(text, term))
}
