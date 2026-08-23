//! Parsing and normalisation of caller-supplied search queries.
//!
//! The raw string has a maximum byte length, the token count is capped, and
//! each token is capped in turn.

use std::fmt;

use unicode_normalization::UnicodeNormalization;

/// Longest raw query accepted, in bytes.
pub const MAX_QUERY_BYTES: usize = 256;

/// Longest single token retained, in characters.
pub const MAX_TOKEN_CHARS: usize = 32;

/// Most tokens retained from one query.
pub const MAX_TOKENS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    TooLong { bytes: usize },
    Empty,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { bytes } => {
                write!(f, "query is {bytes} bytes, limit is {MAX_QUERY_BYTES}")
            }
            Self::Empty => write!(f, "query contains no searchable terms"),
        }
    }
}

impl std::error::Error for QueryError {}

/// A parsed query: required terms, and terms the caller asked to exclude.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Query {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

/// Folds one token to its comparison form: NFKC, lowercase, alphanumeric only,
/// truncated to `MAX_TOKEN_CHARS`.
fn normalise_token(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());

    for ch in raw.nfkc().flat_map(char::to_lowercase) {
        if out.chars().count() >= MAX_TOKEN_CHARS {
            break;
        }
        if ch.is_alphanumeric() {
            out.push(ch);
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Parses a raw query string.
///
/// A leading `-` marks a token for exclusion. Tokens beyond `MAX_TOKENS` are
/// discarded rather than treated as an error, so a long query degrades instead
/// of failing.
///
/// # Errors
///
/// Returns [`QueryError::TooLong`] when the raw input exceeds
/// [`MAX_QUERY_BYTES`], and [`QueryError::Empty`] when nothing survives
/// normalisation.
pub fn parse(raw: &str) -> Result<Query, QueryError> {
    if raw.len() > MAX_QUERY_BYTES {
        return Err(QueryError::TooLong { bytes: raw.len() });
    }

    let mut query = Query::default();

    for field in raw.split_whitespace() {
        if query.include.len().saturating_add(query.exclude.len()) >= MAX_TOKENS {
            break;
        }

        let (negated, body) = match field.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, field),
        };

        if let Some(token) = normalise_token(body) {
            if negated {
                query.exclude.push(token);
            } else {
                query.include.push(token);
            }
        }
    }

    if query.include.is_empty() {
        return Err(QueryError::Empty);
    }

    Ok(query)
}

/// Folds a document field into index tokens using the same rules as the query
/// parser, so a term matches at search time exactly when it matched at index
/// time.
#[must_use]
pub fn tokenise_document(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter_map(normalise_token)
        .collect()
}
