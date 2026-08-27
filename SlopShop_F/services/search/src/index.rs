//! An in-memory inverted index over product documents.

use std::collections::{BTreeMap, HashMap};

use crate::query::{tokenise_document, Query};
use crate::ranking::{sort_by_score, term_score, CorpusStats};

/// Most results returned from a single search.
pub const MAX_RESULTS: usize = 100;

/// Most documents the index will hold. Ingestion refuses further documents
/// rather than growing without bound.
pub const MAX_DOCUMENTS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub id: u32,
    pub product_id: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestError {
    IndexFull,
    DuplicateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub document_id: u32,
    pub score_millis: u32,
}

/// Posting list entry: how often a term occurs in one document.
type Postings = BTreeMap<u32, u32>;

/// Longest document body retained for snippet extraction.
pub const MAX_RETAINED_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub struct Index {
    postings: HashMap<String, Postings>,
    document_lengths: HashMap<u32, u32>,
    product_ids: HashMap<u32, String>,
    bodies: HashMap<u32, String>,
    total_tokens: u64,
}

impl Index {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn product_id(&self, document_id: u32) -> Option<&str> {
        self.product_ids.get(&document_id).map(String::as_str)
    }

    /// The retained body text for a document, used to build result snippets.
    #[must_use]
    pub fn body(&self, document_id: u32) -> Option<&str> {
        self.bodies.get(&document_id).map(String::as_str)
    }

    /// Adds a document.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::IndexFull`] once [`MAX_DOCUMENTS`] is reached and
    /// [`IngestError::DuplicateId`] when the id is already present.
    pub fn ingest(&mut self, document: &Document) -> Result<(), IngestError> {
        if self.document_lengths.len() >= MAX_DOCUMENTS {
            return Err(IngestError::IndexFull);
        }
        if self.document_lengths.contains_key(&document.id) {
            return Err(IngestError::DuplicateId);
        }

        let mut tokens = tokenise_document(&document.title);
        tokens.extend(tokenise_document(&document.body));

        let length = u32::try_from(tokens.len()).unwrap_or(u32::MAX);

        for token in tokens {
            let entry = self.postings.entry(token).or_default();
            let frequency = entry.entry(document.id).or_insert(0);
            *frequency = frequency.saturating_add(1);
        }

        self.document_lengths.insert(document.id, length);
        self.product_ids
            .insert(document.id, document.product_id.clone());

        // Only a bounded prefix of the body is retained.
        let mut cut = MAX_RETAINED_BODY_BYTES.min(document.body.len());
        while cut > 0 && !document.body.is_char_boundary(cut) {
            cut -= 1;
        }
        self.bodies.insert(document.id, document.body[..cut].to_owned());

        self.total_tokens = self.total_tokens.saturating_add(u64::from(length));

        Ok(())
    }

    fn stats(&self) -> CorpusStats {
        CorpusStats::new(
            u32::try_from(self.document_lengths.len()).unwrap_or(u32::MAX),
            self.total_tokens,
        )
    }

    /// Runs a parsed query and returns at most `limit` hits, capped at
    /// [`MAX_RESULTS`].
    #[must_use]
    pub fn search(&self, query: &Query, limit: usize) -> Vec<Hit> {
        if query.is_empty() {
            return Vec::new();
        }

        let stats = self.stats();

        // Exclusion is tested per candidate against the posting lists rather
        // than by materialising every excluded id, so a query with a common
        // negated term does no work proportional to the corpus.
        let excluded: Vec<&Postings> = query
            .exclude
            .iter()
            .filter_map(|term| self.postings.get(term))
            .collect();

        let mut scores: HashMap<u32, f64> = HashMap::new();

        for term in &query.include {
            let Some(postings) = self.postings.get(term) else {
                continue;
            };
            let documents_containing = u32::try_from(postings.len()).unwrap_or(u32::MAX);

            for (&document_id, &frequency) in postings {
                if excluded.iter().any(|postings| postings.contains_key(&document_id)) {
                    continue;
                }
                let length = self
                    .document_lengths
                    .get(&document_id)
                    .copied()
                    .unwrap_or(1);

                let contribution =
                    term_score(stats, documents_containing, frequency, length);
                *scores.entry(document_id).or_insert(0.0) += contribution;
            }
        }

        let mut ranked: Vec<(u32, f64)> = scores.into_iter().collect();
        let wanted = limit.min(MAX_RESULTS);

        // Partition around the cut point before sorting, so only the returned
        // window is ordered rather than the whole match set.
        if ranked.len() > wanted && wanted > 0 {
            ranked.select_nth_unstable_by(wanted - 1, |left, right| {
                right
                    .1
                    .partial_cmp(&left.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| left.0.cmp(&right.0))
            });
            ranked.truncate(wanted);
        }
        sort_by_score(&mut ranked);
        ranked.truncate(wanted);

        ranked
            .into_iter()
            .map(|(document_id, score)| Hit {
                document_id,
                // Scores cross the wire as fixed-point thousandths.
                score_millis: to_millis(score),
            })
            .collect()
    }
}

/// Converts a score to thousandths, clamping instead of wrapping.
fn to_millis(score: f64) -> u32 {
    if !score.is_finite() || score <= 0.0 {
        return 0;
    }
    let scaled = (score * 1000.0).round();
    if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        scaled as u32
    }
}
