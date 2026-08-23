//! Okapi BM25 scoring.
//!
//! Corpus statistics are computed once per query and passed to each term.

/// Term-frequency saturation parameter.
pub const K1: f64 = 1.2;

/// Length-normalisation parameter.
pub const B: f64 = 0.75;

/// Statistics the scorer needs about the corpus as a whole.
#[derive(Debug, Clone, Copy)]
pub struct CorpusStats {
    pub document_count: u32,
    pub mean_document_length: f64,
}

impl CorpusStats {
    /// Builds corpus statistics from a document count and a token total.
    #[must_use]
    pub fn new(document_count: u32, total_tokens: u64) -> Self {
        let mean = if document_count == 0 {
            1.0
        } else {
            let total = u32_to_f64_saturating(u32::try_from(total_tokens).unwrap_or(u32::MAX));
            let count = f64::from(document_count);
            (total / count).max(1.0)
        };

        Self {
            document_count,
            mean_document_length: mean,
        }
    }
}

fn u32_to_f64_saturating(value: u32) -> f64 {
    f64::from(value)
}

/// Inverse document frequency, in the form that stays positive for every
/// `documents_containing` in `0..=document_count`.
#[must_use]
pub fn inverse_document_frequency(document_count: u32, documents_containing: u32) -> f64 {
    let n = f64::from(document_count);
    let df = f64::from(documents_containing.min(document_count));

    (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
}

/// Contribution of a single term to one document score.
#[must_use]
pub fn term_score(
    stats: CorpusStats,
    documents_containing: u32,
    term_frequency: u32,
    document_length: u32,
) -> f64 {
    if term_frequency == 0 {
        return 0.0;
    }

    let idf = inverse_document_frequency(stats.document_count, documents_containing);
    let tf = f64::from(term_frequency);
    let length_ratio = f64::from(document_length.max(1)) / stats.mean_document_length;

    let denominator = tf + K1 * (1.0 - B + B * length_ratio);
    if denominator <= f64::EPSILON {
        return 0.0;
    }

    idf * (tf * (K1 + 1.0) / denominator)
}

/// Orders results by descending score, breaking ties on the document id so the
/// ordering is total and stable across runs.
pub fn sort_by_score(results: &mut [(u32, f64)]) {
    results.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.0.cmp(&right.0))
    });
}
