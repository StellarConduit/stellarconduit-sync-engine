pub mod compression_oracle;
pub mod db;
pub mod envelope_compression;
#[cfg(test)]
mod fault_vfs;

pub use db::{
    ConflictRecord, DbSummary, HistoryEntry, ImportReport, QueuedEnvelopeRecord, SyncEngineDb,
    DB_SNAPSHOT_SCHEMA_VERSION,
};
pub use envelope_compression::{
    compress_at_rest, compressed_segment_sizes, decompress_at_rest, oracle_observable,
    secret_context_compressed_size, CompressionScheme, SegmentSizes, PAD_GRANULARITY,
};

pub use compression_oracle::{
    run_byte_at_a_time_oracle, OracleConfig, OracleReport, PositionOutcome, SecretField,
};
