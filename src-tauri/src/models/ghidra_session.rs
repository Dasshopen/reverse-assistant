use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// Persisted as part of a saved project (see services::project_storage) so a
// "live" project can restore on-demand decompilation after being reopened,
// not just the static export snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub project_dir: PathBuf,
    pub project_name: String,
    pub program_path_in_project: String,
}
