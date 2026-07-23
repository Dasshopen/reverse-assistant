use serde::{Deserialize, Serialize};

use crate::models::ghidra_session::AnalysisSession;

// A locally saved analysis. `session` is `Some` for a "live" project (an
// automatic Ghidra analysis, whose original project files on disk allow
// on-demand decompilation to keep working after the project is reopened)
// and `None` for a "snapshot" project (a manually imported JSON file, or a
// live project whose original Ghidra project files were later found
// missing -- see services::project_storage::load_project). The small
// at-a-glance fields (program_name/format/architecture/function_count)
// are a deliberate cache of data that also lives in the project's
// export.json, kept here so listing every saved project never requires
// parsing a potentially large export file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub id: String,
    pub name: String,
    pub created_at_unix_seconds: u64,
    pub session: Option<AnalysisSession>,
    pub program_name: String,
    pub program_format: String,
    pub program_architecture: String,
    pub function_count: usize,
}
