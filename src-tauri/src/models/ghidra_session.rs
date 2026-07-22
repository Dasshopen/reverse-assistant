use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisSession {
    pub project_dir: PathBuf,
    pub project_name: String,
    pub program_path_in_project: String,
}
