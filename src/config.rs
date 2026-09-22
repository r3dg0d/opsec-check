//! XDG-aware configuration.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Extra home subdirs to sample for metadata (relative to $HOME).
    #[serde(default)]
    pub metadata_sample_dirs: Vec<String>,
    /// Max files to inspect per sample directory.
    #[serde(default = "default_metadata_max")]
    pub metadata_max_files: usize,
    /// Disable sibling tool invocation even without --dry-run.
    #[serde(default)]
    pub skip_sibling_tools: bool,
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_metadata_max() -> usize {
    24
}

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        if let Some(p) = explicit {
            let text =
                fs::read_to_string(p).with_context(|| format!("reading config {}", p.display()))?;
            let cfg: Config = serde_json::from_str(&text)
                .with_context(|| format!("parsing config {}", p.display()))?;
            return Ok((cfg, Some(p.to_path_buf())));
        }

        if let Some(dirs) = ProjectDirs::from("dev", "r3dg0d", "opsec-check") {
            let path = dirs.config_dir().join("config.json");
            if path.exists() {
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                let cfg: Config = serde_json::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()))?;
                return Ok((cfg, Some(path)));
            }
        }

        Ok((Config::default(), None))
    }

    pub fn data_dir() -> Option<PathBuf> {
        ProjectDirs::from("dev", "r3dg0d", "opsec-check").map(|d| d.data_dir().to_path_buf())
    }

    pub fn config_dir() -> Option<PathBuf> {
        ProjectDirs::from("dev", "r3dg0d", "opsec-check").map(|d| d.config_dir().to_path_buf())
    }
}
