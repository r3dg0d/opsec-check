use crate::checks::CheckCtx;
use crate::finding::{Finding, Severity};
use crate::tools;
use std::path::{Path, PathBuf};

pub fn check(ctx: &CheckCtx<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    if tools::command_exists("metaclean") {
        findings.push(
            Finding::new(
                "metadata.sibling",
                "file_metadata",
                Severity::Informational,
                "metaclean available to scrub file metadata",
                "Images and documents often embed GPS, device model, author, and software tags.",
                "Run metaclean on outbound files before sharing.",
            )
            .with_tool("metaclean"),
        );
    }

    let home = match std::env::var_os("HOME").map(PathBuf::from) {
        Some(h) => h,
        None => {
            findings.push(Finding::new(
                "metadata.no_home",
                "file_metadata",
                Severity::Informational,
                "HOME unset — skipping metadata sample",
                "Cannot sample user dirs without HOME.",
                "",
            ));
            return findings;
        }
    };

    let mut dirs: Vec<PathBuf> = vec![
        home.join("Pictures"),
        home.join("Downloads"),
        home.join("Documents"),
    ];
    for rel in &ctx.cfg.metadata_sample_dirs {
        dirs.push(home.join(rel));
    }

    let max = ctx.cfg.metadata_max_files.max(1);
    let mut sampled = 0usize;
    let mut suspicious = Vec::new();
    let exts = [".jpg", ".jpeg", ".png", ".tiff", ".heic", ".pdf", ".docx"];

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        // Shallow only — do not walk huge trees
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            if sampled >= max {
                break;
            }
            let path = e.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !exts.iter().any(|ext| name.ends_with(ext)) {
                continue;
            }
            sampled += 1;
            if looks_like_has_metadata_risk(&path) {
                suspicious.push(path.display().to_string());
            }
        }
    }

    if sampled == 0 {
        findings.push(
            Finding::new(
                "metadata.no_sample",
                "file_metadata",
                Severity::Informational,
                "No sample media/docs in shallow home dirs",
                "Nothing to flag — or directories are empty/missing on this account.",
                format!("Sampled up to {max} files across Pictures/Downloads/Documents."),
            )
            .with_limitation("Does not recurse; intentionally avoids huge trees."),
        );
    } else if suspicious.is_empty() {
        findings.push(
            Finding::new(
                "metadata.sample_cleanish",
                "file_metadata",
                Severity::Informational,
                format!("Sampled {sampled} file(s); no crude EXIF/PDF markers spotted"),
                "Heuristic only — files may still contain metadata metaclean would strip.",
                "Shallow scan of common home folders.",
            )
            .with_tool("metaclean")
            .with_limitation("Byte-signature heuristic; not a full EXIF parser."),
        );
    } else {
        findings.push(
            Finding::new(
                "metadata.sample_hits",
                "file_metadata",
                Severity::AttentionRecommended,
                format!(
                    "{}/{} sampled file(s) look metadata-bearing",
                    suspicious.len(),
                    sampled
                ),
                "Outbound photos/PDFs frequently leak location, author, and device serials. \
Scrub before publishing or sending to untrusted parties.",
                suspicious
                    .into_iter()
                    .take(10)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .with_tool("metaclean")
            .with_hints(["metaclean <file>", "Prefer export tools that strip GPS."]),
        );
    }

    findings
}

fn looks_like_has_metadata_risk(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut buf = [0u8; 64 * 1024];
    let n = f.read(&mut buf).unwrap_or(0);
    let slice = &buf[..n];
    // JPEG EXIF APP1
    if slice.windows(4).any(|w| w == b"Exif") {
        return true;
    }
    // PNG textual chunks often include Software/Author after tEXt
    if slice
        .windows(4)
        .any(|w| w == b"tEXt" || w == b"iTXt" || w == b"eXIf")
    {
        return true;
    }
    // PDF Info dict markers
    if slice.windows(7).any(|w| w == b"/Author") {
        return true;
    }
    if slice.windows(8).any(|w| w == b"/Creator") {
        return true;
    }
    if slice.windows(9).any(|w| w == b"/Producer") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_exif_marker() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.jpg");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"\xff\xd8\xff\xe1\x00\x00Exif\x00\x00")
            .unwrap();
        assert!(looks_like_has_metadata_risk(&p));
    }
}
