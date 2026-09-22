//! Text / JSON / Markdown / HTML report rendering.

use crate::finding::{AuditReport, Severity};
use anyhow::Result;
use std::io::{self, Write};

pub enum Format {
    Text,
    Json,
    Markdown,
    Html,
}

pub fn render(report: &AuditReport, fmt: Format) -> Result<()> {
    match fmt {
        Format::Json => {
            let s = serde_json::to_string_pretty(report)?;
            println!("{s}");
        }
        Format::Text => render_text(report)?,
        Format::Markdown => render_markdown(report)?,
        Format::Html => render_html(report)?,
    }
    Ok(())
}

fn render_text(report: &AuditReport) -> Result<()> {
    let mut out = io::stdout().lock();
    let (info, attn, cfg) = report.counts();
    writeln!(
        out,
        "opsec-check {} — {}",
        report.version, report.generated_at
    )?;
    writeln!(out, "host: {}", report.hostname)?;
    writeln!(
        out,
        "findings: {info} informational, {attn} attention recommended, {cfg} configuration issue"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Note: There is no 0–100 privacy score. Severity is qualitative."
    )?;
    writeln!(out)?;

    writeln!(out, "== Sibling tools ==")?;
    for t in &report.sibling_tools {
        let status = if t.available {
            t.path.clone().unwrap_or_else(|| "on PATH".into())
        } else {
            t.note.clone().unwrap_or_else(|| "missing".into())
        };
        writeln!(out, "  {} — {}", t.name, status)?;
    }
    writeln!(out)?;

    for f in &report.findings {
        writeln!(out, "[{}] {}", f.severity.as_str(), f.title)?;
        writeln!(out, "  id: {}  check: {}", f.id, f.check)?;
        writeln!(out, "  why: {}", f.why_it_matters)?;
        if !f.detail.is_empty() {
            for line in f.detail.lines() {
                writeln!(out, "  detail: {line}")?;
            }
        }
        if let Some(lim) = &f.limitation {
            writeln!(out, "  limitation: {lim}")?;
        }
        for h in &f.remediation_hints {
            writeln!(out, "  hint: {h}")?;
        }
        if let Some(tool) = &f.related_tool {
            writeln!(out, "  related: {tool}")?;
        }
        writeln!(out)?;
    }

    writeln!(out, "== Global limitations ==")?;
    for lim in &report.limitations {
        writeln!(out, "  - {lim}")?;
    }
    Ok(())
}

fn render_markdown(report: &AuditReport) -> Result<()> {
    let mut out = io::stdout().lock();
    let (info, attn, cfg) = report.counts();
    writeln!(out, "# opsec-check report")?;
    writeln!(out)?;
    writeln!(out, "- **Version:** {}", report.version)?;
    writeln!(out, "- **Generated:** {}", report.generated_at)?;
    writeln!(out, "- **Host:** {}", report.hostname)?;
    writeln!(
        out,
        "- **Counts:** {info} informational · {attn} attention recommended · {cfg} configuration issue"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "> No numeric privacy score is assigned. Read each finding and its limitations."
    )?;
    writeln!(out)?;
    writeln!(out, "## Sibling tools")?;
    writeln!(out)?;
    for t in &report.sibling_tools {
        let mark = if t.available { "yes" } else { "no" };
        writeln!(
            out,
            "- `{}` — available: **{mark}**{}",
            t.name,
            t.path
                .as_ref()
                .map(|p| format!(" (`{p}`)"))
                .unwrap_or_default()
        )?;
    }
    writeln!(out)?;
    writeln!(out, "## Findings")?;
    writeln!(out)?;
    for f in &report.findings {
        writeln!(out, "### {} — {}", f.severity.as_str(), f.title)?;
        writeln!(out)?;
        writeln!(out, "- **id:** `{}`", f.id)?;
        writeln!(out, "- **check:** `{}`", f.check)?;
        writeln!(out, "- **why it matters:** {}", f.why_it_matters)?;
        if !f.detail.is_empty() {
            writeln!(out, "- **detail:**")?;
            writeln!(out)?;
            writeln!(out, "```")?;
            writeln!(out, "{}", f.detail)?;
            writeln!(out, "```")?;
        }
        if let Some(lim) = &f.limitation {
            writeln!(out, "- **limitation:** {lim}")?;
        }
        if !f.remediation_hints.is_empty() {
            writeln!(out, "- **hints:**")?;
            for h in &f.remediation_hints {
                writeln!(out, "  - {h}")?;
            }
        }
        writeln!(out)?;
    }
    writeln!(out, "## Global limitations")?;
    writeln!(out)?;
    for lim in &report.limitations {
        writeln!(out, "- {lim}")?;
    }
    Ok(())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Informational => "info",
        Severity::AttentionRecommended => "attn",
        Severity::ConfigurationIssue => "cfg",
    }
}

fn render_html(report: &AuditReport) -> Result<()> {
    let mut out = io::stdout().lock();
    let (info, attn, cfg) = report.counts();
    writeln!(out, "<!DOCTYPE html>")?;
    writeln!(out, "<html lang=\"en\"><head><meta charset=\"utf-8\">")?;
    writeln!(out, "<title>opsec-check report</title>")?;
    writeln!(
        out,
        "<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.45}}
.finding{{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}}
.info{{border-left:6px solid #4a90d9}}
.attn{{border-left:6px solid #e6a700}}
.cfg{{border-left:6px solid #d94a4a}}
.sev{{font-weight:600;text-transform:lowercase}}
pre{{white-space:pre-wrap;background:#f6f6f6;padding:.75rem;border-radius:4px}}
.note{{background:#f0f4ff;padding:.75rem;border-radius:6px}}
</style>"
    )?;
    writeln!(out, "</head><body>")?;
    writeln!(out, "<h1>opsec-check report</h1>")?;
    writeln!(
        out,
        "<p>Version {} · {} · host <code>{}</code></p>",
        esc(&report.version),
        esc(&report.generated_at),
        esc(&report.hostname)
    )?;
    writeln!(
        out,
        "<p class=\"note\">Counts: {info} informational, {attn} attention recommended, \
{cfg} configuration issue. <strong>No 0–100 privacy score</strong> is computed.</p>"
    )?;
    writeln!(out, "<h2>Sibling tools</h2><ul>")?;
    for t in &report.sibling_tools {
        writeln!(
            out,
            "<li><code>{}</code> — {}</li>",
            esc(&t.name),
            if t.available {
                esc(t.path.as_deref().unwrap_or("on PATH"))
            } else {
                esc(t.note.as_deref().unwrap_or("missing"))
            }
        )?;
    }
    writeln!(out, "</ul><h2>Findings</h2>")?;
    for f in &report.findings {
        writeln!(
            out,
            "<div class=\"finding {}\"><div class=\"sev\">{}</div><h3>{}</h3>",
            severity_class(f.severity),
            esc(f.severity.as_str()),
            esc(&f.title)
        )?;
        writeln!(
            out,
            "<p><small>id=<code>{}</code> check=<code>{}</code></small></p>",
            esc(&f.id),
            esc(&f.check)
        )?;
        writeln!(
            out,
            "<p><strong>Why it matters:</strong> {}</p>",
            esc(&f.why_it_matters)
        )?;
        if !f.detail.is_empty() {
            writeln!(out, "<pre>{}</pre>", esc(&f.detail))?;
        }
        if let Some(lim) = &f.limitation {
            writeln!(out, "<p><em>Limitation:</em> {}</p>", esc(lim))?;
        }
        if !f.remediation_hints.is_empty() {
            writeln!(out, "<ul>")?;
            for h in &f.remediation_hints {
                writeln!(out, "<li>{}</li>", esc(h))?;
            }
            writeln!(out, "</ul>")?;
        }
        writeln!(out, "</div>")?;
    }
    writeln!(out, "<h2>Global limitations</h2><ul>")?;
    for lim in &report.limitations {
        writeln!(out, "<li>{}</li>", esc(lim))?;
    }
    writeln!(out, "</ul></body></html>")?;
    Ok(())
}
