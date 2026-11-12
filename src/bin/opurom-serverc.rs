//! `opurom-serverc` — lower a full-stack IR into a standalone Rust service.
//!
//! Usage:
//!   opurom-serverc <fullstack-ir.json> -o <dir> [--dep-root <path>]

use std::path::PathBuf;
use std::process::ExitCode;

use opurom_server::codegen::{lower_service, DEFAULT_DEP_ROOT};

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{}", message);
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("opurom-serverc: {}", message);
            ExitCode::FAILURE
        }
    }
}

/// Parse the arguments, lower the IR and report what was written.
fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let mut ir_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut dep_root = PathBuf::from(DEFAULT_DEP_ROOT);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" | "--out" | "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--dep-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --dep-root".to_string())?;
                dep_root = PathBuf::from(value);
            }
            "--help" | "-h" => {
                return Ok(
                    "usage: opurom-serverc <fullstack-ir.json> -o <dir> [--dep-root <path>]"
                        .to_string(),
                );
            }
            "--version" | "-V" => {
                return Ok(format!("opurom-serverc {}", env!("CARGO_PKG_VERSION")));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {}", other));
            }
            other => {
                if ir_path.is_some() {
                    return Err("only one IR file may be given".to_string());
                }
                ir_path = Some(PathBuf::from(other));
            }
        }
    }

    let ir_path = ir_path.ok_or_else(|| "missing IR file argument".to_string())?;
    let out_dir = out_dir.ok_or_else(|| "missing --out <dir> argument".to_string())?;
    let ir_json = std::fs::read_to_string(&ir_path)
        .map_err(|err| format!("cannot read {}: {}", ir_path.display(), err))?;

    let lowered = lower_service(&ir_json, &out_dir, &dep_root)?;
    let mut message = format!(
        "generated OPUROM service in {} ({} files)",
        lowered.root.display(),
        lowered.files.len()
    );
    for file in &lowered.files {
        message.push_str(&format!("\n  {}", file.display()));
    }
    Ok(message)
}
