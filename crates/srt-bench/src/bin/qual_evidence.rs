//! Build a committed qualification artifact from harness stdout.
//!
//! The parsing and rendering live in `srt_bench::qual_evidence`, which is
//! tested against the harness's own line format, so the artifact cannot lose a
//! field the way a hand-written transcription can.
//!
//! ```text
//! qual-evidence --git-sha <sha> [--git-dirty] --out <file.json> \
//!     <send-log> <recv-log> [<send-log> <recv-log> ...]
//! ```

use std::process::ExitCode;

use srt_bench::qual_evidence::{Provenance, parse_run, render_json};

/// Command-line shape for one artifact build.
struct Cli {
    git_sha: String,
    git_dirty: bool,
    out_path: String,
    logs: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        git_sha: String::new(),
        git_dirty: false,
        out_path: String::new(),
        logs: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--git-sha" => {
                index += 1;
                cli.git_sha = args.get(index).cloned().unwrap_or_default();
            }
            "--git-dirty" => cli.git_dirty = true,
            "--out" => {
                index += 1;
                cli.out_path = args.get(index).cloned().unwrap_or_default();
            }
            other => cli.logs.push(other.to_string()),
        }
        index += 1;
    }
    if cli.git_sha.is_empty()
        || cli.out_path.is_empty()
        || cli.logs.is_empty()
        || !cli.logs.len().is_multiple_of(2)
    {
        return Err(
            "usage: qual-evidence --git-sha <sha> [--git-dirty] --out <file.json> \
             <send-log> <recv-log> [<send-log> <recv-log> ...]"
                .to_string(),
        );
    }
    Ok(cli)
}

/// One `(send-log, recv-log)` pair turned into run evidence.
fn load_run(
    send_path: &str,
    recv_path: &str,
) -> Result<srt_bench::qual_evidence::RunEvidence, String> {
    let send =
        std::fs::read_to_string(send_path).map_err(|e| format!("cannot read {send_path}: {e}"))?;
    let recv =
        std::fs::read_to_string(recv_path).map_err(|e| format!("cannot read {recv_path}: {e}"))?;
    let sender_line = send
        .lines()
        .find(|line| line.starts_with("SHARED_OWNER_QUAL"))
        .unwrap_or_default();
    let receiver_line = recv
        .lines()
        .rfind(|line| line.starts_with("STATS"))
        .unwrap_or_default();
    if sender_line.is_empty() || receiver_line.is_empty() {
        return Err(format!(
            "{send_path} / {recv_path}: missing sender or receiver line"
        ));
    }
    parse_run(sender_line, receiver_line)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::FAILURE;
        }
    };

    let mut runs = Vec::with_capacity(cli.logs.len() / 2);
    for pair in cli.logs.chunks(2) {
        match load_run(&pair[0], &pair[1]) {
            Ok(run) => runs.push(run),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        }
    }
    runs.sort_by_key(|run| run.fanout);

    let provenance = Provenance {
        git_sha: cli.git_sha,
        git_dirty: cli.git_dirty,
        kernel: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".to_string()),
        machine: read_trimmed("/proc/sys/kernel/arch").unwrap_or_else(|| "unknown".to_string()),
        cpus: std::thread::available_parallelism().map_or(0, |cpus| cpus.get()),
    };
    match std::fs::write(&cli.out_path, render_json(&provenance, &runs)) {
        Ok(()) => {
            println!("wrote {} ({} rows)", cli.out_path, runs.len());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot write {}: {error}", cli.out_path);
            ExitCode::FAILURE
        }
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}
