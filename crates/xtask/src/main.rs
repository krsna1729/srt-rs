use std::env;
use std::process::{Command, ExitCode, Stdio};
use std::time::Instant;

mod reportcard;

struct Step {
    name: &'static str,
    cmd: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    tool: Option<(&'static str, &'static str)>,
    cwd: Option<&'static str>,
    informational: bool,
}

struct StepResult {
    name: &'static str,
    passed: bool,
    informational: bool,
    seconds: f64,
}

const FMT: Step = Step {
    name: "fmt",
    cmd: "cargo",
    args: &["fmt", "--all", "--", "--check"],
    env: &[],
    tool: None,
    cwd: None,
    informational: false,
};

const CLIPPY: Step = Step {
    name: "clippy",
    cmd: "cargo",
    args: &[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ],
    env: &[],
    tool: None,
    cwd: None,
    informational: false,
};

const DOC: Step = Step {
    name: "doc",
    cmd: "cargo",
    args: &["doc", "--workspace", "--all-features", "--no-deps"],
    env: &[("RUSTDOCFLAGS", "-D warnings")],
    tool: None,
    cwd: None,
    informational: false,
};

const TYPOS: Step = Step {
    name: "typos",
    cmd: "typos",
    args: &[],
    env: &[],
    tool: Some(("typos", "typos-cli")),
    cwd: None,
    informational: false,
};

const REPORTCARD: Step = Step {
    name: "reportcard",
    cmd: "cargo",
    args: &["xtask", "reportcard"],
    env: &[],
    tool: Some(("rust-code-analysis-cli", "rust-code-analysis-cli")),
    cwd: None,
    informational: false,
};

const TEST: Step = Step {
    name: "test",
    cmd: "cargo",
    args: &["test", "--workspace", "--all-features"],
    env: &[],
    tool: None,
    cwd: None,
    informational: false,
};

const DENY_PUBLISHED: Step = Step {
    name: "deny-published",
    cmd: "cargo",
    args: &[
        "deny",
        "--manifest-path",
        "crates/srt-protocol/Cargo.toml",
        "--exclude-dev",
        "--config",
        "deny-published.toml",
        "check",
        "advisories",
        "bans",
        "licenses",
        "sources",
    ],
    env: &[],
    tool: Some(("cargo-deny", "cargo-deny")),
    cwd: None,
    informational: false,
};

const DENY_WORKSPACE: Step = Step {
    name: "deny-workspace",
    cmd: "cargo",
    args: &["deny", "check", "advisories", "bans", "licenses", "sources"],
    env: &[],
    tool: Some(("cargo-deny", "cargo-deny")),
    cwd: None,
    informational: false,
};

const PACKAGE: Step = Step {
    name: "package",
    cmd: "cargo",
    args: &[
        "package",
        "-p",
        "shiguredo_srt",
        "--locked",
        "--allow-dirty",
    ],
    env: &[],
    tool: None,
    cwd: None,
    informational: false,
};

const FUZZ_BUILD: Step = Step {
    name: "fuzz-build",
    cmd: "cargo",
    args: &["+nightly", "fuzz", "build"],
    env: &[],
    tool: Some(("cargo-fuzz", "cargo-fuzz")),
    cwd: Some("crates/srt-protocol"),
    informational: true,
};

const GEIGER_PROTOCOL: Step = Step {
    name: "geiger-protocol",
    cmd: "cargo",
    args: &["geiger", "--all-features", "--all-targets"],
    env: &[],
    tool: Some(("cargo-geiger", "cargo-geiger")),
    cwd: Some("crates/srt-protocol"),
    informational: true,
};

const GEIGER_TRANSPORT: Step = Step {
    name: "geiger-transport",
    cmd: "cargo",
    args: &["geiger", "--all-features", "--all-targets"],
    env: &[],
    tool: Some(("cargo-geiger", "cargo-geiger")),
    cwd: Some("crates/srt-transport"),
    informational: true,
};

const GEIGER_LIFECYCLE: Step = Step {
    name: "geiger-lifecycle",
    cmd: "cargo",
    args: &["geiger", "--all-features", "--all-targets"],
    env: &[],
    tool: Some(("cargo-geiger", "cargo-geiger")),
    cwd: Some("crates/srt-lifecycle"),
    informational: true,
};
const ASAN_PROTOCOL: Step = Step {
    name: "asan-protocol",
    cmd: "cargo",
    args: &[
        "+nightly",
        "test",
        "-p",
        "shiguredo_srt",
        "--all-targets",
        "--target",
        "x86_64-unknown-linux-gnu",
    ],
    env: &[
        ("RUSTFLAGS", "-Zsanitizer=address"),
        ("RUSTDOCFLAGS", "-Zsanitizer=address"),
    ],
    tool: None,
    cwd: None,
    informational: false,
};

const ASAN_TRANSPORT: Step = Step {
    name: "asan-transport",
    cmd: "cargo",
    args: &[
        "+nightly",
        "test",
        "-p",
        "srt-transport",
        "--all-features",
        "--target",
        "x86_64-unknown-linux-gnu",
    ],
    env: &[
        ("RUSTFLAGS", "-Zsanitizer=address"),
        ("RUSTDOCFLAGS", "-Zsanitizer=address"),
    ],
    tool: None,
    cwd: None,
    informational: false,
};

const PRECOMMIT: &[&Step] = &[&FMT, &CLIPPY, &REPORTCARD, &DOC, &TYPOS];
const CI: &[&Step] = &[
    &FMT,
    &CLIPPY,
    &REPORTCARD,
    &DOC,
    &TYPOS,
    &TEST,
    &DENY_PUBLISHED,
    &DENY_WORKSPACE,
    &PACKAGE,
    &FUZZ_BUILD,
];
fn main() -> ExitCode {
    let arg = env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "fmt" => run_one(&FMT),
        "lint" => run_one(&CLIPPY),
        "doc" => run_one(&DOC),
        "typos" => run_one(&TYPOS),
        "test" => run_one(&TEST),
        "deny" => run_group(&[&DENY_PUBLISHED, &DENY_WORKSPACE]),
        "package" => run_one(&PACKAGE),
        "fuzz-build" => run_one(&FUZZ_BUILD),
        "geiger" => run_group(&[&GEIGER_PROTOCOL, &GEIGER_TRANSPORT, &GEIGER_LIFECYCLE]),
        "reportcard" => reportcard::run(&env::args().skip(2).collect::<Vec<_>>()),
        "asan" => run_group(&[&ASAN_PROTOCOL, &ASAN_TRANSPORT]),
        "precommit" => run_group(PRECOMMIT),
        "ci" | "check-all" => run_group(CI),
        "install-hooks" => install_hooks(),
        _ => {
            eprintln!("usage: cargo xtask <command>");
            eprintln!();
            eprintln!("commands:");
            eprintln!("  fmt            check formatting");
            eprintln!("  lint           clippy with -D warnings");
            eprintln!("  doc            rustdoc with -D warnings");
            eprintln!("  typos          spellcheck (needs typos-cli)");
            eprintln!("  test           workspace tests");
            eprintln!("  deny           advisory and license audit (needs cargo-deny)");
            eprintln!("  package        dry-run package of shiguredo_srt");
            eprintln!("  fuzz-build     compile fuzz targets (needs cargo-fuzz + nightly)");
            eprintln!("  geiger         unsafe surface inventory (needs cargo-geiger)");
            eprintln!("  reportcard     complexity and maintainability ratchet");
            eprintln!("  asan           run AddressSanitizer tests (needs nightly)");
            eprintln!("  precommit      fast gate: fmt + clippy + reportcard + doc + typos");
            eprintln!("  ci             full gate: all checks + report card");
            eprintln!("  check-all      alias for ci");
            eprintln!("  install-hooks  set core.hooksPath to .githooks");
            ExitCode::FAILURE
        }
    }
}

fn run_one(step: &Step) -> ExitCode {
    if !require_tool(step) {
        return ExitCode::FAILURE;
    }
    let r = execute(step);
    print_report(&[r])
}

fn run_group(steps: &[&Step]) -> ExitCode {
    let mut runnable = Vec::new();
    for s in steps {
        if require_tool(s) {
            runnable.push(*s);
        } else if !s.informational {
            return ExitCode::FAILURE;
        }
    }
    let results: Vec<_> = runnable.iter().map(|s| execute(s)).collect();
    print_report(&results)
}

fn print_report(results: &[StepResult]) -> ExitCode {
    let total: f64 = results.iter().map(|r| r.seconds).sum();
    let all_passed = results.iter().all(|r| r.passed || r.informational);

    eprintln!();
    eprintln!("  {:<20} {:>6} {:>8}", "check", "result", "time");
    eprintln!("  {}", "-".repeat(38));
    for r in results {
        let tag = if r.informational {
            "info"
        } else if r.passed {
            "pass"
        } else {
            "FAIL"
        };
        eprintln!("  {:<20} {:>6} {:>7.1}s", r.name, tag, r.seconds);
    }
    eprintln!("  {}", "-".repeat(38));
    eprintln!("  {:<20} {:>6} {:>7.1}s", "", "", total);
    eprintln!();

    if all_passed {
        eprintln!("  all checks passed");
        ExitCode::SUCCESS
    } else {
        let failed: Vec<_> = results
            .iter()
            .filter(|r| !r.passed && !r.informational)
            .map(|r| r.name)
            .collect();
        eprintln!("  FAILED: {}", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn require_tool(step: &Step) -> bool {
    let Some((bin, crate_name)) = step.tool else {
        return true;
    };
    let found = if bin.starts_with("cargo-") {
        Command::new("cargo")
            .arg(bin.trim_start_matches("cargo-"))
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    } else {
        Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !found {
        eprintln!("  {bin}: not found. Install with: cargo install {crate_name} --locked");
    }
    found
}

fn cmd_line(step: &Step) -> String {
    let mut parts = Vec::new();
    for &(k, v) in step.env {
        parts.push(format!("{k}=\"{v}\""));
    }
    parts.push(step.cmd.to_string());
    parts.extend(step.args.iter().map(|a| (*a).to_string()));
    parts.join(" ")
}

fn execute(step: &Step) -> StepResult {
    let header = format!(" {} ", step.name);
    eprintln!();
    eprintln!("  {header:=^60}");
    eprintln!("  $ {}", cmd_line(step));
    if let Some(dir) = step.cwd {
        eprintln!("    (in {dir})");
    }
    eprintln!();

    let start = Instant::now();
    let mut c = Command::new(step.cmd);
    c.args(step.args);
    for &(k, v) in step.env {
        c.env(k, v);
    }
    if let Some(dir) = step.cwd {
        c.current_dir(dir);
    }
    let passed = c.status().is_ok_and(|s| s.success());
    StepResult {
        name: step.name,
        passed,
        informational: step.informational,
        seconds: start.elapsed().as_secs_f64(),
    }
}

fn install_hooks() -> ExitCode {
    let status = Command::new("git")
        .args(["config", "core.hooksPath", ".githooks"])
        .status();
    if status.is_ok_and(|s| s.success()) {
        eprintln!("  set core.hooksPath = .githooks");
        ExitCode::SUCCESS
    } else {
        eprintln!("  failed to set core.hooksPath");
        ExitCode::FAILURE
    }
}
