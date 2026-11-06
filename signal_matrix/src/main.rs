//! Builds the harness as `fuzz_target!` (`#![no_main]`) and `fuzz!` (`main`) binaries
//! with `cargo fuzz build`, with and without ASan, runs them directly, and tabulates
//! whether libFuzzer detects and saves each crash.
//!
//! Run it with `cargo run -p signal-matrix -- --help`.

#[allow(dead_code)]
#[path = "../harness/src/crashes.rs"]
mod crashes;

use clap::{
    builder::{PossibleValue, PossibleValuesParser, TypedValueParser},
    Parser,
};
use crashes::{Crash, CRASHES};
use std::{
    env,
    ffi::OsString,
    fmt, fs,
    fs::File,
    io, mem,
    path::{self, Path, PathBuf},
    process::{Command, ExitCode, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const SANITIZERS: [&str; 2] = ["none", "address"];

/// Harness binaries, with the macro each one uses.
const BINS: [(&str, &str); 2] = [
    ("fuzz_target", "fuzz_target! (no_main)"),
    ("fuzz_main", "fuzz! (main)"),
];

/// Flags for every fuzzer run; the short `-timeout` keeps the `timeout` crash quick.
const FUZZER_FLAGS: [&str; 3] = ["-seed=1", "-runs=10000", "-timeout=3"];

/// Checks whether libFuzzer detects and saves crashes in fuzz_target! and fuzz! binaries.
///
/// Builds with cargo-fuzz (`cargo install cargo-fuzz`).
#[derive(Parser)]
struct Config {
    /// Sanitizers to build with
    #[arg(
        long = "sanitizer",
        value_name = "LIST",
        value_delimiter = ',',
        value_parser = SANITIZERS,
        default_value = "none,address",
    )]
    sanitizers: Vec<String>,

    /// Crashes to trigger, all by default
    #[arg(
        long = "crash",
        value_name = "LIST",
        value_delimiter = ',',
        value_parser = crash_parser(),
    )]
    crashes: Vec<&'static Crash>,

    /// Kill a fuzzer run after this many seconds
    #[arg(
        long,
        value_name = "SECS",
        default_value = "60",
        value_parser = |secs: &str| secs.parse().map(Duration::from_secs),
    )]
    timeout: Duration,

    /// Builds, logs and crash files
    #[arg(long, value_name = "PATH", default_value_os_t = default_work_dir())]
    work_dir: PathBuf,

    /// Flags for every libFuzzer run
    #[arg(last = true, value_name = "LIBFUZZER_FLAGS")]
    fuzzer_flags: Vec<String>,
}

impl Config {
    fn parse_args() -> Result<Self, String> {
        let mut cfg = Self::parse();
        if cfg.crashes.is_empty() {
            cfg.crashes = CRASHES.iter().filter(|crash| crash.supported).collect();
        }
        // fuzzers run inside their own directories
        cfg.work_dir = path::absolute(&cfg.work_dir).map_err(|err| format!("--work-dir: {err}"))?;
        Ok(cfg)
    }

    fn run_dir(&self, sanitizer: &str, bin: &str, name: &str) -> PathBuf {
        self.work_dir
            .join(sanitizer)
            .join("runs")
            .join(bin)
            .join(name)
    }
}

enum Outcome {
    /// Reported by libFuzzer or ASan, with a crash file written.
    Saved(String),
    /// Reported, but no crash file written.
    NotSaved(String),
    /// Not reported; holds how the process ended.
    Missed(String),
    /// Killed after `--timeout`.
    Hung,
    Unavailable(&'static str),
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saved(report) => write!(f, "saved ({report})"),
            Self::NotSaved(report) => write!(f, "NOT SAVED ({report})"),
            Self::Missed(status) => write!(f, "MISSED ({status})"),
            Self::Hung => write!(f, "HUNG"),
            Self::Unavailable(reason) => write!(f, "- ({reason})"),
        }
    }
}

struct Row<'a> {
    sanitizer: &'a str,
    crash: &'static Crash,
    outcomes: [Outcome; 2],
}

struct Run {
    /// `None` if the run was killed.
    status: Option<ExitStatus>,
    log: String,
    artifacts: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cfg = Config::parse_args()?;
    #[cfg(windows)]
    suppress_crash_dialogs();

    let harness = Path::new(env!("CARGO_MANIFEST_DIR")).join("harness");
    let rustc = output(&harness, "rustc", &["-vV"])?;
    let cargo_fuzz = output(&harness, "cargo", &["fuzz", "--version"])?;
    let triple = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("`rustc -vV` printed no host triple")?;
    let rustc_version = rustc.lines().next().unwrap_or_default();
    eprintln!("{rustc_version}, {}, host {triple}", cargo_fuzz.trim());

    let mut rows = Vec::new();
    for sanitizer in &cfg.sanitizers {
        let bins = prepare(&cfg, &harness, triple, sanitizer);
        for &crash in &cfg.crashes {
            let outcomes = std::array::from_fn(|i| {
                let bin = BINS[i].0;
                let outcome = match &bins[i] {
                    Ok(exe) => {
                        let dir = cfg.run_dir(sanitizer, bin, crash.name);
                        match fuzz(&cfg, exe, Some(crash.name), &dir) {
                            Ok(run) => classify(&run),
                            Err(err) => {
                                eprintln!("failed to run {}: {err}", exe.display());
                                Outcome::Unavailable("failed to run")
                            }
                        }
                    }
                    Err(reason) => Outcome::Unavailable(reason),
                };
                eprintln!("{sanitizer:<8} {bin:<12} {:<15} {outcome}", crash.name);
                outcome
            });
            rows.push(Row {
                sanitizer,
                crash,
                outcomes,
            });
        }
    }

    print_table(&cfg, &rows);
    Ok(())
}

fn default_work_dir() -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let target_dir =
        env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo.join("target"), PathBuf::from);
    target_dir.join("signal-matrix")
}

/// Accepts the crashes supported on this platform, described in `--help`.
fn crash_parser() -> impl TypedValueParser<Value = &'static Crash> {
    let supported = CRASHES.iter().filter(|crash| crash.supported);
    PossibleValuesParser::new(
        supported.map(|crash| PossibleValue::new(crash.name).help(crash.description)),
    )
    .map(|name| CRASHES.iter().find(|crash| crash.name == name).unwrap())
}

/// Runs `program` from the harness, so rustup picks the repo's toolchain as cargo will.
fn output(harness: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let command = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .current_dir(harness)
        .output()
        .map_err(|err| format!("failed to run `{command}`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("`{command}` failed:\n{stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Builds both binaries and checks that they fuzz without crashing.
fn prepare(
    cfg: &Config,
    harness: &Path,
    triple: &str,
    sanitizer: &str,
) -> [Result<PathBuf, &'static str>; 2] {
    let release_dir = build(cfg, harness, triple, sanitizer);
    BINS.map(|(bin, _)| {
        let exe = release_dir
            .as_ref()
            .ok_or("build failed")?
            .join(format!("{bin}{}", env::consts::EXE_SUFFIX));
        let dir = cfg.run_dir(sanitizer, bin, "smoke-test");
        match fuzz(cfg, &exe, None, &dir) {
            Ok(run) if run.status.is_some_and(|status| status.success()) && run.artifacts == 0 => {
                Ok(exe)
            }
            _ => {
                eprintln!(
                    "{bin} ({sanitizer}) failed its smoke test, see {}",
                    dir.display()
                );
                Err("smoke test failed")
            }
        }
    })
}

/// Builds the harness with `cargo fuzz build` and returns its output directory.
fn build(cfg: &Config, harness: &Path, triple: &str, sanitizer: &str) -> Option<PathBuf> {
    eprintln!("building harness with sanitizer {sanitizer}");
    let target_dir = cfg.work_dir.join(sanitizer).join("target");
    // cargo-fuzz defaults to the platform it was built for, so pin the output path
    let status = Command::new("cargo")
        .args([
            "fuzz",
            "build",
            "--sanitizer",
            sanitizer,
            "--target",
            triple,
        ])
        .arg("--fuzz-dir")
        .arg(harness)
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(harness)
        .status();
    match status {
        Ok(status) if status.success() => Some(target_dir.join(triple).join("release")),
        Ok(_) => None,
        Err(err) => {
            eprintln!("failed to run cargo: {err}");
            None
        }
    }
}

/// Fuzzes `exe` in a fresh `dir`, triggering `crash` on non-empty inputs.
fn fuzz(cfg: &Config, exe: &Path, crash: Option<&str>, dir: &Path) -> io::Result<Run> {
    match fs::remove_dir_all(dir) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    let artifacts = dir.join("artifacts");
    fs::create_dir_all(&artifacts)?;
    let log_path = dir.join("fuzzer.log");
    let log = File::create(&log_path)?;

    let mut artifact_prefix = OsString::from("-artifact_prefix=");
    artifact_prefix.push(&artifacts);
    artifact_prefix.push(path::MAIN_SEPARATOR_STR);
    // as `cargo fuzz run` sets it
    let mut asan_options = env::var("ASAN_OPTIONS").unwrap_or_default();
    if !asan_options.is_empty() {
        asan_options.push(':');
    }
    asan_options.push_str("detect_odr_violation=0");

    let mut cmd = Command::new(exe);
    cmd.args(FUZZER_FLAGS)
        .arg(artifact_prefix)
        .args(&cfg.fuzzer_flags)
        .current_dir(dir)
        .env("ASAN_OPTIONS", asan_options)
        .env_remove(crashes::ENV)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    if let Some(crash) = crash {
        cmd.env(crashes::ENV, crash);
    }

    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + cfg.timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait()?;
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok(Run {
        status,
        log: String::from_utf8_lossy(&fs::read(&log_path)?).into_owned(),
        artifacts: fs::read_dir(&artifacts)?.count(),
    })
}

fn classify(run: &Run) -> Outcome {
    let Some(status) = run.status else {
        return Outcome::Hung;
    };
    match (report(&run.log), run.artifacts > 0) {
        (Some(report), true) => Outcome::Saved(report),
        (None, true) => Outcome::Saved(describe(status)),
        (Some(report), false) => Outcome::NotSaved(report),
        (None, false) => Outcome::Missed(describe(status)),
    }
}

/// Finds the first error reported by libFuzzer or ASan.
fn report(log: &str) -> Option<String> {
    log.lines().find_map(|line| {
        if let Some((_, error)) = line.split_once("ERROR: libFuzzer: ") {
            // drop details that vary between runs, like "after 3 seconds"
            return Some(error.split(" after ").next()?.trim().to_owned());
        }
        let (_, error) = line.split_once("ERROR: AddressSanitizer: ")?;
        Some(format!("ASan {}", error.split_whitespace().next()?))
    })
}

fn describe(status: ExitStatus) -> String {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return signal_name(signal);
    }
    match status.code() {
        #[cfg(windows)]
        Some(code) if code < 0 => ntstatus_name(code as u32),
        Some(code) => format!("exit {code}"),
        None => status.to_string(),
    }
}

#[cfg(unix)]
fn signal_name(signal: std::ffi::c_int) -> String {
    let name = match signal {
        libc::SIGABRT => "SIGABRT",
        libc::SIGALRM => "SIGALRM",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGILL => "SIGILL",
        libc::SIGKILL => "SIGKILL",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGTRAP => "SIGTRAP",
        _ => return format!("signal {signal}"),
    };
    name.to_owned()
}

#[cfg(windows)]
fn ntstatus_name(code: u32) -> String {
    let name = match code {
        0x8000_0003 => "STATUS_BREAKPOINT",
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_00FD => "STATUS_STACK_OVERFLOW",
        0xC000_0135 => "STATUS_DLL_NOT_FOUND",
        // also the status of `__fastfail`, which Rust's abort uses
        0xC000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        _ => return format!("exit {code:#010x}"),
    };
    name.to_owned()
}

/// Keeps crash dialogs from blocking the fuzzers, which inherit the error mode.
#[cfg(windows)]
fn suppress_crash_dialogs() {
    use std::ffi::c_uint;

    extern "system" {
        fn SetErrorMode(mode: c_uint) -> c_uint;
    }
    const SEM_FAILCRITICALERRORS: c_uint = 0x0001;
    const SEM_NOGPFAULTERRORBOX: c_uint = 0x0002;
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
}

fn print_table(cfg: &Config, rows: &[Row]) {
    let header = ["crash", "sanitizer", BINS[0].1, BINS[1].1, "diff"].map(String::from);
    let body = rows.iter().map(|row| {
        let [no_main, main] = &row.outcomes;
        let differs = mem::discriminant(no_main) != mem::discriminant(main);
        [
            row.crash.name.to_owned(),
            row.sanitizer.to_owned(),
            no_main.to_string(),
            main.to_string(),
            if differs { "differs" } else { "" }.to_owned(),
        ]
    });
    let table: Vec<_> = std::iter::once(header).chain(body).collect();

    let mut widths = [0; 5];
    for row in &table {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    println!();
    for (i, row) in table.iter().enumerate() {
        let cells: Vec<_> = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        println!("| {} |", cells.join(" | "));
        if i == 0 {
            let rules: Vec<_> = widths.iter().map(|&width| "-".repeat(width)).collect();
            println!("|-{}-|", rules.join("-|-"));
        }
    }

    println!();
    println!("saved      reported by libFuzzer or ASan, crash file written");
    println!("NOT SAVED  reported, but no crash file written");
    println!("MISSED     not reported, the fuzzer died with the given status");
    println!("HUNG       killed after {}s", cfg.timeout.as_secs());
    println!();
    for crash in &cfg.crashes {
        println!("{:<15} {}", crash.name, crash.description);
    }
    println!();
    println!(
        "logs: {}",
        cfg.run_dir("<sanitizer>", "<binary>", "<crash>")
            .join("fuzzer.log")
            .display()
    );
}
