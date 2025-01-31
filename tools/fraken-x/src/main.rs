// Some portions Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.

use std::path::Path;
use std::{fs, path::PathBuf, process, sync::atomic::Ordering};

use anyhow::Context;
use crossbeam::channel::Sender;
use fraken_x::walk::{Message, ParWalker, Walker};
use superconsole::{style::Stylize, Component, Line, Lines, Span};

use std::sync::atomic::AtomicUsize;

use clap::{Args, Parser};

use yara_x::{MatchingRules, MetaValue, Scanner, SourceCode};

use yansi::Paint;
use yansi::Color::Red;

use sha256::try_digest;

#[derive(Parser)]
#[command(about, long_about = None)]
struct Cli {
    /// Specify a particular path to a file or folder containing the Yara rules to use
    rules: PathBuf,

    #[command(flatten)]
    testorscan: TestOrScan,

    /// A path under the rules path that contains File Magics
    #[arg(long, default_value = "misc/file-type-signatures.txt")]
    magic: Option<PathBuf>,


    /// Only rules with scores greater than this will be output
    #[arg(long, default_value_t = 40)]
    minscore: i64,
}


#[derive(Args)]
#[group(required = true, multiple = false)]
struct TestOrScan {
    /// Specify a particular folder to be scanned
    #[arg(short, long, group="testorscan")]
    folder: Option<PathBuf>,

    /// Test the rules for syntax validity and then exit
    #[arg(long, group="testorscan")]
    testrules: bool,
}

// Taken from yara-x/cli/src/commands/scan.rs
struct ScanState {
    num_scanned_files: AtomicUsize,
    num_matching_files: AtomicUsize,
}

impl ScanState {
    fn new() -> Self {
        Self {
            num_scanned_files: AtomicUsize::new(0),
            num_matching_files: AtomicUsize::new(0),
        }
    }
}

impl Component for ScanState {
    fn draw_unchecked(
        &self,
        dimensions: superconsole::Dimensions,
        _mode: superconsole::DrawMode,
    ) -> anyhow::Result<Lines> {
        let mut lines = Lines::new();

        lines.push(Line::from_iter([Span::new_unstyled(
            "─".repeat(dimensions.width),
        )?]));

        let scanned = format!(
            " {} file(s) scanned. ",
            self.num_scanned_files.load(Ordering::Relaxed)
        );

        let num_matching_files =
            self.num_matching_files.load(Ordering::Relaxed);

        let matched = format!("{} file(s) matched.", num_matching_files);

        lines.push(Line::from_iter([
            Span::new_unstyled(scanned)?,
            Span::new_styled(if num_matching_files > 0 {
                matched.red().bold()
            } else {
                matched.green().bold()
            })?,
        ]));

        Ok(lines)
    }
}

// TODO(fryy): Magics (filetype)
// TODO(fryy): Owner

pub trait OutputHandler: Sync {
    /// Called for each scanned file.
    fn on_file_scanned(
        &self,
        file_path: &Path,
        scan_results: MatchingRules<'_, '_>,
        output: &Sender<Message>,
        minimum_score: i64,
    );
    /// Called when the last file has been scanned.
    fn on_done(&self, _output: &Sender<Message>);
}

pub struct JsonOutputHandler {
    output_buffer: std::sync::Arc<std::sync::Mutex<Vec<MatchJson>>>,
}

#[derive(serde::Serialize, Clone)]
#[allow(non_snake_case)]
struct MatchJson {
    ImagePath: String,
    SHA256: String,
    Signature: String,
    Description: String,
    Reference: String,
    Score: i64,
}

impl OutputHandler for JsonOutputHandler {
    fn on_file_scanned(&self, file_path: &Path, scan_results: MatchingRules<'_, '_>, _output: &Sender<Message>, minimum_score : i64) {
        let path = file_path
        .canonicalize()
        .ok()
        .as_ref()
        .and_then(|absolute| absolute.to_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

        let mut matches = Vec::new();

        for matching_rule in scan_results.into_iter() {
            let hash = try_digest(file_path).unwrap_or("".to_string());
            let mut output = MatchJson {
                ImagePath: path.clone(),
                SHA256: hash,
                Signature: matching_rule.identifier().to_string(),
                Description: "".to_string(),
                Reference: "".to_string(),
                Score: 50,
            };
            let metadata = matching_rule.metadata();
            for (key, value) in metadata {
                if key == "score" {
                    if let MetaValue::Integer(value) = value {
                        output.Score = value;
                    } else if let MetaValue::String(value) = value {
                        output.Score = value.parse().unwrap_or(50);
                    }
                }
                if key.starts_with("desc") {
                    if let MetaValue::String(value) = value {
                        output.Description = value.to_string();
                    }
                }
                if key == "reference" || key.starts_with("report") {
                    if let MetaValue::String(value) = value {
                        output.Reference = value.to_string();
                    }
                }
                if key == "context" {
                    if let MetaValue::String(value) = value {
                        if value == "yes" || value == "true" || value == "1"{
                            output.Score = 0;
                        }
                    }
                }
            }
            if output.Score >= minimum_score {
                matches.push(output);
            }
        }
        let mut lock = self.output_buffer.lock().unwrap();
        lock.extend(matches);
    }

    fn on_done(&self, output: &Sender<Message>) {
        let matches = {
            let mut lock = self.output_buffer.lock().unwrap();
            std::mem::take(&mut *lock)
        };
        let rendered_json = serde_json::to_string(&matches).expect("Failed to render JSON");
        output.send(Message::Info(rendered_json)).unwrap();
    }
}
fn main() {
    let cli = Cli::parse();

    let mut compiler = yara_x::Compiler::new();
    let state = ScanState::new();

    // External vars.
    let vars = vec!["filepath", "filename", "filetype", "extension", "owner"];
     for ident in vars {
        compiler.define_global(ident, "").unwrap();
     }

    // Scan the rules dir
    let mut w = Walker::path(cli.rules.as_path());
    w.filter("**/*.yar");
    w.filter("**/*.yara");
    if let Err(err) = w.walk(|file_path| {
            eprintln!("[-] Attempting to parse {}", file_path.display());
            let src = fs::read(file_path).with_context(|| {
                format!("can not read `{}`", file_path.display())
            })?;
            
            let src = SourceCode::from(src.as_slice()).with_origin(file_path.as_os_str().to_str().unwrap());
            let _ = compiler.add_source(src);
            
            Ok(())
    },
    Err,
    ) {
        eprintln!("Rules parsing error: {}", err);
        process::exit(1);
    }

    for error in compiler.errors() {
        eprintln!("Rule error: {}", error);
    }

    /*for warning in compiler.warnings() {
        eprintln!("{}", warning);
    }*/

    eprintln!("[+] Building the rules");
    // Obtain the compiled YARA rules.
    let rules = compiler.build();

    if cli.testorscan.testrules {
        println!("[+] Rules are valid!");
        process::exit(0);

    }
    eprintln!("[+] Scanning!");
    let path = cli.testorscan.folder.expect("Needs a path");
    let w = ParWalker::path(path.as_path());
    let output_handler = JsonOutputHandler {
        output_buffer: Default::default(),
    };
    w.walk(
        state,
        // Init.
        |_, _output| {
            let scanner = Scanner::new(&rules);
            scanner
        },
        // File handler
        |state, output, file_path, scanner| {
            scanner.set_global("filepath", file_path.to_str().unwrap())?;
            scanner.set_global("filename", file_path.file_name().unwrap().to_str().unwrap())?;
            scanner.set_global("extension", file_path.extension().map(|name| name.to_string_lossy().into_owned()).unwrap_or("".to_string()))?;
            let scan_results = scanner.scan_file(file_path.as_path());
            let scan_results = scan_results?;
            let matched_count = scan_results.matching_rules().len();
            let matched = Box::new(scan_results.matching_rules());

            output_handler.on_file_scanned(file_path.as_path(), *matched, output, cli.minscore);

            state.num_scanned_files.fetch_add(1, Ordering::Relaxed);
            if matched_count > 0 {
                state.num_matching_files.fetch_add(1, Ordering::Relaxed);
            }

            Ok(())
        },
        // Finalisation
        |_, _| {},
        // Walk done.
        |output| output_handler.on_done(output),
        // Error handler
        |err, _| {
            let error = err.to_string();
            let root_cause = err.root_cause().to_string();
            let msg = if error != root_cause {
                format!(
                    "{} {}: {}",
                    "error: ".paint(Red).bold(),
                    error,
                    root_cause,
                )
            } else {
                format!("{}: {}", "error: ".paint(Red).bold(), error)
            };

            eprintln!("{}", msg);

            Ok(())
        },
    ).unwrap();

    println!("Done!")
}
