use clap::{Arg, Command as ClapCommand};
use log::{error, info, warn};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::hash_map::DefaultHasher;
use std::fs::{remove_file, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::channel;
use std::time::Duration;

struct LockFile {
    path: PathBuf,
}

impl LockFile {
    fn new(command: &str) -> io::Result<Self> {
        let lock_file_path =
            PathBuf::from(format!("/tmp/fswatcher_{}.lock", hash_command(command)));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_file_path)
        {
            Ok(_) => {
                info!("Lock file created: {}", lock_file_path.display());
                Ok(LockFile {
                    path: lock_file_path,
                })
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                warn!("Another instance with the same command is already running.");
                Err(e)
            }
            Err(e) => {
                error!("Failed to create lock file: {:?}", e);
                Err(e)
            }
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.path) {
            error!(
                "Failed to delete lock file {}: {:?}",
                self.path.display(),
                e
            );
        } else {
            info!("Lock file deleted: {}", self.path.display());
        }
    }
}

/// Execute the provided command and stream its output
fn execute_command(command: &str) -> io::Result<()> {
    info!("Executing command..");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::inherit()) // Stream output to console
        .stderr(Stdio::inherit())
        .spawn()?;

    let status = child.wait()?;
    if !status.success() {
        error!("Command failed: {} with status: {}", command, status);
    }
    Ok(())
}

/// Generate a unique hash for the command string
fn hash_command(command: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);
    hasher.finish()
}

fn main() -> notify::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("FSWATCHER_LOG", "warn"))
        .init();
    let matches = ClapCommand::new("fswatcher")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Marcel Borges")
        .about("Watches a file and executes a command on changes")
        .arg(
            Arg::new("file")
                .help("The file to watch for changes")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("command")
                .help("The command to execute when the file changes")
                .required(true)
                .index(2)
                .num_args(1..)
                .allow_hyphen_values(true)
                .trailing_var_arg(true),
        )
        .get_matches();

    let file_path = PathBuf::from(matches.get_one::<String>("file").unwrap());

    let command = matches
        .get_many::<String>("command")
        .unwrap()
        .map(String::as_str)
        .collect::<Vec<&str>>()
        .join(" ");

    // Prevent multiple instances
    let _lock_file = LockFile::new(&command).map_err(|e| {
        error!("Failed to acquire lock file: {}", e);
        notify::Error::generic(format!("Lock file error: {:?}", e).as_str())
    })?;

    let (tx, rx) = channel();

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                info!("File changed..");
                if matches!(event.kind, EventKind::Modify(_)) {
                    tx.send(()).expect("Failed to send notification");
                }
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_millis(1000)),
    )?;

    watcher.watch(&file_path, RecursiveMode::NonRecursive)?;

    info!("Watching: {}", file_path.display());

    // Handle file changes asynchronously
    for _ in rx {
        if let Err(e) = execute_command(&command) {
            error!("Error executing command: {}", e);
        }
    }

    Ok(())
}
