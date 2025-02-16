//! A file system watcher that executes a command when a specified file changes.
//!
//! This crate provides a simple utility to watch a file for changes and execute
//! a command whenever the file is modified. It uses asynchronous I/O for
//! efficient file watching and command execution.

use clap::{Arg, Command as ClapCommand};
use futures::{
    channel::mpsc::{channel, Receiver},
    SinkExt, StreamExt,
};
use log::{error, info, warn};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::hash_map::DefaultHasher;
use std::fs::{remove_file, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind};
use std::{path::PathBuf, sync::Arc};
use tokio::{process::Command, signal};

/// Represents a lock file to prevent multiple instances of the watcher.
struct LockFile {
    path: PathBuf,
}

/// Generates a unique hash for a given command string.
///
/// # Arguments
/// * `command` - The command string to hash.
///
/// # Returns
/// A `u64` hash value.
fn hash_command(command: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);
    hasher.finish()
}

impl LockFile {
    /// Creates a new lock file for the given command.
    ///
    /// # Arguments
    /// * `command` - The command string used to generate a unique lock file name.
    ///
    /// # Returns
    /// An `io::Result<LockFile>` representing the lock file.
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

    /// Cleans up the lock file by deleting it.
    fn cleanup(&self) {
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

impl Drop for LockFile {
    /// Automatically cleans up the lock file when the `LockFile` instance is dropped.
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Executes a shell command asynchronously.
///
/// # Arguments
/// * `command` - The command to execute.
///
/// # Returns
/// An `io::Result<()>` indicating success or failure.
async fn execute_command(command: &str) -> io::Result<()> {
    info!("Executing command: {}", command);
    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
        .spawn()?
        .wait()
        .await?;
    if !status.success() {
        error!("Command failed: {} with status: {:?}", command, status);
    }
    Ok(())
}

/// Creates an asynchronous file watcher.
///
/// # Returns
/// A tuple containing the watcher and a receiver for file change events.
fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);
    let watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        Config::default(),
    )?;
    Ok((watcher, rx))
}

/// Watches a file for changes and executes a command when changes are detected.
///
/// # Arguments
/// * `path` - The path to the file to watch.
/// * `command` - The command to execute when the file changes.
///
/// # Returns
/// A `notify::Result<()>` indicating success or failure.
async fn async_watch(path: PathBuf, command: String) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;
    watcher.watch(&path, RecursiveMode::NonRecursive)?;
    info!("Watching: {}", path.display());
    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => {
                info!("File changed: {:?}", event);
                if let Err(e) = execute_command(&command).await {
                    error!("Error executing command: {}", e);
                }
            }
            Err(e) => error!("Watch error: {:?}", e),
        }
    }
    Ok(())
}

/// The main entry point for the file watcher application.
#[tokio::main]
async fn main() -> notify::Result<()> {
    // Initialize the logger with a default log level of "warn".
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("FSWATCHER_LOG", "warn"))
        .init();

    // Parse command-line arguments.
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

    // Get the file path and command from the parsed arguments.
    let file_path = PathBuf::from(matches.get_one::<String>("file").unwrap());
    let command = matches
        .get_many::<String>("command")
        .unwrap()
        .map(String::as_str)
        .collect::<Vec<&str>>()
        .join(" ");

    // Prevent multiple instances by creating a lock file.
    let lock_file = Arc::new(LockFile::new(&command).map_err(|e| {
        error!("Failed to acquire lock file: {}", e);
        notify::Error::generic(format!("Lock file error: {:?}", e).as_str())
    })?);

    // Handle Ctrl+C to clean up the lock file.
    let lock_file_clone = lock_file.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received SIGINT, cleaning up..");
        lock_file_clone.cleanup();
        std::process::exit(0);
    });

    // Start watching the file for changes.
    async_watch(file_path, command).await
}
