# fswatcher

![Crates.io](https://img.shields.io/crates/v/fswatcher?style=for-the-badge)
![License](https://img.shields.io/crates/l/fswatcher?style=for-the-badge)
![Downloads](https://img.shields.io/crates/d/fswatcher?style=for-the-badge)

## 📌 Overview

`fswatcher` is a simple CLI tool to monitor file changes and execute a command when modifications are detected. It is built with Rust and utilizes the [`notify`](https://crates.io/crates/notify) crate for efficient filesystem event watching.

## 🚀 Installation

You can install `fswatcher` using Cargo:

```sh
cargo install fswatcher
```

## 🛠 Usage

Run `fswatcher` by specifying a file to watch and a command to execute when the file changes:

```sh
fswatcher <file> <command>
```

### Example:

```sh
fswatcher config.yaml 'echo "Config changed!"'
```

This will monitor `config.yaml` and print "Config changed!" whenever the file is modified.

## ✨ Features

- Watches a specified file for changes
- Executes a command automatically upon file modification
- Uses a lock mechanism to prevent same command duplicate execution

## 🔧 Development

Clone the repository and build locally:

```sh
git clone https://github.com/jmarcelomb/fswatcher.git
cd fswatcher
cargo build --release
```

Run the tool with:

```sh
cargo run -- <file> <command>
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙌 Contribution

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.

---

Created by [Marcelo Borges](https://github.com/jmarcelomb).
