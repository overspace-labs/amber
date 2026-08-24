mod commands;

use clap::{Parser, Subcommand};

use commands::{AppendCommand, CreateCommand, ExportCommand, ListCommand, ShowCommand};

#[derive(Debug, Parser)]
#[command(
    name = "amber",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nreads:  projects whose Proxy rows use the 52685 row schema",
        "\nwrites: the 52685 project grammar only"
    ),
    about = "Read and write Burp Suite Proxy HTTP history, byte for byte"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Export Proxy HTTP history and raw messages from a Burp project.
    Export(ExportCommand),
    /// List Proxy HTTP history entries without materializing message bodies.
    List(ListCommand),
    /// Show one Proxy HTTP history entry by its stable ID.
    Show(ShowCommand),
    /// Synthesize a whole project from JSON entries, with no source project.
    Create(CreateCommand),
    /// Append JSON entries to a copy of an existing project, preserving everything already stored.
    Append(AppendCommand),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Export(command) => command.run(),
        Command::List(command) => command.run(),
        Command::Show(command) => command.run(),
        Command::Create(command) => command.run(),
        Command::Append(command) => command.run(),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) if commands::is_broken_pipe(&error) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::from(commands::exit_code(&error))
        }
    }
}
