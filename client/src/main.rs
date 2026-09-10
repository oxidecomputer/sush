// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command-line interface to the Oxide Support Shell.

use std::io::stdout;
use std::process::ExitCode;

use clap::Parser as _;
use rustix::termios::{OptionalActions, OutputModes, Termios, isatty, tcgetattr, tcsetattr};

use sush_client::cli::Cli;
use sush_client::commands::ClientArgs;

/// The kernel tab-expansion bits, which rustix does not expose on
/// illumos: TABDLY from illumos sys/termios.h.
#[cfg(target_os = "illumos")]
const TABDLY: OutputModes = OutputModes::from_bits_retain(0o014000);

#[cfg(not(target_os = "illumos"))]
const TABDLY: OutputModes = OutputModes::TABDLY;

/// Expand tabs in the terminal, not the kernel. illumos ttys default
/// to tab3, whose column accounting is emoji-blind and misaligns our
/// tabbed output. Returns the modes to restore at exit.
fn no_expand_tabs() -> Option<Termios> {
    let out = stdout();
    if !isatty(&out) {
        return None;
    }
    let old = tcgetattr(&out).ok()?;
    let mut new = old.clone();
    new.output_modes &= !TABDLY;
    tcsetattr(&out, OptionalActions::Drain, &new).ok()?;
    Some(old)
}

#[tokio::main]
async fn main() -> ExitCode {
    let saved = no_expand_tabs();
    let mut cli = Cli::default();
    cli.load_session();
    let code = match ClientArgs::parse().execute(&mut cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    };
    if let Some(old) = saved {
        let _ = tcsetattr(stdout(), OptionalActions::Drain, &old);
    }
    code
}
