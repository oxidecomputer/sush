// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The client configuration file, e.g., `~/.config/sush/sush.toml`.
//!
//! The options specified in the config file provide defaults for
//! the client command options. Option values cascade, as in CSS:
//! the command line overrides the environment, which overrides the
//! config file, which overrides the built-in defaults. When two
//! conflicting options come from different sources, the cascade
//! drops the one from the weaker source. To run the cascade, we
//! take `UnmergedArgs` from the environment and command line,
//! and *merge* that with the parsed config options; see [`parse_with_config`].
//!
//! Each key in the config file is the long name of a command option
//! with a (non-secret) environment variable. Each table is a profile,
//! and `--profile` selects one to apply. Top-level keys apply to
//! every profile, and the selected profile overrides the top-level.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env::var_os;
use std::ffi::OsString;
use std::fs::read_to_string;
use std::io;
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::{Arg, ArgMatches, Command, CommandFactory as _, FromArgMatches as _};
use strum::Display;
use thiserror::Error;
use toml::{Table, Value};

use crate::commands::{ClientArgs, CommandError, GlobalArgs};
use crate::{PREFIX, base_directories};

const FILE_NAME: &str = "sush.toml";

/// One profile's settings, ready to become option defaults.
#[derive(Clone, Debug, Default)]
pub struct ConfigOptions {
    values: BTreeMap<String, Vec<String>>,
}

impl ConfigOptions {
    /// Read `path`, or the default file if it exists.
    fn load(path: Option<PathBuf>, profile: Option<String>) -> Result<Self, ConfigError> {
        let path = path.or_else(|| base_directories().find_config_file(FILE_NAME));
        let Some(path) = path else {
            return match profile {
                Some(profile) => Err(ConfigError::NoFile(profile)),
                None => Ok(Self::default()),
            };
        };
        let text = read_to_string(&path).map_err(|error| ConfigError::Read {
            path: path.clone(),
            error,
        })?;
        Self::from_toml(path, &text, profile)
    }

    /// Load the config file and profile that `supplied` and the
    /// environment select.
    pub fn from_supplied(supplied: &SuppliedOptions) -> Result<Self, CommandError> {
        let words = supplied.command_line();
        let matches = parse_with_config(GlobalArgs::command(), words, &Self::default())?;
        let GlobalArgs {
            config, profile, ..
        } = GlobalArgs::from_arg_matches(&matches)?;
        Ok(Self::load(config, profile)?)
    }

    fn from_toml(path: PathBuf, text: &str, profile: Option<String>) -> Result<Self, ConfigError> {
        let table = toml::from_str::<Table>(text).map_err(|error| ConfigError::Parse {
            path: path.clone(),
            error,
        })?;
        let valid_keys = all_keys(&ClientArgs::command());
        let convert = |table| convert_table(table, &valid_keys, &path);

        let mut top_level = Table::new();
        let mut profiles = BTreeMap::new();
        for (key, value) in table {
            match value {
                Value::Table(profile) => {
                    profiles.insert(key, convert(profile)?);
                }
                value => {
                    top_level.insert(key, value);
                }
            }
        }

        let mut values = convert(top_level)?;
        let profile = profile.or_else(|| values.get("profile")?.first().cloned());
        if let Some(profile) = profile {
            let selected = profiles
                .remove(&profile)
                .ok_or(ConfigError::UnknownProfile { path, profile })?;
            values.extend(selected);
        }
        Ok(Self { values })
    }

    fn values_for(&self, arg: &Arg) -> Option<&Vec<String>> {
        arg_keys(arg).find_map(|key| self.values.get(key))
    }

    /// Describe each option that has a value from the command line,
    /// the environment, or this config, as `key = value (source)`.
    /// The values of global options come from `matches`. Subcommand
    /// options take their values from the environment or this config.
    pub fn describe(&self, matches: &ArgMatches) -> Vec<String> {
        let command = ClientArgs::command();
        let mut described = BTreeSet::new();
        let mut lines = Vec::new();
        for arg in all_arguments(&command) {
            let Some(long_name) = arg.get_long() else {
                continue;
            };
            if !described.insert(long_name) {
                continue;
            }
            let value = match matches.try_get_raw(arg_id(arg)) {
                Ok(_) => self.parsed_value(arg, matches),
                Err(_) => self.unparsed_value(arg),
            };
            if let Some((values, source)) = value {
                lines.push(format!("{long_name} = {values} ({source})"));
            }
        }
        lines
    }

    /// Find the value of `arg` in `matches`, and its source.
    fn parsed_value(&self, arg: &Arg, matches: &ArgMatches) -> Option<(String, OptionSource)> {
        let source = match matches.value_source(arg_id(arg))? {
            ValueSource::CommandLine => OptionSource::CommandLine,
            ValueSource::EnvVariable => OptionSource::Environment,
            _ if self.values_for(arg).is_none() => return None,
            _ => OptionSource::ConfigFile,
        };
        Some((display_values(arg, matches), source))
    }

    /// Find the value of a configurable `arg` in the environment or
    /// this config, and its source.
    fn unparsed_value(&self, arg: &Arg) -> Option<(String, OptionSource)> {
        if !is_configurable(arg) {
            return None;
        }
        match (arg.get_env().and_then(var_os), self.values_for(arg)) {
            (Some(value), _) => Some((
                value.to_string_lossy().into_owned(),
                OptionSource::Environment,
            )),
            (None, Some(values)) => Some((values.join(", "), OptionSource::ConfigFile)),
            (None, None) => None,
        }
    }
}

/// Where an option's value comes from.
#[derive(Clone, Copy, Debug, Display)]
enum OptionSource {
    #[strum(to_string = "command line")]
    CommandLine,
    #[strum(to_string = "environment")]
    Environment,
    #[strum(to_string = "config file")]
    ConfigFile,
}

/// Convert the entries of `table` to option values. Fails on
/// any key not in `valid_keys` or any value of the wrong type,
/// reporting `path` as the source.
fn convert_table(
    table: Table,
    valid_keys: &BTreeSet<String>,
    path: &Path,
) -> Result<BTreeMap<String, Vec<String>>, ConfigError> {
    table
        .into_iter()
        .map(|(key, value)| {
            if !valid_keys.contains(&key) {
                return Err(ConfigError::UnknownKey {
                    path: path.to_owned(),
                    key,
                    valid_keys: valid_keys.iter().cloned().collect(),
                });
            }
            let Some(values) = arg_values(value) else {
                return Err(ConfigError::InvalidValue {
                    path: path.to_owned(),
                    key,
                });
            };
            Ok((key, values))
        })
        .collect()
}

/// Parse `words` with `command`, merging in defaults from `options`.
pub fn parse_with_config<I, T>(
    command: Command,
    words: I,
    options: &ConfigOptions,
) -> Result<ArgMatches, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    UnmergedArgs::parse(command, words)?.merge(options)
}

/// Parse `words` with `command`, merging in the config file and
/// profile they select.
pub fn parse_and_merge_config<I, T>(command: Command, words: I) -> Result<ArgMatches, CommandError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let unmerged = UnmergedArgs::parse(command, words)?;
    let GlobalArgs {
        config, profile, ..
    } = GlobalArgs::from_arg_matches(&unmerged.matches)?;
    let options = ConfigOptions::load(config, profile)?;
    Ok(unmerged.merge(&options)?)
}

struct UnmergedArgs {
    command: Command,
    words: Vec<OsString>,
    matches: ArgMatches,
}

impl UnmergedArgs {
    fn parse<I, T>(command: Command, words: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let words = words.into_iter().map(Into::into).collect::<Vec<_>>();
        let matches = command
            .clone()
            .ignore_errors(true) // wait for merge to resolve conflicts
            .disable_help_flag(true) // wait for merge so defaults show
            .disable_help_subcommand(true) // ditto
            .try_get_matches_from(&words)?;
        Ok(Self {
            command,
            words,
            matches,
        })
    }

    fn merge(self, options: &ConfigOptions) -> Result<ArgMatches, clap::Error> {
        let Self {
            command,
            words,
            matches,
        } = self;
        let losers = compute_merge_losers(options, &command, &matches);
        let command = map_command_tree(command, &|command| {
            command.mut_args(|arg| {
                if losers.contains(arg.get_id().as_str()) {
                    arg.env(None).default_value(None)
                } else if let Some(values) = options.values_for(&arg) {
                    arg.default_values(values.clone())
                } else {
                    arg
                }
            })
        });
        command.try_get_matches_from(words)
    }
}

/// An option is configurable if it has an environment variable
/// whose value is not a secret.
fn is_configurable(arg: &Arg) -> bool {
    arg.get_env().is_some() && !arg.is_hide_env_values_set()
}

/// List the config file keys that can set `arg`.
fn arg_keys(arg: &Arg) -> impl Iterator<Item = &str> {
    let configurable = is_configurable(arg);
    arg.get_long()
        .into_iter()
        .chain(arg.get_all_aliases().unwrap_or_default())
        .filter(move |_| configurable)
}

/// Collect the config file keys valid anywhere in `command`.
fn all_keys(command: &Command) -> BTreeSet<String> {
    all_arguments(command)
        .into_iter()
        .flat_map(arg_keys)
        .map(str::to_owned)
        .collect()
}

/// Collect the arguments of `command` and all its subcommands.
fn all_arguments(command: &Command) -> Vec<&Arg> {
    let mut args = command.get_arguments().collect::<Vec<_>>();
    for subcommand in command.get_subcommands() {
        args.extend(all_arguments(subcommand));
    }
    args
}

fn compute_merge_losers(
    options: &ConfigOptions,
    command: &Command,
    matches: &ArgMatches,
) -> BTreeSet<String> {
    let mut losers = BTreeSet::new();
    let source = |arg: &Arg| {
        matches
            .value_source(arg.get_id().as_str())
            .filter(|&source| source != ValueSource::DefaultValue)
            .or_else(|| options.values_for(arg).map(|_| ValueSource::DefaultValue))
    };
    for arg in command.get_arguments() {
        for other in command.get_arg_conflicts_with(arg) {
            if let (Some(a), Some(b)) = (source(arg), source(other)) {
                match a.cmp(&b) {
                    Ordering::Equal => (), // neither loses
                    Ordering::Less => {
                        losers.insert(arg.get_id().to_string());
                    }
                    Ordering::Greater => {
                        losers.insert(other.get_id().to_string());
                    }
                }
            }
        }
    }
    if let Some((name, matches)) = matches.subcommand()
        && let Some(subcommand) = command.find_subcommand(name)
    {
        losers.extend(compute_merge_losers(options, subcommand, matches));
    }
    losers
}

fn map_command_tree(command: Command, f: &impl Fn(Command) -> Command) -> Command {
    f(command).mut_subcommands(|subcommand| map_command_tree(subcommand, f))
}

/// Options explicitly supplied on the command line, by long name, with
/// their values (none for a flag).
#[derive(Clone, Debug, Default)]
pub struct SuppliedOptions(BTreeMap<String, Vec<OsString>>);

impl SuppliedOptions {
    /// Collect the options of `command` that `matches` shows were
    /// supplied on the command line.
    pub fn from_matches(command: &Command, matches: &ArgMatches) -> Self {
        let mut supplied = BTreeMap::new();
        for arg in command.get_arguments() {
            let Some(long_name) = arg.get_long() else {
                continue;
            };
            if matches.value_source(arg_id(arg)) != Some(ValueSource::CommandLine) {
                continue;
            }
            let values = match arg.get_action().takes_values() {
                true => matches
                    .get_raw(arg_id(arg))
                    .into_iter()
                    .flatten()
                    .map(ToOwned::to_owned)
                    .collect(),
                false => Vec::new(),
            };
            supplied.insert(long_name.to_owned(), values);
        }
        Self(supplied)
    }

    /// Supply the option of `command` named `long_name`, replacing any
    /// supplied with that name or one that conflicts with it.
    pub fn set(&mut self, command: &Command, long_name: &str, values: Vec<OsString>) {
        for conflicting in conflicting_long_names(command, long_name) {
            self.0.remove(&conflicting);
        }
        self.0.insert(long_name.to_owned(), values);
    }

    /// Stop supplying the option named `long_name`. Returns false
    /// if that option was not supplied.
    pub fn remove(&mut self, long_name: &str) -> bool {
        self.0.remove(long_name).is_some()
    }

    /// Supply each of the options in `other`, as by [`Self::set`].
    pub fn update(&mut self, command: &Command, other: &Self) {
        for (long_name, values) in &other.0 {
            self.set(command, long_name, values.clone());
        }
    }

    /// Write these options as a command line.
    pub fn command_line(&self) -> Vec<OsString> {
        let mut words = vec![OsString::from(PREFIX)];
        for (long_name, values) in &self.0 {
            if values.is_empty() {
                words.push(OsString::from(format!("--{long_name}")));
            }
            for value in values {
                let mut word = OsString::from(format!("--{long_name}="));
                word.push(value);
                words.push(word);
            }
        }
        words
    }
}

/// List the long names of the options of `command` that conflict with
/// the option named `long_name`.
fn conflicting_long_names(command: &Command, long_name: &str) -> Vec<String> {
    let mut names = Vec::new();
    for arg in command.get_arguments() {
        for other in command.get_arg_conflicts_with(arg) {
            if arg.get_long() == Some(long_name) {
                names.extend(other.get_long().map(str::to_owned));
            }
            if other.get_long() == Some(long_name) {
                names.extend(arg.get_long().map(str::to_owned));
            }
        }
    }
    names
}

/// Show the values of `arg` in `matches`, hiding secrets.
fn display_values(arg: &Arg, matches: &ArgMatches) -> String {
    if arg.is_hide_env_values_set() {
        return "(hidden)".to_owned();
    }
    if !arg.get_action().takes_values() {
        return matches.get_flag(arg_id(arg)).to_string();
    }
    let values = matches.get_raw(arg_id(arg)).into_iter().flatten();
    let values = values
        .map(|value| value.to_string_lossy())
        .collect::<Vec<_>>();
    values.join(", ")
}

fn arg_id(arg: &Arg) -> &str {
    arg.get_id().as_str()
}

fn arg_values(value: Value) -> Option<Vec<String>> {
    let scalar = |value| match value {
        Value::String(value) => Some(value),
        Value::Integer(value) => Some(value.to_string()),
        Value::Boolean(value) => Some(value.to_string()),
        _ => None,
    };
    match value {
        Value::Array(values) => values.into_iter().map(scalar).collect(),
        value => scalar(value).map(|value| vec![value]),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("can't read {path}: {error}", path = path.display())]
    Read { path: PathBuf, error: io::Error },
    #[error("can't parse {path}: {error}", path = path.display())]
    Parse {
        path: PathBuf,
        error: toml::de::Error,
    },
    #[error("no profile `{profile}` in {path}", path = path.display())]
    UnknownProfile { path: PathBuf, profile: String },
    #[error("no {FILE_NAME} found for profile `{0}`")]
    NoFile(String),
    #[error(
        "`{key}` in {path} must be a string, integer, boolean, or array",
        path = path.display()
    )]
    InvalidValue { path: PathBuf, key: String },
    #[error(
        "unknown key `{key}` in {path}, try one of: {}",
        valid_keys.join(", "),
        path = path.display()
    )]
    UnknownKey {
        path: PathBuf,
        key: String,
        valid_keys: Vec<String>,
    },
}

#[cfg(test)]
mod test {
    use std::env::{remove_var, set_var};
    use std::fs::write;
    use std::iter::once;

    use rusty_fork::rusty_fork_test;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::commands::{SUSH_CONFIG, SUSH_NEXUS, SUSH_PROFILE, SUSH_PROXY_ROOT, SUSH_URL};
    use crate::context::OutputFormat;

    /// Parse `words` with the config file `text`, after unsetting every
    /// option's environment variable and then setting those in `env`.
    fn parse(text: &str, env: &[(&str, &str)], words: &str) -> Result<ArgMatches, CommandError> {
        // SAFETY: `rusty_fork_test!` runs each test alone in its own
        // process, so no other thread reads the environment while this
        // function writes it.
        fn unset(command: &Command) {
            for arg in command.get_arguments() {
                if let Some(var) = arg.get_env() {
                    unsafe { remove_var(var) }
                }
            }
            for subcommand in command.get_subcommands() {
                unset(subcommand);
            }
        }
        unset(&ClientArgs::command());
        let file = NamedTempFile::new().unwrap();
        write(file.path(), text).unwrap();
        unsafe { set_var(SUSH_CONFIG, file.path()) }
        for (var, value) in env {
            unsafe { set_var(var, value) }
        }
        let words = ["sush"].into_iter().chain(words.split_whitespace());
        parse_and_merge_config(ClientArgs::command(), words)
    }

    fn globals(text: &str, env: &[(&str, &str)], words: &str) -> GlobalArgs {
        GlobalArgs::from_arg_matches(&parse(text, env, words).unwrap()).unwrap()
    }

    /// Collect the global options supplied in `words`, ignoring the
    /// environment.
    fn supplied(words: &str) -> SuppliedOptions {
        let command = map_command_tree(GlobalArgs::command(), &|command| {
            command.mut_args(|arg| arg.env(None))
        });
        let words = once("sush").chain(words.split_whitespace());
        let matches = command.clone().try_get_matches_from(words).unwrap();
        SuppliedOptions::from_matches(&command, &matches)
    }

    fn command_line(supplied: &SuppliedOptions) -> Vec<String> {
        let words = supplied.command_line().into_iter();
        words.map(|word| word.into_string().unwrap()).collect()
    }

    /// Supplied options come back out as a command line with a flag, a
    /// value, and a repeated value, and that command line parses back to
    /// the same options.
    #[test]
    fn supplied_command_line() {
        let options = supplied("--offline --rack r --nexus-root a.pem --nexus-root b.pem");
        let words = [
            "sush",
            "--nexus-root=a.pem",
            "--nexus-root=b.pem",
            "--offline",
            "--rack=r",
        ];
        assert_eq!(command_line(&options), words);
        assert_eq!(command_line(&supplied(&words[1..].join(" "))), words);
    }

    /// Supplying an option replaces any supplied option that conflicts
    /// with it, in either direction, and keeps the rest.
    #[test]
    fn supplied_update() {
        let command = GlobalArgs::command();
        let mut options = supplied("--nexus https://nexus --rack r");
        options.update(&command, &supplied("--url https://url"));
        assert_eq!(
            command_line(&options),
            ["sush", "--rack=r", "--url=https://url"],
            "url replaces nexus, which declares the conflict"
        );
        options.update(&command, &supplied("--offline"));
        assert_eq!(
            command_line(&options),
            ["sush", "--offline", "--rack=r"],
            "offline replaces url"
        );
        options.update(&command, &supplied("--rack s"));
        assert_eq!(
            command_line(&options),
            ["sush", "--offline", "--rack=s"],
            "a new value replaces the old"
        );
    }

    rusty_fork_test! {
        /// The file's `profile` key selects a profile, and `--profile` or
        /// `SUSH_PROFILE` overrides that choice.
        #[test]
        fn profiles() {
            let text = r#"
                profile = "a"
                [a]
                rack = "a"
                [b]
                rack = "b"
            "#;
            let rack = |env, words| globals(text, env, words).rack;
            assert_eq!(rack(&[], "version").as_deref(), Some("a"));
            assert_eq!(rack(&[], "--profile b version").as_deref(), Some("b"));
            assert_eq!(
                rack(&[(SUSH_PROFILE, "b")], "version").as_deref(),
                Some("b")
            );
            assert!(matches!(
                parse(text, &[], "--profile c version"),
                Err(CommandError::Config(ConfigError::UnknownProfile { .. }))
            ));
        }

        /// Each source overrides the ones below it: the command line, the
        /// environment, the selected profile, the file's top level, and the
        /// built-in default.
        #[test]
        fn precedence() {
            let text = r#"
                profile = "dublin"
                rack = "top"
                ssh-auth-sock = "top"
                proxy-root = "file.pem"
                [dublin]
                ssh-auth-sock = "profile"
                url = "https://file"
                nexus-root = ["a.pem", "b.pem"]
            "#;
            let env = [(SUSH_URL, "https://env"), (SUSH_PROXY_ROOT, "env.pem")];
            let globals = globals(text, &env, "--proxy-root cli.pem version");
            assert_eq!(
                globals.output,
                Some(OutputFormat::Text),
                "the built-in default applies when nothing else sets the option"
            );
            assert_eq!(
                globals.rack.as_deref(),
                Some("top"),
                "the top level applies when the profile does not set the option"
            );
            assert_eq!(
                globals.ssh_auth_sock.as_deref(),
                Some("profile"),
                "the profile overrides the top level"
            );
            assert_eq!(
                globals.nexus_roots,
                [PathBuf::from("a.pem"), PathBuf::from("b.pem")],
                "the profile sets every element of an array"
            );
            assert_eq!(
                globals.url.as_deref(),
                Some("https://env"),
                "the environment overrides the profile"
            );
            assert_eq!(
                globals.proxy_roots,
                [PathBuf::from("cli.pem")],
                "the command line overrides the environment and the top level"
            );
        }

        /// The file can set a subcommand's options, and the command line can
        /// override one of them while the others keep the file's values.
        #[cfg(feature = "permslip")]
        #[test]
        fn subcommand_options() {
            let text = r#"
                permslip-key = "Key"
                permslip-url = "https://permslip"
            "#;
            let start = |words| {
                let matches = parse(text, &[], words).unwrap();
                let start = matches
                    .subcommand_matches("job")
                    .and_then(|job| job.subcommand_matches("start"))
                    .unwrap();
                let get = |id| start.get_one::<String>(id).cloned();
                (get("permslip_key"), get("permslip_url"))
            };
            assert_eq!(
                start("job start uptime"),
                (Some("Key".to_owned()), Some("https://permslip".to_owned()))
            );
            assert_eq!(
                start("job start --permslip-url https://other uptime"),
                (Some("Key".to_owned()), Some("https://other".to_owned()))
            );
        }

        /// Of two conflicting options, the one from the stronger source wins.
        #[test]
        fn conflicts() {
            let reach = |text, env, words| {
                let GlobalArgs {
                    offline,
                    url,
                    nexus,
                    ..
                } = globals(text, env, words);
                (offline, url, nexus)
            };
            let url = || Some("https://url".to_owned());
            let nexus = || Some("https://nexus".to_owned());

            let file_url = r#"url = "https://url""#;
            assert_eq!(
                reach(file_url, &[], "--nexus https://nexus version"),
                (false, None, nexus()),
                "the command line beats the file"
            );
            assert_eq!(
                reach(file_url, &[], "--offline version"),
                (true, None, None),
                "offline beats a configured url"
            );
            assert_eq!(
                reach(file_url, &[(SUSH_NEXUS, "https://nexus")], "version"),
                (false, None, nexus()),
                "the environment beats the file"
            );
            assert_eq!(
                reach(
                    "",
                    &[(SUSH_NEXUS, "https://nexus")],
                    "--url https://url version"
                ),
                (false, url(), None),
                "the command line beats the environment"
            );
            assert!(
                parse("", &[], "--nexus https://nexus --url https://url version").is_err(),
                "conflicts from one source are errors"
            );

            let output = |text, words| globals(text, &[], words).output_format();
            let file_json = r#"output = "json""#;
            assert_eq!(
                output(file_json, "version"),
                Some(OutputFormat::Json),
                "the file beats the built-in default"
            );
            assert_eq!(
                output(file_json, "--text version"),
                Some(OutputFormat::Text),
                "the command line beats the file"
            );
        }

        /// The file rejects keys for secrets, keys for options without an
        /// environment variable, and keys that name no option.
        #[test]
        fn invalid_keys() {
            for (text, bad) in [
                (r#"nexus-token = "secret""#, "nexus-token"),
                ("[rack]\nurll = \"https://url\"", "urll"),
                ("force = true", "force"),
            ] {
                assert!(
                    matches!(
                        parse(text, &[], "version"),
                        Err(CommandError::Config(ConfigError::UnknownKey { key, .. })) if key == bad
                    ),
                    "the file rejects `{bad}`"
                );
            }
        }
    }
}
