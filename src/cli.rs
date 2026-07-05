// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Command-line parsing.
//!
//! Supports `-name value`, `-name=value`, and the `--` variants; boolean flags
//! take no argument unless `=value` is given. Crucially it records which flags
//! were *explicitly set* so the tri-state `boguspriv`/`block_svcb` precedence
//! (CLI > file > default) can be reproduced.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlagKind {
    Str,
    Int,
    Bool,
}

const FLAGS: &[(&str, FlagKind)] = &[
    ("dns", FlagKind::Str),
    ("fall", FlagKind::Str),
    ("listen", FlagKind::Str),
    ("force_fall", FlagKind::Str),
    ("qtime", FlagKind::Int),
    ("aaaa", FlagKind::Str),
    ("trust_rcode", FlagKind::Str),
    ("lite", FlagKind::Str),
    ("d", FlagKind::Bool),
    ("debug", FlagKind::Bool),
    ("config", FlagKind::Str),
    ("version", FlagKind::Bool),
    ("boguspriv", FlagKind::Bool),
    ("block_svcb", FlagKind::Bool),
    ("lease_file", FlagKind::Str),
    ("hosts_file", FlagKind::Str),
    ("pplog_server", FlagKind::Str),
    ("pplog_uuid", FlagKind::Str),
    ("pplog_level", FlagKind::Int),
];

fn kind_of(name: &str) -> Option<FlagKind> {
    FLAGS.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
}

/// Parse a boolean accepting the common true/false/1/0 forms.
fn parse_go_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Raw parsed flags: string values keyed by flag name, plus the set of flags
/// that were explicitly present on the command line.
#[derive(Debug, Default)]
pub struct RawArgs {
    values: HashMap<String, String>,
    seen: HashSet<String>,
}

impl RawArgs {
    pub fn was_set(&self, name: &str) -> bool {
        self.seen.contains(name)
    }

    /// The raw string value for a flag if it was present (may be empty; callers
    /// that want to treat empty as absent wrap this in `nonempty`).
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }

    pub fn get_int(&self, name: &str) -> Option<i64> {
        self.values.get(name).and_then(|s| s.parse().ok())
    }

    /// Boolean value for a flag that was set (`-flag` stores "true").
    pub fn get_bool(&self, name: &str) -> Option<bool> {
        self.values.get(name).and_then(|s| parse_go_bool(s))
    }
}

/// Parse an argument iterator (excluding the program name).
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<RawArgs, String> {
    let argv: Vec<String> = args.into_iter().collect();
    let mut out = RawArgs::default();
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        // Non-flag token, bare "-", or "--" terminate flag parsing.
        if tok == "--" || tok == "-" || !tok.starts_with('-') {
            break;
        }
        let stripped = if let Some(s) = tok.strip_prefix("--") {
            s
        } else {
            &tok[1..]
        };
        let (name, inline_val) = match stripped.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (stripped, None),
        };

        let kind =
            kind_of(name).ok_or_else(|| format!("flag provided but not defined: -{name}"))?;

        let value = match kind {
            FlagKind::Bool => match inline_val {
                Some(v) => {
                    if parse_go_bool(&v).is_none() {
                        return Err(format!("invalid boolean value {v:?} for -{name}"));
                    }
                    v
                }
                None => "true".to_string(),
            },
            FlagKind::Str | FlagKind::Int => {
                let v = match inline_val {
                    Some(v) => v,
                    None => {
                        i += 1;
                        argv.get(i)
                            .cloned()
                            .ok_or_else(|| format!("flag needs an argument: -{name}"))?
                    }
                };
                if kind == FlagKind::Int && v.parse::<i64>().is_err() {
                    return Err(format!("invalid value {v:?} for flag -{name}: parse error"));
                }
                v
            }
        };

        out.values.insert(name.to_string(), value);
        out.seen.insert(name.to_string());
        i += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn basic_forms() {
        let r = parse(args(&[
            "-dns",
            "10.10.10.8",
            "--fall=223.5.5.5",
            "-qtime",
            "300",
            "-debug",
            "-boguspriv=false",
        ]))
        .unwrap();
        assert_eq!(r.get_str("dns"), Some("10.10.10.8"));
        assert_eq!(r.get_str("fall"), Some("223.5.5.5"));
        assert_eq!(r.get_int("qtime"), Some(300));
        assert!(r.was_set("debug"));
        assert_eq!(r.get_bool("debug"), Some(true));
        assert!(r.was_set("boguspriv"));
        assert_eq!(r.get_bool("boguspriv"), Some(false));
        // Untouched tri-state flag reads as not-set.
        assert!(!r.was_set("block_svcb"));
    }

    #[test]
    fn negative_int_and_commas() {
        let r = parse(args(&[
            "-qtime",
            "-5",
            "-force_fall",
            "192.168.1.10,^192.168.2.0/24",
        ]))
        .unwrap();
        assert_eq!(r.get_int("qtime"), Some(-5));
        assert_eq!(
            r.get_str("force_fall"),
            Some("192.168.1.10,^192.168.2.0/24")
        );
    }

    #[test]
    fn errors() {
        assert!(parse(args(&["-nope"])).is_err()); // unknown
        assert!(parse(args(&["-dns"])).is_err()); // missing arg
        assert!(parse(args(&["-qtime", "abc"])).is_err()); // bad int
        assert!(parse(args(&["-debug=maybe"])).is_err()); // bad bool
    }

    #[test]
    fn stops_at_terminator() {
        let r = parse(args(&["-debug", "--", "-dns", "ignored"])).unwrap();
        assert!(r.was_set("debug"));
        assert!(!r.was_set("dns"));
    }
}
