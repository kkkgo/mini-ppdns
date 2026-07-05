// Copyright (c) 2026, https://blog.03k.org. All rights reserved.

//! Configuration model + INI parser.
//!
//! The parser is hand-rolled (not a generic INI crate) to match the original
//! exactly: repeated lines accumulate, `[hook]` values are quote-trimmed,
//! inline `#` comments are stripped in `[hosts]`, a leading UTF-8 BOM is
//! dropped, and section names strip exactly one bracket per side.

use std::collections::HashMap;
use std::net::IpAddr;

/// Fully-resolved configuration (after CLI + file merge). The `*_set` flags
/// track whether a tri-state boolean was explicitly present in the file so the
/// CLI-vs-file-vs-default precedence can be applied by the caller.
#[derive(Debug, Clone)]
pub struct Config {
    pub dns: Vec<String>,
    pub fall: Vec<String>,
    pub listen: Vec<String>,
    pub force_fall: Vec<String>,
    pub qtime: i64,
    pub aaaa: String,
    pub lite: String,
    pub trust_rcode: Vec<i32>,
    pub daemon: bool,
    pub debug: bool,

    pub lease_file: Vec<String>,
    pub hosts_file: Vec<String>,
    pub boguspriv: bool,
    pub boguspriv_set: bool,
    pub block_svcb: bool,
    pub block_svcb_set: bool,

    pub pplog_uuid: String,
    pub pplog_server: String,
    pub pplog_level: i64,
    pub pplog_heart_beat: i64,

    pub hosts: HashMap<String, Vec<IpAddr>>,
    pub hook: Option<HookConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dns: Vec::new(),
            fall: Vec::new(),
            listen: Vec::new(),
            force_fall: Vec::new(),
            qtime: 250,
            aaaa: "no".to_string(),
            lite: "yes".to_string(),
            trust_rcode: Vec::new(),
            daemon: false,
            debug: false,
            lease_file: Vec::new(),
            hosts_file: Vec::new(),
            boguspriv: true,
            boguspriv_set: false,
            block_svcb: true,
            block_svcb_set: false,
            pplog_uuid: String::new(),
            pplog_server: String::new(),
            pplog_level: 0,
            pplog_heart_beat: 0,
            hosts: HashMap::new(),
            hook: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HookConfig {
    pub exec: String,
    pub exit_code: i32,
    pub exit_code_set: bool,
    pub keyword: String,
    pub sleep_time: i64,
    pub retry_time: i64,
    pub count: i64,
    pub switch_fall_exec: String,
    pub switch_main_exec: String,
}

impl Default for HookConfig {
    fn default() -> Self {
        HookConfig {
            exec: String::new(),
            exit_code: 0,
            exit_code_set: false,
            keyword: String::new(),
            sleep_time: 60,
            retry_time: 5,
            count: 10,
            switch_fall_exec: String::new(),
            switch_main_exec: String::new(),
        }
    }
}

/// Parse an INI file into `cfg`, appending collection entries and overwriting
/// scalar keys. Non-fatal issues are pushed onto `warnings`.
pub fn parse_ini(path: &str, cfg: &mut Config, warnings: &mut Vec<String>) -> std::io::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    // Drop a leading UTF-8 BOM if present (Windows editors add it).
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);

    let mut section = String::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // Strip exactly one bracket per side.
            section = line[1..line.len() - 1].to_string();
            continue;
        }

        match section.as_str() {
            "dns" => cfg.dns.push(line.to_string()),
            "fall" => cfg.fall.push(line.to_string()),
            "listen" => cfg.listen.push(line.to_string()),
            "force_fall" => cfg.force_fall.push(line.to_string()),
            "adv" => parse_adv(line, cfg, warnings),
            "hosts" => parse_hosts(line, cfg, warnings),
            "pplog" => parse_pplog(line, cfg, warnings),
            "hook" => parse_hook(line, cfg, warnings),
            other => warnings.push(format!("unknown config section, ignored: {other}")),
        }
    }
    Ok(())
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    line.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
}

fn parse_bool_word(v: &str) -> bool {
    let lv = v.to_ascii_lowercase();
    lv == "1" || lv == "yes" || lv == "true"
}

fn parse_adv(line: &str, cfg: &mut Config, warnings: &mut Vec<String>) {
    let Some((k, v)) = split_kv(line) else { return };
    match k {
        "qtime" => match v.parse::<i64>() {
            Ok(n) => cfg.qtime = n,
            Err(_) => warnings.push(format!("invalid qtime value, using default: {v}")),
        },
        "aaaa" => cfg.aaaa = v.to_string(),
        "lite" => cfg.lite = v.to_string(),
        "trust_rcode" => {
            cfg.trust_rcode.clear();
            for s in v.split(',') {
                let s = s.trim();
                if s.is_empty() {
                    continue;
                }
                match s.parse::<i32>() {
                    Ok(n) => cfg.trust_rcode.push(n),
                    Err(_) => warnings.push(format!("invalid trust_rcode value, skipping: {s}")),
                }
            }
        }
        "boguspriv" => {
            cfg.boguspriv = parse_bool_word(v);
            cfg.boguspriv_set = true;
        }
        "block_svcb" => {
            cfg.block_svcb = parse_bool_word(v);
            cfg.block_svcb_set = true;
        }
        "lease_file" => append_csv(&mut cfg.lease_file, v),
        "hosts_file" => append_csv(&mut cfg.hosts_file, v),
        _ => warnings.push(format!("unknown config key in [adv], ignored: {k}")),
    }
}

fn append_csv(dst: &mut Vec<String>, v: &str) {
    for item in v.split(',') {
        let item = item.trim();
        if !item.is_empty() {
            dst.push(item.to_string());
        }
    }
}

fn parse_hosts(line: &str, cfg: &mut Config, warnings: &mut Vec<String>) {
    // Strip inline comment before tokenizing.
    let hosts_line = match line.split_once('#') {
        Some((head, _)) => head,
        None => line,
    };
    let fields: Vec<&str> = hosts_line.split_whitespace().collect();
    if fields.len() < 2 {
        return;
    }
    let ip: IpAddr = match fields[0].parse() {
        Ok(ip) => ip,
        Err(_) => {
            warnings.push(format!("invalid hosts IP, skipping: {line}"));
            return;
        }
    };
    for domain in &fields[1..] {
        if *domain == "*" || domain.is_empty() {
            continue;
        }
        let base = domain
            .strip_suffix('.')
            .unwrap_or(domain)
            .to_ascii_lowercase();
        let key = format!("{base}.");
        cfg.hosts.entry(key).or_default().push(ip);
    }
}

fn parse_pplog(line: &str, cfg: &mut Config, warnings: &mut Vec<String>) {
    let Some((k, v)) = split_kv(line) else { return };
    match k {
        "uuid" => cfg.pplog_uuid = v.to_string(),
        "server" => cfg.pplog_server = v.to_string(),
        "level" => match v.parse::<i64>() {
            Ok(n) => cfg.pplog_level = n,
            Err(_) => warnings.push(format!("invalid pplog level value, using default: {v}")),
        },
        "heart_beat" => match v.parse::<i64>() {
            Ok(n) if n >= 0 => cfg.pplog_heart_beat = n,
            _ => warnings.push(format!("invalid pplog heart_beat value, ignoring: {v}")),
        },
        _ => warnings.push(format!("unknown config key in [pplog], ignored: {k}")),
    }
}

fn parse_hook(line: &str, cfg: &mut Config, warnings: &mut Vec<String>) {
    let Some((k, raw)) = split_kv(line) else {
        return;
    };
    // Trim surrounding double quotes.
    let v = raw.trim_matches('"');
    let hook = cfg.hook.get_or_insert_with(HookConfig::default);
    match k {
        "exec" => hook.exec = v.to_string(),
        "exit_code" => match v.parse::<i32>() {
            Ok(n) => {
                hook.exit_code = n;
                hook.exit_code_set = true;
            }
            Err(_) => warnings.push(format!("invalid hook exit_code value: {v}")),
        },
        "keyword" => hook.keyword = v.to_string(),
        "sleep_time" => match v.parse::<i64>() {
            Ok(n) if n > 0 => hook.sleep_time = n,
            _ => warnings.push(format!("invalid hook sleep_time value, using default: {v}")),
        },
        "retry_time" => match v.parse::<i64>() {
            Ok(n) if n > 0 => hook.retry_time = n,
            _ => warnings.push(format!("invalid hook retry_time value, using default: {v}")),
        },
        "count" => match v.parse::<i64>() {
            Ok(n) if n > 0 => hook.count = n,
            _ => warnings.push(format!("invalid hook count value, using default: {v}")),
        },
        "switch_fall_exec" => hook.switch_fall_exec = v.to_string(),
        "switch_main_exec" => hook.switch_main_exec = v.to_string(),
        _ => warnings.push(format!("unknown config key in [hook], ignored: {k}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse_str(contents: &str) -> (Config, Vec<String>) {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "mini-ppdns-test-{}-{:p}.ini",
            std::process::id(),
            contents as *const _
        );
        path.push(unique);
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(contents.as_bytes()).unwrap();
        }
        let mut cfg = Config::default();
        let mut warnings = Vec::new();
        parse_ini(path.to_str().unwrap(), &mut cfg, &mut warnings).unwrap();
        let _ = std::fs::remove_file(&path);
        (cfg, warnings)
    }

    #[test]
    fn full_config() {
        let ini = "\u{feff}# comment\n\
            [dns]\n10.10.10.8:53\n10.10.10.9:53\n\
            [fall]\n223.5.5.5:53\n\
            [listen]\n127.0.0.1:53\n\
            [force_fall]\n192.168.1.10\n^192.168.10.0/24\n\
            [adv]\nqtime=300\naaaa=noerror\nlite=no\ntrust_rcode=0,3\nboguspriv=0\nblock_svcb=no\nlease_file=/tmp/a.leases,/tmp/b.leases\n\
            [hosts]\n1.2.3.4 example.com ALIAS.example.com # inline\n\
            [pplog]\nuuid=abc\nserver=192.168.1.100:9999\nlevel=3\nheart_beat=60\n\
            [hook]\nexec=\"curl -s http://x/\"\nexit_code=0\nkeyword=\"204\"\nsleep_time=30\ncount=5\n";
        let (cfg, warnings) = parse_str(ini);

        assert_eq!(cfg.dns, ["10.10.10.8:53", "10.10.10.9:53"]);
        assert_eq!(cfg.fall, ["223.5.5.5:53"]);
        assert_eq!(cfg.listen, ["127.0.0.1:53"]);
        assert_eq!(cfg.force_fall, ["192.168.1.10", "^192.168.10.0/24"]);
        assert_eq!(cfg.qtime, 300);
        assert_eq!(cfg.aaaa, "noerror");
        assert_eq!(cfg.lite, "no");
        assert_eq!(cfg.trust_rcode, [0, 3]);
        assert!(!cfg.boguspriv && cfg.boguspriv_set);
        assert!(!cfg.block_svcb && cfg.block_svcb_set);
        assert_eq!(cfg.lease_file, ["/tmp/a.leases", "/tmp/b.leases"]);

        // hosts: inline comment stripped; both aliases mapped, lower-cased + fqdn.
        assert_eq!(cfg.hosts.get("example.com.").map(|v| v.len()), Some(1),);
        assert!(cfg.hosts.contains_key("alias.example.com."));

        assert_eq!(cfg.pplog_uuid, "abc");
        assert_eq!(cfg.pplog_server, "192.168.1.100:9999");
        assert_eq!(cfg.pplog_level, 3);
        assert_eq!(cfg.pplog_heart_beat, 60);

        let hook = cfg.hook.expect("hook present");
        assert_eq!(hook.exec, "curl -s http://x/"); // quotes trimmed
        assert!(hook.exit_code_set && hook.exit_code == 0);
        assert_eq!(hook.keyword, "204");
        assert_eq!(hook.sleep_time, 30);
        assert_eq!(hook.count, 5);
        assert_eq!(hook.retry_time, 5); // default preserved

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn unknown_section_and_key_warn() {
        let (_, warnings) = parse_str("[mystery]\nfoo=bar\n[adv]\nbogus_key=1\n");
        assert!(warnings
            .iter()
            .any(|w| w.contains("unknown config section")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("unknown config key in [adv]")));
    }
}
