//! The commands: login, exec, logout and list.

use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, ExitStatus},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
};

use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2},
    iterator::Signals,
    low_level,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    app::{
        args::{ExecCommandArgs, ListCommandArgs, LoginCommandArgs, LogoutCommandArgs},
        note, warn,
    },
    vault::{
        auth::{self, basic::Prompt, CredentialState, LoginOutcome},
        config::{Config, Kind, Profile},
        nix::{self, netrc, proxy, render, session},
        store::{Credential, CredentialStore},
        Error, Result,
    },
};

/// Stores credentials for a profile.
pub struct LoginCommand {
    /// Where confirmations go.
    pub writer: Box<dyn Write>,
    /// The validated configuration.
    pub config: Config,
    /// Where credentials are kept.
    pub store: CredentialStore,
    /// How a username and password are asked for.
    pub prompt: Box<dyn Prompt>,
}

impl LoginCommand {
    /// Execute the LoginCommand with the provided arguments.
    pub fn execute(&mut self, args: &LoginCommandArgs) -> Result<()> {
        let profile = self.config.profile(&args.profile)?;
        match &profile.kind {
            Kind::Basic => {
                match auth::login_basic(profile, &self.store, args.force, self.prompt.as_ref())? {
                    LoginOutcome::Stored => writeln!(
                        self.writer,
                        "Stored credentials for {} ({}). They were not checked with the service.",
                        profile.name, profile.host
                    )?,
                    LoginOutcome::Reused | LoginOutcome::Refreshed => writeln!(
                        self.writer,
                        "Profile {} already has usable credentials; use --force to replace them.",
                        profile.name
                    )?,
                }
            }
            Kind::Process(_) => writeln!(
                self.writer,
                "Profile {} gets its credential from a command each time it is used; there is \
                 nothing to log in to here. Log in with that command's own tool, then run \
                 nix-vault exec.",
                profile.name
            )?,
            Kind::OAuth2(_) => {
                match auth::login_oauth(profile, &self.store, &args.parent.state_dir, args.force)? {
                    LoginOutcome::Stored => writeln!(
                        self.writer,
                        "Stored credentials for {} ({}).",
                        profile.name, profile.host
                    )?,
                    LoginOutcome::Refreshed => writeln!(
                        self.writer,
                        "Refreshed the credentials for {}.",
                        profile.name
                    )?,
                    LoginOutcome::Reused => writeln!(
                        self.writer,
                        "Profile {} already has usable credentials; use --force to log in again.",
                        profile.name
                    )?,
                }
            }
        }
        Ok(())
    }
}

/// Removes the stored credentials of a profile.
pub struct LogoutCommand {
    /// Where confirmations go.
    pub writer: Box<dyn Write>,
    /// The validated configuration.
    pub config: Config,
    /// Where credentials are kept.
    pub store: CredentialStore,
}

impl LogoutCommand {
    /// Execute the LogoutCommand with the provided arguments.
    pub fn execute(&mut self, args: &LogoutCommandArgs) -> Result<()> {
        let profile = self.config.profile(&args.profile)?;
        if matches!(profile.kind, Kind::Process(_)) {
            writeln!(
                self.writer,
                "Profile {} stores no credentials: it gets them from a command. Nothing was \
                 removed.",
                profile.name
            )?;
            return Ok(());
        }
        if self.store.remove(&profile.name)? {
            writeln!(
                self.writer,
                "Removed the stored credentials for {}. They are not revoked at the service.",
                profile.name
            )?;
        } else {
            writeln!(
                self.writer,
                "No stored credentials for {}. Nothing was revoked at the service.",
                profile.name
            )?;
        }
        Ok(())
    }
}

/// Shows profiles and the state of their credentials.
pub struct ListCommand {
    /// Where the table goes.
    pub writer: Box<dyn Write>,
    /// The validated configuration.
    pub config: Config,
    /// Where credentials are kept.
    pub store: CredentialStore,
    /// The current time, for expiry.
    pub now: OffsetDateTime,
}

impl ListCommand {
    /// Execute the ListCommand with the provided arguments.
    pub fn execute(&mut self, _args: &ListCommandArgs) -> Result<()> {
        let mut rows = vec![[
            "PROFILE".to_string(),
            "HOST".to_string(),
            "TYPE".to_string(),
            "CREDENTIALS".to_string(),
            "EXPIRES".to_string(),
        ]];
        for profile in &self.config.profiles {
            if matches!(profile.kind, Kind::Process(_)) {
                // Running the command to find out would be a side effect of a listing
                rows.push([
                    profile.name.clone(),
                    profile.host.clone(),
                    profile.type_name().to_string(),
                    "from a command".to_string(),
                    "-".to_string(),
                ]);
                continue;
            }
            let stored = self.store.load(&profile.name)?;
            let state = auth::state(profile, stored.as_ref(), self.now);
            let refreshable = stored
                .as_ref()
                .and_then(|s| s.oauth2.as_ref())
                .is_some_and(|o| o.refresh_token.is_some());
            let credentials = match state {
                CredentialState::Absent => "no",
                CredentialState::StaleIdentity => "login again (changed)",
                CredentialState::Expired => "expired",
                CredentialState::Expiring => "stored (refreshable)",
                CredentialState::Usable if refreshable => "stored (refreshable)",
                CredentialState::Usable => "stored",
            };
            let expires = match state {
                CredentialState::Absent | CredentialState::StaleIdentity => None,
                _ => stored
                    .as_ref()
                    .and_then(|s| s.oauth2.as_ref())
                    .and_then(|o| o.expires_at),
            };
            rows.push([
                profile.name.clone(),
                profile.host.clone(),
                profile.type_name().to_string(),
                credentials.to_string(),
                expires
                    .and_then(|t| t.format(&Rfc3339).ok())
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        let widths: Vec<usize> = (0..5)
            .map(|c| rows.iter().map(|r| r[c].len()).max().unwrap_or(0))
            .collect();
        for row in &rows {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i + 1 == row.len() {
                    line.push_str(cell);
                } else {
                    line.push_str(&format!("{:<width$}  ", cell, width = widths[i]));
                }
            }
            writeln!(self.writer, "{line}")?;
        }
        Ok(())
    }
}

/// Runs a command with the credentials of the selected profiles available to Nix.
pub struct ExecCommand {
    /// The validated configuration.
    pub config: Config,
    /// Where credentials are kept.
    pub store: CredentialStore,
}

impl ExecCommand {
    /// Execute the ExecCommand with the provided arguments. Returns how the command ended, after
    /// the session was removed.
    pub fn execute(&mut self, args: &ExecCommandArgs) -> Result<ExitStatus> {
        if args.profiles.is_empty() {
            return Err(Error::usage(
                "exec needs at least one --profile (-p); profiles are never selected implicitly",
            ));
        }
        if args.command.is_empty() {
            return Err(Error::usage("exec needs a command after `--`"));
        }

        // Selection: resolve, deduplicate keeping first-seen order
        let mut selected: Vec<&Profile> = Vec::new();
        for name in &args.profiles {
            let profile = self.config.profile(name)?;
            if !selected.iter().any(|p| p.name == profile.name) {
                selected.push(profile);
            }
        }

        // Credentials: only the selected profiles are read
        let now = OffsetDateTime::now_utc();
        let mut credentials: Vec<(&Profile, Credential)> = Vec::new();
        let mut problems: Vec<Error> = Vec::new();
        for profile in &selected {
            if matches!(profile.kind, Kind::Process(_)) {
                // Not stored: the command is asked each time. Its own messages are on the
                // terminal, so a failure here is reported once, by name
                match auth::process::acquire(profile) {
                    Ok(credential) => credentials.push((profile, credential)),
                    Err(e) => problems.push(e),
                }
                continue;
            }
            let stored = self.store.load(&profile.name)?;
            match auth::state(profile, stored.as_ref(), now) {
                CredentialState::Usable => credentials.push((profile, stored.expect("usable"))),
                CredentialState::Expiring => {
                    match auth::refresh_profile(profile, &self.store, &args.parent.state_dir) {
                        Ok(credential) => credentials.push((profile, credential)),
                        Err(e) => problems.push(e),
                    }
                }
                CredentialState::Absent => problems.push(Error::NoCredentials {
                    profile: profile.name.clone(),
                    detail: None,
                }),
                CredentialState::StaleIdentity => problems.push(Error::NoCredentials {
                    profile: profile.name.clone(),
                    detail: Some("its host or OAuth client changed since the last login".into()),
                }),
                CredentialState::Expired => problems.push(Error::NoCredentials {
                    profile: profile.name.clone(),
                    detail: Some("expired and cannot be refreshed".into()),
                }),
            }
        }
        if let Some(last) = problems.pop() {
            for problem in &problems {
                eprintln!("error: {problem}");
            }
            return Err(last);
        }

        // Plan: what to present to Nix, rejecting conflicts before anything is launched
        let (mut plan, specs) = build_plan(&credentials)?;

        // The user's own Nix settings, which must be preserved
        let nix_config = nix::effective_config()?;
        let existing_netrc = if plan.netrc.is_empty() {
            Vec::new()
        } else {
            read_existing_netrc(&nix_config.netrc_file)
        };
        announce_replacements(&credentials, &nix_config.access_tokens, &existing_netrc);

        // Proxied hosts: one local proxy each, and Nix is pointed at it instead of the host
        let mut proxies: Vec<proxy::Proxy> = Vec::new();
        let mut env: Vec<(String, String)> = Vec::new();
        if !specs.is_empty() {
            let mut list = nix_config.substituters.clone();
            for spec in specs {
                let started = proxy::Proxy::start(proxy::Target {
                    base: format!("https://{}", spec.host),
                    headers: spec.headers,
                })?;
                list = nix::point_at_proxy(&list, &spec.host, started.url());
                for name in &spec.profiles {
                    env.push((proxy_env_name(name), started.url().to_string()));
                }
                note(format!(
                    "{} is served through a local proxy that adds its credentials; Nix uses it \
                     for substitution (the address is in ${})",
                    spec.host,
                    proxy_env_name(&spec.profiles[0])
                ));
                proxies.push(started);
            }
            plan.substituters = Some(list);
        }

        let (session, conf_path) =
            session::build(&session::base_dir(), &plan, &nix_config, &existing_netrc)?;

        let include = format!("!include {}", conf_path.display());
        let nix_config_value = match std::env::var("NIX_CONFIG") {
            Ok(mut existing) if !existing.is_empty() => {
                if !existing.ends_with('\n') {
                    existing.push('\n');
                }
                existing + &include
            }
            _ => include,
        };
        run_child(&args.command, &nix_config_value, session, &env, proxies)
    }
}

/// What the proxy for one host needs: the profiles that use it and the headers it adds.
struct ProxySpec {
    host: String,
    profiles: Vec<String>,
    headers: Vec<(String, crate::vault::auth::redact::Secret)>,
}

/// The variable that carries a proxied profile's local address to the command, so a command that
/// names the service itself (`nix copy --to "$NIX_VAULT_PROXY_CACHE"`) can use it.
fn proxy_env_name(profile: &str) -> String {
    let name: String = profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("NIX_VAULT_PROXY_{name}")
}

fn build_plan(credentials: &[(&Profile, Credential)]) -> Result<(session::Plan, Vec<ProxySpec>)> {
    let mut proxied: BTreeMap<String, ProxySpec> = BTreeMap::new();
    let mut fingerprints: BTreeMap<&str, (&str, String)> = BTreeMap::new();
    let mut tokens: BTreeMap<String, (String, crate::vault::auth::redact::Secret)> =
        BTreeMap::new();
    let mut netrc_entries: BTreeMap<String, (String, netrc::Entry)> = BTreeMap::new();

    for (profile, credential) in credentials {
        let fingerprint = render::account_fingerprint(credential);
        match fingerprints.get(profile.host.as_str()) {
            Some((other, existing)) if *existing != fingerprint => {
                return Err(Error::usage(format!(
                    "profiles \"{other}\" and \"{}\" would present different credentials for \
                     {}; select only one of them",
                    profile.name, profile.host
                )))
            }
            Some(_) => {}
            None => {
                fingerprints.insert(profile.host.as_str(), (profile.name.as_str(), fingerprint));
            }
        }
        let delivery = profile.delivery();
        if delivery.proxy {
            let headers = render::proxy_headers(profile, credential)?;
            proxied
                .entry(profile.host.clone())
                .and_modify(|spec| spec.profiles.push(profile.name.clone()))
                .or_insert_with(|| ProxySpec {
                    host: profile.host.clone(),
                    profiles: vec![profile.name.clone()],
                    headers,
                });
        }
        if delivery.access_token.is_some() {
            let (host, value) = render::access_token_entry(profile, credential)?;
            match tokens.get(&host) {
                Some((other, existing)) if existing.expose() != value.expose() => {
                    return Err(conflict(other, &profile.name, &host))
                }
                Some(_) => {}
                None => {
                    tokens.insert(host, (profile.name.clone(), value));
                }
            }
        }
        if delivery.netrc {
            let entry = render::netrc_entry(profile, credential)?;
            match netrc_entries.get(&entry.host) {
                Some((other, existing))
                    if existing.login != entry.login
                        || existing.password.expose() != entry.password.expose() =>
                {
                    return Err(conflict(other, &profile.name, &entry.host))
                }
                Some(_) => {}
                None => {
                    netrc_entries.insert(entry.host.clone(), (profile.name.clone(), entry));
                }
            }
        }
    }
    let plan = session::Plan {
        access_tokens: tokens.into_iter().map(|(h, (_, v))| (h, v)).collect(),
        netrc: netrc_entries.into_values().map(|(_, e)| e).collect(),
        substituters: None,
    };
    Ok((plan, proxied.into_values().collect()))
}

fn conflict(first: &str, second: &str, host: &str) -> Error {
    Error::usage(format!(
        "profiles \"{first}\" and \"{second}\" would present different credentials for {host}; \
         select only one of them"
    ))
}

/// Reads the user's netrc. A missing file means no entries; one that cannot be read is skipped
/// with a warning that names the file (never its contents).
fn read_existing_netrc(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            warn(format!(
                "cannot read netrc-file {}; its entries are unavailable to the command",
                path.display()
            ));
            Vec::new()
        }
    }
}

/// Tells the user which of their existing entries the selected profiles replace.
fn announce_replacements(
    credentials: &[(&Profile, Credential)],
    existing_tokens: &BTreeMap<String, crate::vault::auth::redact::Secret>,
    existing_netrc: &[u8],
) {
    let netrc_hosts = netrc::hosts(existing_netrc);
    for (profile, _) in credentials {
        let delivery = profile.delivery();
        let clash = (delivery.access_token.is_some()
            && existing_tokens.contains_key(&profile.host))
            || (delivery.netrc && netrc_hosts.contains(&profile.host));
        if clash {
            note(format!(
                "profile \"{}\" replaces existing credentials for {}",
                profile.name, profile.host
            ));
        }
    }
}

fn forward(pid: i32, signal: i32) {
    // SAFETY: plain kill(2) on the child's pid
    unsafe {
        libc::kill(pid, signal);
    }
}

/// Starts the child, forwards termination signals, mirrors its exit status and removes the
/// session afterwards.
fn run_child(
    command: &[String],
    nix_config: &str,
    mut session: session::Session,
    env: &[(String, String)],
    proxies: Vec<proxy::Proxy>,
) -> Result<ExitStatus> {
    // The terminal sends Ctrl-C and Ctrl-\ to the child too; nix-vault just keeps waiting.
    // Handlers (unlike "ignore") are reset in the child on exec.
    // SAFETY: the closures do nothing, which is async-signal-safe
    let ids = unsafe {
        [
            low_level::register(SIGINT, || {}),
            low_level::register(SIGQUIT, || {}),
        ]
    };
    let mut signals = Signals::new([SIGTERM, SIGHUP, SIGUSR1, SIGUSR2])
        .map_err(|e| Error::io("cannot install signal handlers", e))?;
    let handle = signals.handle();
    let pid = Arc::new(AtomicI32::new(0));
    let pending = Arc::new(AtomicI32::new(0));
    let forwarder = {
        let (pid, pending) = (pid.clone(), pending.clone());
        std::thread::spawn(move || {
            for signal in signals.forever() {
                match pid.load(Ordering::SeqCst) {
                    0 => pending.store(signal, Ordering::SeqCst),
                    pid => forward(pid, signal),
                }
            }
        })
    };

    let spawned = Command::new(&command[0])
        .args(&command[1..])
        .env("NIX_CONFIG", nix_config)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            handle.close();
            let _ = forwarder.join();
            drop(proxies);
            session.cleanup();
            return Err(Error::Spawn {
                command: command[0].clone(),
                not_executable: e.kind() == std::io::ErrorKind::PermissionDenied,
            });
        }
    };
    pid.store(child.id() as i32, Ordering::SeqCst);
    let early = pending.load(Ordering::SeqCst);
    if early != 0 {
        forward(child.id() as i32, early);
    }

    let status = child.wait();
    handle.close();
    let _ = forwarder.join();
    for id in ids.into_iter().flatten() {
        low_level::unregister(id);
    }
    // Clean up first, whatever happened to the child
    drop(proxies);
    session.cleanup();

    status.map_err(|e| Error::io("cannot wait for the command", e))
}
