//! live-nested: recursive containers and recursive narrowed capabilities, as a live system (CES-8).
//!
//! `nest.outer` is a holder cell. It runs box `a7` (bubblewrap, no network) holding an inner door with three
//! inner cells: `notes.agent` (scripted, no model), `notes.app` (a notes program wrapped by wrap-tool) and
//! `calc.run`, itself a holder of box `a7/b2` with `calc.exec`. Every call into a box carries a cap v3 chain
//! that one link narrows at each boundary; every inner door checks it with
//! `ce_net_proto::ces8::authorize_inner` before an inner cell acts.
//!
//! The wire is one JSON object per line over a held connection (TCP outside, a Unix socket into a box).
use ce_net_proto::cap::Caveats;
use ce_net_proto::ces8::{authorize_inner, box_resource, DEFAULT_NEST_MAX};
use ce_net_proto::program::ResourceV3;
use ce_net_proto::v3::mint::{attenuate, mint_root, Grant};
use ce_net_proto::v3::sign::{verify_bytes, Signer};
use ce_net_proto::v3::{AudienceSet, Delegate, Key, Link, Sig, TokenV3};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const NOTES_POLICY: &str = include_str!("../policy/notes.toml");
/// What `nest.outer` exports: callers anywhere may call these and nothing else (CES-8 `[box.export]`).
pub const EXPORTS: &[&str] = &["Do", "Prove", "render:tree"];
/// What the inner network of box a7 may be given for `Do` (`[box.export.Do] inner`).
pub const DO_INNER: &[&str] = &["notes.app:add", "notes.app:list", "calc.exec:eval"];
/// What calc.run's box a7/b2 may be given (`[box.export.Eval] inner` of calc.run).
pub const EVAL_INNER: &[&str] = &["calc.exec:eval"];
/// Everything the run owner grants nest.outer.
pub const OWNER_GRANTS: &[&str] = &["notes.app:add", "notes.app:list", "calc.exec:eval", "net:connect"];

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A fresh Ed25519 key from the kernel's random source. Keys live in memory only and end with the process.
pub fn fresh_signer() -> Signer {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)).expect("/dev/urandom");
    Signer::ed25519(&seed)
}

pub fn nonce() -> u64 {
    let mut b = [0u8; 8];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    u64::from_le_bytes(b)
}

pub fn key_hex(k: &Key) -> String {
    match k {
        Key::Ed25519(b) => hex::encode(b),
        Key::P256(b) => hex::encode(b),
    }
}

pub fn key_from_hex(s: &str) -> Result<Key, String> {
    let b = hex::decode(s).map_err(|e| format!("key: {e}"))?;
    let a: [u8; 32] = b.try_into().map_err(|_| "key: not 32 bytes".to_string())?;
    Ok(Key::Ed25519(a))
}

pub fn raw(k: &Key) -> [u8; 32] {
    match k {
        Key::Ed25519(b) => *b,
        Key::P256(_) => [0; 32],
    }
}

pub fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

pub fn path_of(p: &str) -> Vec<String> {
    p.split('/').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// One link: to `to`, may use `abilities`, may grant `delegate` (abilities, depth), scoped to box `path`
/// (empty: unscoped), valid until `until`.
pub fn grant(to: &Key, abilities: &[&str], path: &[String], until: u64, delegate: Option<(&[&str], u8)>) -> Grant {
    Grant {
        audience: *to,
        abilities: strs(abilities),
        resource: if path.is_empty() { ResourceV3::Any } else { box_resource(path) },
        caveats: Caveats { not_after: until, ..Caveats::default() },
        ext: vec![],
        delegate: delegate.map(|(a, depth)| Delegate { abilities: strs(a), audience: AudienceSet::Any, depth }),
        nonce: nonce(),
    }
}

pub fn root(owner: &Signer, outer: &Key, until: u64) -> Link {
    mint_root(owner, grant(outer, &[], &[], until, Some((OWNER_GRANTS, 6)))).expect("root link")
}

pub fn extend(by: &Signer, parent: &Link, g: Grant) -> Result<Link, String> {
    attenuate(by, parent, g).map_err(|e| e.to_string())
}

pub fn token_hex(links: &[Link]) -> String {
    TokenV3 { links: links.to_vec(), programs: vec![] }.to_hex()
}

pub fn token_from_hex(s: &str) -> Result<TokenV3, String> {
    TokenV3::from_hex(s).map_err(|e| format!("token: {e}"))
}

/// Re-sign a link after changing it: how a cell would try to give more than it holds.
pub fn forged(by: &Signer, l: &Link, f: impl FnOnce(&mut ce_net_proto::v3::CapabilityV3)) -> Link {
    let Link::V3 { cap, .. } = l else { panic!("v3 link") };
    let mut cap = cap.clone();
    f(&mut cap);
    Link::V3 { sig: by.sign(&cap), cap }
}

/// Names for keys, so a printed chain reads `nest.outer -> door a7`.
#[derive(Clone, Default, Debug)]
pub struct Names(pub BTreeMap<String, String>);

impl Names {
    pub fn add(&mut self, k: &Key, name: &str) {
        self.0.insert(key_hex(k), name.to_string());
    }
    pub fn of(&self, k: &Key) -> String {
        let h = key_hex(k);
        self.0.get(&h).cloned().unwrap_or_else(|| format!("key {}", &h[..8]))
    }
    pub fn args(&self) -> Vec<String> {
        self.0.iter().flat_map(|(k, v)| ["--name".to_string(), format!("{k}={v}")]).collect()
    }
}

/// One link as printed: who gave what to whom, at which scope, how deep, how long.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LinkView {
    pub from: String,
    pub to: String,
    pub abilities: Vec<String>,
    pub may_grant: Vec<String>,
    pub depth: u8,
    pub scope: String,
    pub expires_in_s: i64,
}

/// A chain as one door saw it when it let a cell act.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Level {
    pub door: String,
    pub cell: String,
    pub ability: String,
    pub chain: Vec<LinkView>,
}

pub fn view(links: &[Link], names: &Names) -> Vec<LinkView> {
    let t = now() as i64;
    links
        .iter()
        .filter_map(|l| match l {
            Link::V3 { cap, .. } => Some(cap),
            Link::V1(_) => None,
        })
        .map(|c| LinkView {
            from: names.of(&c.issuer),
            to: names.of(&c.audience),
            abilities: c.abilities.clone(),
            may_grant: c.delegate.as_ref().map(|d| d.abilities.clone()).unwrap_or_default(),
            depth: c.delegate.as_ref().map(|d| d.depth).unwrap_or(0),
            scope: match &c.resource {
                ResourceV3::AllOf(t) => t.join(" "),
                ResourceV3::Any => "any".into(),
                r => format!("{r:?}"),
            },
            expires_in_s: c.caveats.not_after as i64 - t,
        })
        .collect()
}

/// The inner-door check (CES-8 section 3), with the holder's declared rights per box.
pub fn check(door: &Signer, path: &[String], roots: &[Key], declared: &BTreeMap<String, Vec<String>>, requester: &Key, ability: &str, links: &[Link]) -> Result<(), String> {
    let t = TokenV3 { links: links.to_vec(), programs: vec![] };
    let d = |p: &[String]| declared.get(&p.join("/")).cloned();
    authorize_inner(raw(&door.key()), path, roots, now(), requester, ability, &t, DEFAULT_NEST_MAX, &d).map(|_| ()).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------------------------------------ wire

/// A call into a box: the cell and op, its arguments, the chain, and the caller's signature over all of it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Call {
    pub cell: String,
    pub op: String,
    pub args: Value,
    pub token: String,
    pub from: String,
    pub ts: u64,
    pub sig: String,
}

fn call_msg(cell: &str, op: &str, args: &Value, token: &str, ts: u64) -> Vec<u8> {
    format!("live-nested/call\n{cell}\n{op}\n{args}\n{token}\n{ts}").into_bytes()
}

impl Call {
    pub fn new(by: &Signer, cell: &str, op: &str, args: Value, links: &[Link]) -> Call {
        let (token, ts) = (token_hex(links), now());
        let sig = match by.sign_bytes(&call_msg(cell, op, &args, &token, ts)) {
            Sig::Ed25519(b) => hex::encode(b),
            _ => String::new(),
        };
        Call { cell: cell.into(), op: op.into(), args, token, from: key_hex(&by.key()), ts, sig }
    }
    /// The caller's key, its signature checked, and the chain.
    pub fn open(&self) -> Result<(Key, Vec<Link>), String> {
        let k = key_from_hex(&self.from)?;
        let b: [u8; 64] = hex::decode(&self.sig).ok().and_then(|b| b.try_into().ok()).ok_or("signature: not 64 bytes")?;
        verify_bytes(&k, &call_msg(&self.cell, &self.op, &self.args, &self.token, self.ts), &Sig::Ed25519(b)).map_err(|e| format!("signature: {e}"))?;
        if self.ts + 30 < now() {
            return Err("call older than 30 s".into());
        }
        Ok((k, token_from_hex(&self.token)?.links))
    }
}

/// A held connection: one JSON line out, one back.
pub struct Conn<S: Read + Write> {
    r: BufReader<S>,
}

impl<S: Read + Write> Conn<S> {
    pub fn new(s: S) -> Self {
        Conn { r: BufReader::new(s) }
    }
    pub fn send(&mut self, v: &Value) -> Result<(), String> {
        let mut b = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        b.push(b'\n');
        self.r.get_mut().write_all(&b).map_err(|e| format!("send: {e}"))
    }
    pub fn recv(&mut self) -> Result<Option<Value>, String> {
        let mut line = String::new();
        let n = self.r.read_line(&mut line).map_err(|e| format!("recv: {e}"))?;
        if n == 0 {
            return Ok(None);
        }
        serde_json::from_str(&line).map(Some).map_err(|e| format!("recv: {e}"))
    }
    pub fn ask(&mut self, v: &Value) -> Result<Value, String> {
        self.send(v)?;
        self.recv()?.ok_or_else(|| "connection closed".into())
    }
}

// ------------------------------------------------------------------------------------------------ boxes

/// How a box is isolated: `bwrap` (own user, pid, net, ipc, uts and mount namespaces; isolation class I1) or
/// `none` (a plain child process, for machines without user namespaces; the network refusals are then not shown).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Iso {
    Bwrap,
    None,
}

impl Iso {
    pub fn parse(s: &str) -> Iso {
        if s == "none" {
            Iso::None
        } else {
            Iso::Bwrap
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Iso::Bwrap => "bwrap",
            Iso::None => "none",
        }
    }
}

/// A started box: its process and the socket its inner door listens on (as this side sees it).
pub struct Boxed {
    pub child: Child,
    pub sock: PathBuf,
}

/// Start `nest door` for box `path` in `dir`. `exe_dir` holds `nest` and `notes` as this side sees them.
pub fn start_box(iso: Iso, exe_dir: &Path, dir: &Path, door_args: &[String]) -> Result<Boxed, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let sock = dir.join("door.sock");
    let _ = std::fs::remove_file(&sock);
    let mut cmd = match iso {
        Iso::Bwrap => {
            let mut c = Command::new("bwrap");
            c.args(["--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/usr", "/usr"]);
            for d in ["/lib", "/lib64", "/bin", "/sbin"] {
                match std::fs::read_link(d) {
                    Ok(t) => {
                        c.args(["--symlink", &t.to_string_lossy(), d]);
                    }
                    Err(_) if Path::new(d).is_dir() => {
                        c.args(["--ro-bind", d, d]);
                    }
                    Err(_) => {}
                }
            }
            c.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
            c.arg("--ro-bind").arg(exe_dir.join("nest")).arg("/nest/nest");
            if exe_dir.join("notes").exists() {
                c.arg("--ro-bind").arg(exe_dir.join("notes")).arg("/nest/notes");
            }
            c.arg("--bind").arg(dir).arg("/box");
            c.args(["--chdir", "/box", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--", "/nest/nest", "door", "--sock", "/box/door.sock", "--home", "/box", "--bin", "/nest"]);
            c
        }
        Iso::None => {
            let mut c = Command::new(exe_dir.join("nest"));
            c.arg("door").arg("--sock").arg(&sock).arg("--home").arg(dir).arg("--bin").arg(exe_dir);
            c
        }
    };
    cmd.args(door_args).stdin(Stdio::null()).stdout(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("start box ({}): {e}", iso.name()))?;
    // the door writes one line once its socket listens: block on it, no polling (CES-1 rule 2)
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("piped stdout")).read_line(&mut line).map_err(|e| format!("box {}: {e}", dir.display()))?;
    if line.trim() != "ready" || !sock.exists() {
        let _ = child.kill();
        return Err(format!("box {}: the door did not start ({:?})", dir.display(), line.trim()));
    }
    Ok(Boxed { child, sock })
}

/// Connect to a box's door; the first line is its hello with its key.
pub fn dial(sock: &Path) -> Result<(Conn<std::os::unix::net::UnixStream>, Key), String> {
    // one held connection per box, opened once when the holder starts it
    let s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?; // cell-check: allow conn-per-call
    s.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let mut c = Conn::new(s);
    let hello = c.recv()?.ok_or("door closed before its hello")?;
    let k = key_from_hex(hello["key"].as_str().unwrap_or(""))?;
    Ok((c, k))
}

/// One TCP connection attempt from wherever this runs; the error says what stopped it.
pub fn try_connect(addr: &str) -> String {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => match std::net::TcpStream::connect_timeout(&a, Duration::from_secs(2)) {
            Ok(_) => format!("connected to {addr}"),
            Err(e) => format!("refused by the box: connect {addr}: {e}"),
        },
        Err(e) => e.to_string(),
    }
}

// ------------------------------------------------------------------------------------------------ calc

/// calc.exec's language: integers, + - * / and parentheses, at most 64 characters.
pub fn calc(expr: &str) -> Result<i64, String> {
    if expr.len() > 64 {
        return Err("expression longer than 64 characters".into());
    }
    let t: Vec<char> = expr.chars().filter(|c| !c.is_whitespace()).collect();
    let mut i = 0;
    let v = sum(&t, &mut i)?;
    if i != t.len() {
        return Err(format!("unexpected {:?}", t[i]));
    }
    Ok(v)
}

fn sum(t: &[char], i: &mut usize) -> Result<i64, String> {
    let mut v = prod(t, i)?;
    while *i < t.len() && (t[*i] == '+' || t[*i] == '-') {
        let op = t[*i];
        *i += 1;
        let r = prod(t, i)?;
        v = if op == '+' { v.checked_add(r) } else { v.checked_sub(r) }.ok_or("overflow")?;
    }
    Ok(v)
}

fn prod(t: &[char], i: &mut usize) -> Result<i64, String> {
    let mut v = atom(t, i)?;
    while *i < t.len() && (t[*i] == '*' || t[*i] == '/') {
        let op = t[*i];
        *i += 1;
        let r = atom(t, i)?;
        v = if op == '*' { v.checked_mul(r).ok_or("overflow")? } else { v.checked_div(r).ok_or("division by zero")? };
    }
    Ok(v)
}

fn atom(t: &[char], i: &mut usize) -> Result<i64, String> {
    if *i < t.len() && t[*i] == '(' {
        *i += 1;
        let v = sum(t, i)?;
        if *i >= t.len() || t[*i] != ')' {
            return Err("missing )".into());
        }
        *i += 1;
        return Ok(v);
    }
    let s = *i;
    while *i < t.len() && t[*i].is_ascii_digit() {
        *i += 1;
    }
    if s == *i {
        return Err("expected a number".into());
    }
    t[s..*i].iter().collect::<String>().parse().map_err(|_| "number too large".into())
}

/// The first arithmetic expression in a note, if any: `order 3*4 bolts` -> `3*4`.
pub fn find_expr(text: &str) -> Option<String> {
    let ok = |c: char| c.is_ascii_digit() || "+-*/()".contains(c);
    text.split_whitespace().find(|w| w.chars().all(ok) && w.chars().any(|c| "+-*/".contains(c)) && calc(w).is_ok()).map(str::to_string)
}

/// The typed result of `nest.outer Do`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DoResult {
    pub note: Option<Value>,
    pub notes: Vec<Value>,
    pub calc: Option<Value>,
    pub levels: Vec<Level>,
    pub isolation: String,
    pub ms: u64,
}

pub fn refused(why: impl std::fmt::Display) -> Value {
    json!({ "refused": why.to_string() })
}
