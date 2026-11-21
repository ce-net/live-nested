//! nest: the processes of live-nested.
//!
//!   nest outer [--listen 127.0.0.1:7790] [--ttl 900] [--home DIR] [--box bwrap|none]
//!                                    the holder cell nest.outer; starts box a7, which starts box a7/b2; exits at --ttl
//!   nest call <host:port> '<json>' [--json]
//!                                    one call to nest.outer from anywhere: '{"Do":{"AddNote":{"text":"order 3*4 bolts"}}}',
//!                                    '{"Do":"ListNotes"}', '{"Prove":{}}', '{"render:tree":{}}'
//!   nest door ...                    an inner door (started by a holder inside its box, never by hand)
use live_nested::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn arg(a: &[String], f: &str, d: &str) -> String {
    a.iter().position(|x| x == f).and_then(|i| a.get(i + 1)).cloned().unwrap_or_else(|| d.to_string())
}

fn args_all(a: &[String], f: &str) -> Vec<String> {
    a.iter().enumerate().filter(|(_, x)| *x == f).filter_map(|(i, _)| a.get(i + 1).cloned()).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("outer") => outer(&a),
        Some("door") => door(&a),
        Some("call") => std::process::exit(call(&a)),
        _ => {
            eprintln!("usage: nest outer [--listen ADDR] [--ttl S] [--home DIR] [--box bwrap|none] | nest call <host:port> '<json>' [--json]");
            std::process::exit(2);
        }
    }
}

// ------------------------------------------------------------------------------------------------ nest.outer

struct Outer {
    me: ce_net_proto::v3::sign::Signer,
    l0: ce_net_proto::v3::Link,
    door: Conn<std::os::unix::net::UnixStream>,
    door_key: ce_net_proto::v3::Key,
    iso: Iso,
    last: Option<DoResult>,
}

fn outer(a: &[String]) {
    let listen = arg(a, "--listen", "127.0.0.1:7790"); // cell-check: allow hardcoded-host (loopback default)
    let ttl: u64 = arg(a, "--ttl", "900").parse().unwrap_or(900);
    let home = PathBuf::from(arg(a, "--home", &std::env::temp_dir().join(format!("live-nested-{}", std::process::id())).to_string_lossy()));
    let iso = Iso::parse(&arg(a, "--box", "bwrap"));
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).expect("exe dir");
    // The run owner's key exists only in this process's memory: it signs one root link and is dropped.
    let owner = fresh_signer();
    let me = fresh_signer();
    let start = now();
    let l0 = root(&owner, &me.key(), start + ttl + 120);
    let mut names = Names::default();
    names.add(&owner.key(), "owner");
    names.add(&me.key(), "nest.outer");
    drop(owner);
    let roots = key_hex(&names_key(&names, "owner"));
    let mut door_args = vec![
        "--path".into(), "a7".into(), "--role".into(), "a".into(), "--box".into(), iso.name().into(),
        "--roots".into(), roots, "--declare".into(), format!("a7={}", DO_INNER.join(",")),
    ];
    door_args.extend(names.args());
    let boxed = start_box(iso, &exe_dir, &home.join("a7"), &door_args).unwrap_or_else(|e| fail(&e));
    let (door, door_key) = dial(&boxed.sock).unwrap_or_else(|e| fail(&e));
    let l = TcpListener::bind(&listen).unwrap_or_else(|e| fail(&format!("listen {listen}: {e}")));
    println!("listening {} box {} ttl {ttl}s", l.local_addr().map(|x| x.to_string()).unwrap_or_default(), iso.name());
    std::io::stdout().flush().ok();
    // the lease: one wake-up at the end, then the whole tree goes (bwrap --die-with-parent, PDEATHSIG for none)
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(ttl));
        eprintln!("nest.outer: ttl {ttl}s reached, stopping the tree");
        std::process::exit(0);
    });
    let mut o = Outer { me, l0, door, door_key, iso, last: None };
    for s in l.incoming().flatten() {
        s.set_read_timeout(Some(Duration::from_secs(30))).ok();
        let mut c = Conn::new(s);
        while let Ok(Some(req)) = c.recv() {
            let resp = o.handle(&req);
            if c.send(&resp).is_err() {
                break;
            }
        }
    }
    let mut child = boxed.child;
    let _ = child.kill();
}

fn names_key(n: &Names, name: &str) -> ce_net_proto::v3::Key {
    n.0.iter().find(|(_, v)| *v == name).and_then(|(k, _)| key_from_hex(k).ok()).expect("named key")
}

fn fail(e: &str) -> ! {
    eprintln!("nest: {e}");
    std::process::exit(1)
}

impl Outer {
    fn into_box(&mut self, cell: &str, op: &str, args: Value, links: &[ce_net_proto::v3::Link]) -> Value {
        let c = Call::new(&self.me, cell, op, args, links);
        self.door.ask(&serde_json::to_value(c).unwrap()).unwrap_or_else(refused)
    }

    /// The one link nest.outer adds to cross into box a7 for one call: scoped to the box, only the rights `Do`
    /// declares for the inner network, one level less deep, expiring in 60 s.
    fn l1(&self) -> ce_net_proto::v3::Link {
        extend(&self.me, &self.l0, grant(&self.door_key, &[], &path_of("a7"), now() + 60, Some((DO_INNER, 5)))).expect("l1")
    }

    fn handle(&mut self, req: &Value) -> Value {
        let t0 = Instant::now();
        let Some((op, body)) = req.as_object().and_then(|m| m.iter().next()) else { return refused("a call is {\"<op>\": <args>}") };
        match op.as_str() {
            "Do" => {
                let (inner_op, args) = match body {
                    Value::String(s) if s == "ListNotes" => ("ListNotes", json!({})),
                    Value::Object(m) if m.contains_key("AddNote") => {
                        let text = m["AddNote"]["text"].as_str().unwrap_or("").to_string();
                        if text.is_empty() || text.chars().count() > 200 {
                            return refused("AddNote.text: 1 to 200 characters");
                        }
                        ("AddNote", json!({ "text": text }))
                    }
                    _ => return refused("Do takes {\"AddNote\":{\"text\":..}} or \"ListNotes\""),
                };
                let links = vec![self.l0.clone(), self.l1()];
                let mut r = self.into_box("notes.agent", inner_op, args, &links);
                if r.get("refused").is_some() {
                    return r;
                }
                r["isolation"] = json!(self.iso.name());
                r["ms"] = json!(t0.elapsed().as_millis() as u64);
                if let Ok(d) = serde_json::from_value::<DoResult>(r.clone()) {
                    if !d.levels.is_empty() {
                        self.last = Some(d);
                    }
                }
                r
            }
            "Prove" => self.prove(),
            "render:tree" => json!({ "html": self.render() }),
            other => refused(format!(
                "nest.outer exports only {}; {other:?} is not one of them. notes.agent, notes.app, calc.run and calc.exec are inside box a7 and have no address outside it",
                EXPORTS.join(", ")
            )),
        }
    }

    /// The four refusals, each a real attempt made now.
    fn prove(&mut self) -> Value {
        let mut out = vec![];
        let ext = self.handle(&json!({"notes.app:add": {"text": "from outside"}}));
        let l0 = vec![self.l0.clone()];
        let direct = self.into_box("notes.app", "Add", json!({"text": "from outside"}), &l0);
        out.push(json!({
            "name": "an inner cell called from outside",
            "attempts": [
                {"how": "a caller asks nest.outer for notes.app:add", "result": ext},
                {"how": "nest.outer hands door a7 its own unscoped chain and asks for notes.app:add", "result": direct},
            ]
        }));
        for (name, cell, op) in [
            ("an inner cell calling outside its uplink", "notes.agent", "ProbeUplink"),
            ("a right wider than delegated", "notes.agent", "WiderRight"),
            ("box a7/b2 reaching the network", "calc.run", "ProbeNet"),
        ] {
            let links = vec![self.l0.clone(), self.l1()];
            let r = self.into_box(cell, op, json!({}), &links);
            // an answer without attempts is a refusal of the probe itself: show it rather than hide it
            let attempts = r.get("attempts").cloned().unwrap_or_else(|| json!([{"how": format!("{cell} {op}"), "result": r, "unexpected": true}]));
            out.push(json!({"name": name, "attempts": attempts}));
        }
        let all_refused = out.iter().all(|r| {
            r["attempts"].as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|x| x.get("unexpected").is_none() && x["result"].get("refused").is_some()))
        });
        json!({ "isolation": self.iso.name(), "all_refused": all_refused, "refusals": out })
    }

    fn render(&self) -> String {
        let Some(d) = &self.last else { return "<p>No call yet.</p>".into() };
        let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        let mut h = String::from("<div class=\"nest-tree\">");
        for l in &d.levels {
            h += &format!("<section><h3>{} let {} use {}</h3><ol>", esc(&l.door), esc(&l.cell), esc(&l.ability));
            for v in &l.chain {
                h += &format!(
                    "<li>{} &rarr; {}: uses [{}] may grant [{}] depth {} scope {} expires in {} s</li>",
                    esc(&v.from), esc(&v.to), esc(&v.abilities.join(", ")), esc(&v.may_grant.join(", ")), v.depth, esc(&v.scope), v.expires_in_s
                );
            }
            h += "</ol></section>";
        }
        h + "</div>"
    }
}

// ------------------------------------------------------------------------------------------------ inner doors

struct Cell {
    name: &'static str,
    s: ce_net_proto::v3::sign::Signer,
}

struct Door {
    me: ce_net_proto::v3::sign::Signer,
    path: Vec<String>,
    roots: Vec<ce_net_proto::v3::Key>,
    declared: BTreeMap<String, Vec<String>>,
    names: Names,
    home: PathBuf,
    cells: Vec<Cell>,
    sub: Option<(Conn<std::os::unix::net::UnixStream>, ce_net_proto::v3::Key, std::process::Child)>,
}

fn door(a: &[String]) {
    #[cfg(target_os = "linux")]
    unsafe {
        // a door started without bwrap still ends with its holder
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    let sock = PathBuf::from(arg(a, "--sock", "door.sock"));
    let home = PathBuf::from(arg(a, "--home", "."));
    let bin = PathBuf::from(arg(a, "--bin", "."));
    let path = path_of(&arg(a, "--path", ""));
    let role = arg(a, "--role", "a");
    let iso = Iso::parse(&arg(a, "--box", "bwrap"));
    let roots = arg(a, "--roots", "").split(',').filter_map(|k| key_from_hex(k).ok()).collect();
    let mut declared = BTreeMap::new();
    for d in args_all(a, "--declare") {
        if let Some((p, r)) = d.split_once('=') {
            declared.insert(p.to_string(), r.split(',').map(str::to_string).collect());
        }
    }
    let mut names = Names::default();
    for n in args_all(a, "--name") {
        if let Some((k, v)) = n.split_once('=') {
            names.0.insert(k.into(), v.into());
        }
    }
    let me = fresh_signer();
    let label = format!("door {}", path.join("/"));
    names.add(&me.key(), &label);
    let cell_names: &[&'static str] = if role == "a" { &["notes.agent", "notes.app", "calc.run"] } else { &["calc.exec"] };
    let cells: Vec<Cell> = cell_names.iter().map(|n| Cell { name: n, s: fresh_signer() }).collect();
    for c in &cells {
        names.add(&c.s.key(), c.name);
    }
    let mut d = Door { me, path, roots, declared, names, home: home.clone(), cells, sub: None };
    if role == "a" {
        // notes.app: the wrapped program's allowlist, and where its executable is
        let pol = home.join("policy");
        std::fs::create_dir_all(&pol).ok();
        std::fs::write(pol.join("notes.toml"), NOTES_POLICY).expect("policy");
        std::env::set_var("WRAP_TOOL_POLICY_DIR", &pol);
        std::env::set_var("WRAP_TOOL_BIN_DIR", &bin);
        // calc.run is itself a holder: box a7/b2 with calc.exec
        let mut sub_path = d.path.clone();
        sub_path.push("b2".into());
        let mut args = vec![
            "--path".into(), sub_path.join("/"), "--role".into(), "b".into(), "--box".into(), iso.name().into(),
            "--roots".into(), d.roots.iter().map(key_hex).collect::<Vec<_>>().join(","),
            "--declare".into(), format!("{}={}", d.path.join("/"), DO_INNER.join(",")),
            "--declare".into(), format!("{}={}", sub_path.join("/"), EVAL_INNER.join(",")),
        ];
        args.extend(d.names.args());
        let b = start_box(iso, &bin, &home.join("b2"), &args).unwrap_or_else(|e| fail(&e));
        let (c, k) = dial(&b.sock).unwrap_or_else(|e| fail(&e));
        d.names.add(&k, &format!("door {}", sub_path.join("/")));
        d.sub = Some((c, k, b.child));
    }
    let _ = std::fs::remove_file(&sock);
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap_or_else(|e| fail(&format!("{}: {e}", sock.display())));
    println!("ready");
    std::io::stdout().flush().ok();
    for s in l.incoming().flatten() {
        let mut c = Conn::new(s);
        if c.send(&json!({"hello": "door", "path": d.path.join("/"), "key": key_hex(&d.me.key())})).is_err() {
            continue;
        }
        while let Ok(Some(req)) = c.recv() {
            let resp = match serde_json::from_value::<Call>(req) {
                Ok(call) => d.handle(&call),
                Err(e) => refused(format!("not a call: {e}")),
            };
            if c.send(&resp).is_err() {
                break;
            }
        }
    }
}

type Links = Vec<ce_net_proto::v3::Link>;

impl Door {
    fn cell(&self, n: &str) -> &ce_net_proto::v3::sign::Signer {
        &self.cells.iter().find(|c| c.name == n).expect("cell").s
    }

    fn check(&self, who: &ce_net_proto::v3::Key, ability: &str, links: &[ce_net_proto::v3::Link]) -> Result<(), String> {
        check(&self.me, &self.path, &self.roots, &self.declared, who, ability, links)
    }

    fn level(&self, cell: &str, ability: &str, links: &[ce_net_proto::v3::Link]) -> Level {
        Level { door: format!("door {}", self.path.join("/")), cell: cell.into(), ability: ability.into(), chain: view(links, &self.names) }
    }

    fn handle(&mut self, c: &Call) -> Value {
        let (from, links) = match c.open() {
            Ok(x) => x,
            Err(e) => return refused(e),
        };
        // a call straight at an inner cell from the holder: the holder must itself hold that right here
        if c.cell == "notes.app" {
            return match self.check(&from, "notes.app:add", &links) {
                Ok(()) => refused("unexpected: an unscoped chain was accepted"),
                Err(e) => refused(format!("door {} refused: {e}", self.path.join("/"))),
            };
        }
        let ends_here = matches!(links.last(), Some(ce_net_proto::v3::Link::V3 { cap, .. }) if cap.audience == self.me.key() && cap.issuer == from);
        if !ends_here {
            return refused(format!("door {}: the chain does not end at this door from the caller", self.path.join("/")));
        }
        let r = match (c.cell.as_str(), c.op.as_str()) {
            ("notes.agent", "AddNote") => self.add_note(links, c.args["text"].as_str().unwrap_or("")),
            ("notes.agent", "ListNotes") => self.list_notes(links),
            ("notes.agent", "ProbeUplink") => Ok(self.probe_uplink(links)),
            ("notes.agent", "WiderRight") => Ok(self.wider_right(links)),
            ("calc.run", "ProbeNet") => self.agent_link(&links).and_then(|c| self.calc_run(c, "ProbeNet", json!({}))),
            ("calc.exec", "Eval") => self.calc_exec(links, c.args["expr"].as_str().unwrap_or("")),
            ("calc.exec", "ProbeNet") => self.calc_probe(links),
            (cell, op) => Err(format!("door {}: no {cell} {op} in this box", self.path.join("/"))),
        };
        r.unwrap_or_else(refused)
    }

    /// door -> notes.agent: the agent's own link, inside this box, one level less deep.
    fn agent_link(&self, links: &Links) -> Result<Links, String> {
        let agent = self.cell("notes.agent").key();
        let l2 = extend(&self.me, links.last().unwrap(), grant(&agent, &[], &self.path, now() + 50, Some((DO_INNER, 4))))?;
        let mut v = links.clone();
        v.push(l2);
        Ok(v)
    }

    fn add_note(&mut self, links: Links, text: &str) -> Result<Value, String> {
        let chain = self.agent_link(&links)?;
        let mut levels = vec![];
        let mut calc_out = None;
        // the scripted agent: a note with arithmetic in it is first worked out by calc.run (in its own box)
        if let Some(expr) = find_expr(text) {
            let r = self.calc_run(chain.clone(), "Eval", json!({ "expr": expr }))?;
            if r.get("refused").is_some() {
                return Ok(r);
            }
            levels.extend(serde_json::from_value::<Vec<Level>>(r["levels"].clone()).unwrap_or_default());
            calc_out = Some(json!({"expr": expr, "value": r["value"]}));
        }
        let app = self.cell("notes.app").key();
        let l3 = extend(self.cell("notes.agent"), chain.last().unwrap(), grant(&app, &["notes.app:add"], &self.path, now() + 40, None))?;
        let mut c3 = chain.clone();
        c3.push(l3);
        self.check(&app, "notes.app:add", &c3)?;
        levels.insert(0, self.level("notes.app", "notes.app:add", &c3));
        let full = match &calc_out {
            Some(c) => format!("{text} (= {})", c["value"]),
            None => text.to_string(),
        };
        let note = self.notes_add(&full)?;
        Ok(serde_json::to_value(DoResult { note: Some(note), notes: vec![], calc: calc_out, levels, isolation: String::new(), ms: 0 }).unwrap())
    }

    fn list_notes(&mut self, links: Links) -> Result<Value, String> {
        let chain = self.agent_link(&links)?;
        let app = self.cell("notes.app").key();
        let l3 = extend(self.cell("notes.agent"), chain.last().unwrap(), grant(&app, &["notes.app:list"], &self.path, now() + 40, None))?;
        let mut c3 = chain;
        c3.push(l3);
        self.check(&app, "notes.app:list", &c3)?;
        let notes: Vec<Value> = std::fs::read(self.home.join("notes.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(serde_json::to_value(DoResult { notes, levels: vec![self.level("notes.app", "notes.app:list", &c3)], ..DoResult::default() }).unwrap())
    }

    /// notes.app: the notes program, run through wrap-tool's allowlist and limits.
    fn notes_add(&self, text: &str) -> Result<Value, String> {
        let p = wrap_tool::Policy::load("notes")?;
        let exe = wrap_tool::find_exe(&p).ok_or("notes: program not found")?;
        let file = self.home.join("notes.json");
        let input = std::fs::read(&file).unwrap_or_else(|_| b"[]".to_vec());
        let args = strs(&["add", "{in}", text, "{out}"]);
        let plan = wrap_tool::plan(&p, &args, &input, "json", "json").map_err(|e| format!("notes.app: {e}"))?;
        let o = wrap_tool::exec(&p, &exe, &plan, &input, true).map_err(|e| format!("notes.app: {e}"))?;
        if o.exit != 0 {
            return Err(format!("notes.app: exit {}: {}", o.exit, String::from_utf8_lossy(&o.stderr)));
        }
        std::fs::write(&file, &o.output).map_err(|e| format!("notes.json: {e}"))?;
        let mut v: Value = serde_json::from_slice(&o.stdout).map_err(|e| format!("notes.app output: {e}"))?;
        v["argv"] = json!(plan.argv);
        Ok(v)
    }

    /// calc.run, a holder inside this box: checks its own right here, adds the one link into box a7/b2.
    fn calc_run(&mut self, chain_to_agent: Links, op: &str, args: Value) -> Result<Value, String> {
        let run = &self.cells.iter().find(|c| c.name == "calc.run").expect("calc.run").s;
        let l3 = extend(self.cell("notes.agent"), chain_to_agent.last().unwrap(), grant(&run.key(), &["calc.exec:eval"], &self.path, now() + 40, Some((EVAL_INNER, 3))))?;
        let mut c3 = chain_to_agent.clone();
        c3.push(l3);
        self.check(&run.key(), "calc.exec:eval", &c3)?;
        let mine = self.level("calc.run", "calc.exec:eval", &c3);
        let bkey = self.sub.as_ref().map(|s| s.1).ok_or("calc.run: no box a7/b2")?;
        let mut sub = self.path.clone();
        sub.push("b2".into());
        let l4 = extend(run, c3.last().unwrap(), grant(&bkey, &[], &sub, now() + 30, Some((EVAL_INNER, 2))))?;
        let mut c4 = c3;
        c4.push(l4);
        let call = serde_json::to_value(Call::new(run, "calc.exec", op, args, &c4)).unwrap();
        let mut r = self.sub.as_mut().unwrap().0.ask(&call)?;
        if r.get("levels").is_some() {
            let mut lv = vec![mine];
            lv.extend(serde_json::from_value::<Vec<Level>>(r["levels"].clone()).unwrap_or_default());
            r["levels"] = serde_json::to_value(lv).unwrap();
        }
        Ok(r)
    }

    /// door a7/b2 -> calc.exec: the last link, use only, nothing to grant.
    fn exec_link(&self, links: &Links) -> Result<(ce_net_proto::v3::Key, Links), String> {
        let k = self.cell("calc.exec").key();
        let l5 = extend(&self.me, links.last().unwrap(), grant(&k, &["calc.exec:eval"], &self.path, now() + 20, None))?;
        let mut v = links.clone();
        v.push(l5);
        self.check(&k, "calc.exec:eval", &v)?;
        Ok((k, v))
    }

    fn calc_exec(&mut self, links: Links, expr: &str) -> Result<Value, String> {
        let (_, v) = self.exec_link(&links)?;
        let value = calc(expr)?;
        Ok(json!({ "value": value, "levels": [self.level("calc.exec", "calc.exec:eval", &v)] }))
    }

    fn calc_probe(&mut self, links: Links) -> Result<Value, String> {
        let (_, v) = self.exec_link(&links)?;
        let net = try_connect("1.1.1.1:53"); // cell-check: allow hardcoded-host (the probe target: an outside address)
        let ok = net.starts_with("connected");
        Ok(json!({
            "levels": [self.level("calc.exec", "calc.exec:eval", &v)],
            // cell-check: allow hardcoded-host (names the probe target)
            "attempts": [{"how": "calc.exec, holding a valid chain, opens TCP to 1.1.1.1:53", "refused": !ok, "result": if ok { json!({"connected": net}) } else { refused(&net) }}]
        }))
    }

    fn probe_uplink(&self, links: Links) -> Value {
        let chain = match self.agent_link(&links) {
            Ok(c) => c,
            Err(e) => return json!({"attempts": [{"how": "agent link", "result": refused(e)}]}),
        };
        let agent = self.cell("notes.agent").key();
        let cap = match self.check(&agent, "net:connect", &chain) {
            Ok(()) => json!({"accepted": "net:connect"}),
            Err(e) => refused(format!("door {} refused: {e}", self.path.join("/"))),
        };
        let uplink = refused(format!("door {}: net:connect is not in [box.uplink] of box {} (empty), so there is nothing to relay it to", self.path.join("/"), self.path.join("/")));
        let net = try_connect("1.1.1.1:443"); // cell-check: allow hardcoded-host (the probe target: an outside address)
        let raw = if net.starts_with("connected") { json!({"connected": net}) } else { refused(&net) };
        json!({"attempts": [
            {"how": "notes.agent asks door a7 for net:connect with its chain", "result": cap},
            {"how": "notes.agent asks door a7 to relay a call out of the box", "result": uplink},
            // cell-check: allow hardcoded-host (names the probe target)
            {"how": "notes.agent opens TCP to 1.1.1.1:443 itself", "result": raw},
        ]})
    }

    fn wider_right(&self, links: Links) -> Value {
        let chain = match self.agent_link(&links) {
            Ok(c) => c,
            Err(e) => return json!({"attempts": [{"how": "agent link", "result": refused(e)}]}),
        };
        let agent = self.cell("notes.agent");
        let app = self.cell("notes.app").key();
        let mint = match extend(agent, chain.last().unwrap(), grant(&app, &["notes.app:delete"], &self.path, now() + 40, None)) {
            Ok(_) => json!({"accepted": "minted"}),
            Err(e) => refused(format!("cap v3 mint refused: {e}")),
        };
        let ok = extend(agent, chain.last().unwrap(), grant(&app, &["notes.app:add"], &self.path, now() + 40, None)).expect("narrow link");
        let bad = forged(agent, &ok, |c| c.abilities = strs(&["notes.app:delete"]));
        let mut c3 = chain.clone();
        c3.push(bad);
        let used = match self.check(&app, "notes.app:delete", &c3) {
            Ok(()) => json!({"accepted": "notes.app:delete"}),
            Err(e) => refused(format!("door {} refused: {e}", self.path.join("/"))),
        };
        let deeper = forged(agent, &ok, |c| c.delegate = Some(ce_net_proto::v3::Delegate { abilities: strs(&["notes.app:add"]), audience: ce_net_proto::v3::AudienceSet::Any, depth: 9 }));
        let mut c4 = chain;
        c4.push(deeper);
        let deep = match self.check(&app, "notes.app:add", &c4) {
            Ok(()) => json!({"accepted": "depth 9"}),
            Err(e) => refused(format!("door {} refused: {e}", self.path.join("/"))),
        };
        json!({"attempts": [
            {"how": "notes.agent mints notes.app:delete for notes.app (it may grant only notes.app:add, notes.app:list, calc.exec:eval)", "result": mint},
            {"how": "notes.agent signs that link by hand and notes.app uses it", "result": used},
            {"how": "notes.agent signs a link with depth 9 below its depth 4", "result": deep},
        ]})
    }
}

// ------------------------------------------------------------------------------------------------ the caller

fn call(a: &[String]) -> i32 {
    let (Some(addr), Some(body)) = (a.get(1), a.get(2)) else {
        eprintln!("usage: nest call <host:port> '<json>' [--json]");
        return 2;
    };
    let req: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("nest call: {e}");
            return 2;
        }
    };
    // the caller CLI: one connection per invocation, held for its one call
    let s = match std::net::TcpStream::connect(addr) { // cell-check: allow conn-per-call
        Ok(s) => s,
        Err(e) => {
            eprintln!("nest call: {addr}: {e}");
            return 1;
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut c = Conn::new(s);
    let r = match c.ask(&req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nest call: {e}");
            return 1;
        }
    };
    if a.iter().any(|x| x == "--json") {
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    } else {
        print_human(&r);
    }
    if r.get("refused").is_some() {
        3
    } else {
        0
    }
}

fn print_human(r: &Value) {
    if let Some(w) = r.get("refused") {
        println!("REFUSED  {}", w.as_str().unwrap_or(""));
        return;
    }
    if let Some(n) = r.get("note").filter(|n| !n.is_null()) {
        println!("note #{}  {}", n["id"], n["text"].as_str().unwrap_or(""));
    }
    if let Some(c) = r.get("calc").filter(|c| !c.is_null()) {
        println!("calc     {} = {}  (worked out by calc.exec in box a7/b2)", c["expr"].as_str().unwrap_or(""), c["value"]);
    }
    if let Some(ns) = r.get("notes").and_then(Value::as_array).filter(|n| !n.is_empty()) {
        for n in ns {
            println!("  #{}  {}", n["id"], n["text"].as_str().unwrap_or(""));
        }
    }
    for l in r.get("levels").and_then(Value::as_array).into_iter().flatten() {
        println!("\n{} let {} use {}:", l["door"].as_str().unwrap_or(""), l["cell"].as_str().unwrap_or(""), l["ability"].as_str().unwrap_or(""));
        for v in l["chain"].as_array().into_iter().flatten() {
            let j = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            println!(
                "  {:<12} -> {:<12} uses [{}]  may grant [{}]  depth {}  scope {}  expires in {} s",
                v["from"].as_str().unwrap_or(""), v["to"].as_str().unwrap_or(""), j("abilities"), j("may_grant"), v["depth"], v["scope"].as_str().unwrap_or(""), v["expires_in_s"]
            );
        }
    }
    for rf in r.get("refusals").and_then(Value::as_array).into_iter().flatten() {
        println!("\n{}:", rf["name"].as_str().unwrap_or(""));
        for at in rf["attempts"].as_array().into_iter().flatten() {
            let why = at["result"]["refused"].as_str().map(|s| format!("REFUSED  {s}")).unwrap_or_else(|| format!("ACCEPTED {}", at["result"]));
            println!("  {}\n    {}", at["how"].as_str().unwrap_or(""), why);
        }
    }
    if let Some(i) = r.get("isolation") {
        println!("\nisolation {}{}", i.as_str().unwrap_or(""), r.get("ms").map(|m| format!(", {m} ms")).unwrap_or_default());
    }
    if let Some(b) = r.get("all_refused") {
        println!("all refused: {b}");
    }
}
