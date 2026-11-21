//! The whole tree as processes: nest.outer on loopback, box a7 with its inner door, box a7/b2 inside it, one
//! AddNote through all of them, then the four refusals. NEST_BOX=bwrap (default when bwrap works) or none.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn bwrap_works() -> bool {
    Command::new("bwrap").args(["--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "bwrap", "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"])
        .stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

fn ask(addr: &str, v: Value) -> Value {
    let s = std::net::TcpStream::connect(addr).unwrap();
    let mut w = s.try_clone().unwrap();
    w.write_all(format!("{v}\n").as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn add_note_through_two_boxes_and_four_refusals() {
    let iso = std::env::var("NEST_BOX").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| if bwrap_works() { "bwrap".into() } else { "none".into() });
    let home = std::env::temp_dir().join(format!("live-nested-test-{}", std::process::id()));
    let mut outer = Command::new(env!("CARGO_BIN_EXE_nest"))
        .args(["outer", "--listen", "127.0.0.1:0", "--ttl", "120", "--box", &iso, "--home"]).arg(&home)
        .stdout(Stdio::piped()).spawn().unwrap();
    let mut first = String::new();
    BufReader::new(outer.stdout.take().unwrap()).read_line(&mut first).unwrap();
    let addr = first.split_whitespace().nth(1).expect("listening line").to_string();
    eprintln!("{first}");

    let r = ask(&addr, json!({"Do": {"AddNote": {"text": "order 3*4 bolts"}}}));
    eprintln!("{}", serde_json::to_string_pretty(&r).unwrap());
    assert!(r.get("refused").is_none(), "{r}");
    assert_eq!(r["calc"]["value"], 12);
    assert!(r["note"]["text"].as_str().unwrap().contains("(= 12)"));
    let levels = r["levels"].as_array().unwrap();
    let doors: Vec<&str> = levels.iter().map(|l| l["door"].as_str().unwrap()).collect();
    assert_eq!(doors, ["door a7", "door a7", "door a7/b2"]);
    let deepest = levels[2]["chain"].as_array().unwrap();
    assert_eq!(deepest.len(), 6);
    assert_eq!(deepest[0]["may_grant"].as_array().unwrap().len(), 4);
    assert_eq!(deepest[5]["abilities"], json!(["calc.exec:eval"]));

    let r = ask(&addr, json!({"notes.app:add": {"text": "x"}}));
    assert!(r["refused"].as_str().unwrap().contains("exports only"));
    let p = ask(&addr, json!({"Prove": {}}));
    eprintln!("{}", serde_json::to_string_pretty(&p).unwrap());
    let rf = p["refusals"].as_array().unwrap();
    assert_eq!(rf.len(), 4);
    let refused = |i: usize, j: usize| {
        let a = &rf[i]["attempts"][j];
        a["result"].get("refused").is_some()
    };
    assert!(refused(0, 0) && refused(0, 1), "inner cell from outside");
    assert!(refused(1, 0) && refused(1, 1), "outside the uplink");
    assert!(refused(2, 0) && refused(2, 1) && refused(2, 2), "wider right");
    if iso == "bwrap" {
        assert!(refused(1, 2), "box a7 has no network");
        assert!(refused(3, 0), "box a7/b2 has no network");
        assert_eq!(p["all_refused"], true);
    }
    let _ = outer.kill();
    let _ = outer.wait();
    let _ = std::fs::remove_dir_all(&home);
}
