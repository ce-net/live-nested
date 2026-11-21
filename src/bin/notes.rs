//! notes: a harmless notes program, the program `notes.app` wraps. `notes add <text> <in.json> <out.json>` reads a
//! JSON list of notes, appends one (keeping the last 50) and writes the list. `notes list <in.json>` prints it.
use serde_json::{json, Value};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let load = |p: &str| -> Vec<Value> { std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default() };
    match a.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["--version"] => println!("notes 0.1.0"),
        ["add", text, inp, out] | ["add", inp, text, out] if inp.ends_with(".json") => {
            let mut v = load(inp);
            let id = v.iter().filter_map(|n| n["id"].as_u64()).max().unwrap_or(0) + 1;
            v.push(json!({"id": id, "text": text}));
            let keep = v.len().saturating_sub(50);
            let v: Vec<Value> = v.into_iter().skip(keep).collect();
            std::fs::write(out, serde_json::to_vec(&v).unwrap()).expect("write");
            println!("{}", json!({"id": id, "text": text}));
        }
        ["list", inp] => println!("{}", Value::Array(load(inp))),
        _ => {
            eprintln!("usage: notes add <text> <in.json> <out.json> | notes list <in.json>");
            std::process::exit(2);
        }
    }
}
