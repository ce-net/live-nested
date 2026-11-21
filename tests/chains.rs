//! The capability side alone, in one process: the chain live-nested builds for one AddNote with arithmetic,
//! checked at each door the way the doors check it, and the chains it must refuse.
use live_nested::*;
use std::collections::BTreeMap;

fn declared() -> BTreeMap<String, Vec<String>> {
    let mut d = BTreeMap::new();
    d.insert("a7".into(), strs(DO_INNER));
    d.insert("a7/b2".into(), strs(EVAL_INNER));
    d
}

#[test]
fn rights_narrow_at_every_boundary_and_every_door_accepts() {
    let (owner, outer, door_a, agent, app, run, door_b, exec) =
        (fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer());
    let (a7, b2) = (path_of("a7"), path_of("a7/b2"));
    let t = now();
    let roots = vec![owner.key()];
    let l0 = root(&owner, &outer.key(), t + 600);
    let l1 = extend(&outer, &l0, grant(&door_a.key(), &[], &a7, t + 60, Some((DO_INNER, 5)))).unwrap();
    let l2 = extend(&door_a, &l1, grant(&agent.key(), &[], &a7, t + 50, Some((DO_INNER, 4)))).unwrap();
    let l3 = extend(&agent, &l2, grant(&app.key(), &["notes.app:add"], &a7, t + 40, None)).unwrap();
    check(&door_a, &a7, &roots, &declared(), &app.key(), "notes.app:add", &[l0.clone(), l1.clone(), l2.clone(), l3]).unwrap();
    let r3 = extend(&agent, &l2, grant(&run.key(), &["calc.exec:eval"], &a7, t + 40, Some((EVAL_INNER, 3)))).unwrap();
    let chain_run = vec![l0.clone(), l1.clone(), l2.clone(), r3.clone()];
    check(&door_a, &a7, &roots, &declared(), &run.key(), "calc.exec:eval", &chain_run).unwrap();
    let l4 = extend(&run, &r3, grant(&door_b.key(), &[], &b2, t + 30, Some((EVAL_INNER, 2)))).unwrap();
    let l5 = extend(&door_b, &l4, grant(&exec.key(), &["calc.exec:eval"], &b2, t + 20, None)).unwrap();
    let full = vec![l0, l1, l2, r3, l4, l5];
    check(&door_b, &b2, &roots, &declared(), &exec.key(), "calc.exec:eval", &full).unwrap();
    let v = view(&full, &Names::default());
    // may-grant sets only shrink, depth drops on every link, expiry never grows, scope only goes deeper
    for w in v.windows(2) {
        assert!(w[1].may_grant.iter().all(|a| w[0].may_grant.contains(a)), "{:?} -> {:?}", w[0].may_grant, w[1].may_grant);
        assert!(w[1].depth < w[0].depth || w[1].depth == 0);
        assert!(w[1].expires_in_s <= w[0].expires_in_s);
    }
    assert_eq!(v[0].may_grant.len(), 4);
    assert_eq!(v[4].may_grant, strs(&["calc.exec:eval"]));
    assert_eq!(v[5].scope, "box:a7 box:a7/b2");
}

#[test]
fn refusals() {
    let (owner, outer, door_a, agent, app, door_b) = (fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer(), fresh_signer());
    let a7 = path_of("a7");
    let t = now();
    let roots = vec![owner.key()];
    let l0 = root(&owner, &outer.key(), t + 600);
    // an inner cell called from outside: the holder's own unscoped chain does not work inside the box
    let e = check(&door_a, &a7, &roots, &declared(), &outer.key(), "notes.app:add", &[l0.clone()]).unwrap_err();
    assert!(!e.is_empty());
    let l1 = extend(&outer, &l0, grant(&door_a.key(), &[], &a7, t + 60, Some((DO_INNER, 5)))).unwrap();
    let l2 = extend(&door_a, &l1, grant(&agent.key(), &[], &a7, t + 50, Some((DO_INNER, 4)))).unwrap();
    // outside the uplink: the agent holds no net:connect
    assert!(check(&door_a, &a7, &roots, &declared(), &agent.key(), "net:connect", &[l0.clone(), l1.clone(), l2.clone()]).is_err());
    // a wider right: the mint refuses, and a hand-signed link is refused at the door
    assert!(extend(&agent, &l2, grant(&app.key(), &["notes.app:delete"], &a7, t + 40, None)).is_err());
    let ok = extend(&agent, &l2, grant(&app.key(), &["notes.app:add"], &a7, t + 40, None)).unwrap();
    let bad = forged(&agent, &ok, |c| c.abilities = strs(&["notes.app:delete"]));
    assert!(check(&door_a, &a7, &roots, &declared(), &app.key(), "notes.app:delete", &[l0.clone(), l1.clone(), l2.clone(), bad]).is_err());
    // the same chain replayed at the inner box's door: scoped to a7, not a7/b2 (CES-8 B2)
    let e = check(&door_b, &path_of("a7/b2"), &roots, &declared(), &app.key(), "notes.app:add", &[l0, l1, l2, ok]).unwrap_err();
    assert!(!e.is_empty(), "{e}");
}

#[test]
fn calc_and_notes_text() {
    assert_eq!(calc("3*4").unwrap(), 12);
    assert_eq!(calc("(2+3)*4-6/2").unwrap(), 17);
    assert!(calc("1/0").is_err());
    assert!(calc("2**3").is_err());
    assert_eq!(find_expr("order 3*4 bolts"), Some("3*4".into()));
    assert_eq!(find_expr("call me at 3"), None);
}
