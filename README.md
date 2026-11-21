# live-nested

A live system of recursive containers and recursive narrowed capabilities on ce-net
([CES-8](https://github.com/ce-net/ce-net-proto/blob/main/docs/standards/CES-8-nesting.md)).

`nest.outer` is one cell with a typed contract. Inside it, box `a7` holds an inner door and three inner cells.
One of those cells, `calc.run`, holds box `a7/b2` with `calc.exec`. A call from another machine goes through
both boxes. At every boundary the cap v3 chain gains one link, and each new link carries fewer rights, less
depth, an earlier expiry and a scope one box deeper. Every inner door checks the whole chain with
`ce_net_proto::ces8::authorize_inner` before an inner cell acts.

```
caller (any machine) --TCP--> nest.outer                       exports Do, Prove, render:tree; nothing else
                                 | one link: scope box:a7, may grant notes.app:add, notes.app:list, calc.exec:eval
                                 v
                    box a7 (bwrap, no network) -- door a7
                       notes.agent  scripted, no model
                       notes.app    a notes program behind wrap-tool's allowlist (ce wrap)
                       calc.run     a holder
                                 | one link: scope box:a7 box:a7/b2, may grant calc.exec:eval
                                 v
                    box a7/b2 (bwrap inside bwrap, no network) -- door a7/b2
                       calc.exec    integers, + - * / ( )
```

`Do { AddNote { text: "order 3*4 bolts" } }`: the agent finds `3*4` and asks `calc.run`. `calc.run` adds one
link into box `a7/b2`, where `calc.exec` returns 12. Then the agent asks `notes.app` to store
`order 3*4 bolts (= 12)`. The answer is typed. It holds the note, the calculation and the chain that each door
accepted:

```
door a7/b2 let calc.exec use calc.exec:eval:
  owner        -> nest.outer   uses []  may grant [notes.app:add, notes.app:list, calc.exec:eval, net:connect]  depth 6  scope any
  nest.outer   -> door a7      uses []  may grant [notes.app:add, notes.app:list, calc.exec:eval]  depth 5  scope box:a7
  door a7      -> notes.agent  uses []  may grant [notes.app:add, notes.app:list, calc.exec:eval]  depth 4  scope box:a7
  notes.agent  -> calc.run     uses [calc.exec:eval]  may grant [calc.exec:eval]  depth 3  scope box:a7
  calc.run     -> door a7/b2   uses []  may grant [calc.exec:eval]  depth 2  scope box:a7 box:a7/b2
  door a7/b2   -> calc.exec    uses [calc.exec:eval]  may grant []  depth 0  scope box:a7 box:a7/b2
```

`Prove` makes four attempts that must fail, and shows each refusal:

1. **An inner cell called from outside.** `nest.outer` exports only its own ops, and the holder's own unscoped
   chain is refused at door a7.
2. **An inner cell calling outside its uplink.** The agent holds no `net:connect`, `[box.uplink]` is empty, and
   the box has no network.
3. **A right wider than delegated.** cap v3 refuses to mint `notes.app:delete`. A hand-signed link with that
   right is refused at the door, and so is a link deeper than its parent.
4. **Box a7/b2 reaching the network.** `calc.exec` holds a valid chain, and its TCP connect still fails.

## Run it

You need Rust and, for real boxes, bubblewrap (`apt install bubblewrap`) on a kernel that allows unprivileged
user namespaces.

```sh
git clone https://github.com/ce-net/live-nested && cd live-nested
cargo test --release                                   # chains in one process, then the whole tree as processes
cargo build --release
target/release/nest outer --listen 0.0.0.0:7790 --ttl 900 --box bwrap &
target/release/nest call <host>:7790 '{"Do":{"AddNote":{"text":"order 3*4 bolts"}}}'
target/release/nest call <host>:7790 '{"Prove":{}}'
target/release/nest call <host>:7790 '{"notes.app:add":{"text":"x"}}'    # refused: not exported
```

`--box none` runs the same tree without namespaces, for a machine where bubblewrap cannot start. The chain
refusals stay the same. The network refusals are not shown, because nothing stops the connect.

## Small while idle (CES-1)

Every process blocks on its socket. There is no polling and no heartbeat. The only timer is the lease:
`nest.outer` exits at `--ttl`, and both boxes end with it (`bwrap --die-with-parent`, or `PR_SET_PDEATHSIG`
without bwrap). The run owner's key exists only in `nest.outer`'s memory. It signs one root link and is then
dropped, so no secret is written anywhere. Each door and cell makes its own key when it starts.
[`cell.toml`](cell.toml) declares the budget and the box: `[box.export.<Op>] inner` lists what each op may give
the inner network, and `[box.uplink]` is empty.

## Page

[ce-net.github.io/live-nested](https://ce-net.github.io/live-nested/) has a simulation you can step through
(marked as one) and the recorded run from a real node: the answer, the chains, the four refusals and the idle
numbers measured with `cell-audit idle`.

## License

Apache-2.0. It builds on [ce-net-proto](https://github.com/ce-net/ce-net-proto) (cap v3, CES-8) and on
wrap-tool from [demo-wrap-anything](https://github.com/ce-net/demo-wrap-anything).
