**English** · [Русский](README.ru.md)

# wireguard-go (lx fork) — sagernet + AmneziaWG 2.0

The WireGuard-Go runtime used by **[sing-box-lx](https://github.com/Leadaxe/sing-box-lx)**:
**[sagernet/wireguard-go](https://github.com/sagernet/wireguard-go)** (the fork sing-box builds on) **+ AmneziaWG 2.0 obfuscation**, merged together.

This is **not** a general-purpose project. It exists for one reason — see below — and lives on the **`lx`** branch.

---

## Why this fork exists

sing-box's WireGuard endpoint needs **sagernet/wireguard-go**'s additions (the `conn.Bind.Send(…, offset)` contract, `device.InputPacket`, reserved/control). AmneziaWG's DPI-evasion obfuscation lives in **[amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)**, which is a fork of *upstream* wireguard-go and therefore **lacks** those sagernet additions.

So neither fork alone works for sing-box-lx:

| | sing-box-compat API | AmneziaWG obfuscation |
|---|:---:|:---:|
| `sagernet/wireguard-go` | ✅ | ❌ |
| `amnezia-vpn/amneziawg-go` | ❌ | ✅ |
| **this fork** | ✅ | ✅ |

Each existing fork gives exactly **half** of what's needed:

- **Take `sagernet/wireguard-go`** → sing-box-lx compiles and runs, but the AWG fields (`jc`/`h1`/`i1`…) do nothing → **no obfuscation**; AmneziaWG doesn't actually work.
- **Take `amnezia-vpn/amneziawg-go`** → the obfuscation is there, but sing-box-lx **won't even compile** (the sagernet functions are missing).

We need **both** ✅ at once, and no ready-made fork has them — so we built one by **merging**: sagernet (for the API) + amnezia (for the obfuscation). That is exactly the **"this fork"** row above.

The approach: **keep the sagernet base and graft the obfuscation onto it** — rather than the reverse (adding sagernet's APIs to amneziawg-go, which would route even plain WireGuard through a foreign device). This way sing-box compiles unchanged, the obfuscation is additive and off by default, and a config without AWG fields behaves exactly like plain WireGuard.

## How the merge works

Both `sagernet/wireguard-go` and `amneziawg-go` descend from the same upstream `git.zx2c4.com/wireguard-go`, so they share git history — which makes a real **3-way merge** possible (not a hand-port).

- **Base:** `sagernet/wireguard-go` (the exact commit sing-box pins — currently `506b7631853c`).
- **Merged in:** `amnezia-vpn/amneziawg-go` (a tip with AWG2 / I1–I5 + the S4-keepalive fix).
- **Key trick:** `MessageEncapsulatingTransportSize` is set to **`0`** in `device/noise-protocol.go`. sing-box-lx does not use sagernet's 8-byte `Bind.Send` headroom, and zeroing it makes the AmneziaWG obfuscation compose cleanly with no weave conflicts in the packet send path.
- **Isolation:** the obfuscation is confined to `device/` — new files `device/obf*.go`, `device/magic-header.go`, plus grafts in `device/{send,receive,device,uapi}.go`. **`conn/`, `tun/`, `ipc/` stay pure sagernet.**
- **Module path is unchanged** (`module github.com/sagernet/wireguard-go`) so the consumer plugs it in with a `replace` directive and needs **no import edits**.

## Consumed by

[sing-box-lx](https://github.com/Leadaxe/sing-box-lx) wires this in as a git submodule + a `replace`:

```
# sing-box-lx/.gitmodules
[submodule "submodules/wireguard-go"]
    url = https://github.com/Leadaxe/wireguard-go-awg2-lx
    branch = lx

# sing-box-lx/go.mod   (// lx)
replace github.com/sagernet/wireguard-go => ./submodules/wireguard-go
```

Built with the `with_awg` tag, it has been **live-validated** against a real AmneziaWG 2.0 server (handshake + keepalive + outbound traffic) and cross-compiles on linux/darwin/windows × amd64/arm64.

## Maintaining it (rebase onto a new sagernet tag)

When sing-box bumps `sagernet/wireguard-go`, redo the merge:

```sh
git remote add origin  https://github.com/sagernet/wireguard-go    # base
git remote add amnezia https://github.com/amnezia-vpn/amneziawg-go # obfuscation source
git fetch --all
git checkout -b lx <new-sagernet-commit>
git merge amnezia/master          # real 3-way merge via the shared upstream ancestor
```

Conflict resolution recipe:

1. New `device/obf*.go` + `device/magic-header.go` come in clean.
2. **Mechanical** conflicts (amnezia → sagernet import paths, `queueconstants*`, `sticky*`, `tun.go`) → take **ours** (sagernet).
3. Remove amnezia-added infra duplicates: `conn/gso_*.go`, `outline/*`, `tun/*_test.go`.
4. `device/device.go` → **union** (sagernet `pauseManager` + amnezia obf fields).
5. `device/send.go` / `receive.go` → take amnezia's obfuscation, set `MessageEncapsulatingTransportSize = 0`, and keep the 3-arg `bind.Send(…, 0)` calls.
6. `conn/`, `tun/`, `ipc/`, `go.mod` module path → **ours** (sagernet).

Then in sing-box-lx: bump the submodule, `make -f Makefile.lx lx-build`, and re-test against an AWG2 server.

## Links

| | |
|---|---|
| Consumer | [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx) |
| Base | [sagernet/wireguard-go](https://github.com/sagernet/wireguard-go) |
| Obfuscation source | [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) · [docs.amnezia.org](https://docs.amnezia.org/documentation/amnezia-wg/) |
| Original | [WireGuard/wireguard-go](https://git.zx2c4.com/wireguard-go/about/) |

## License

MIT, inherited from WireGuard-Go (see [`LICENSE`](LICENSE)). The AmneziaWG obfuscation is likewise MIT (from amneziawg-go). This is an unofficial fork, not affiliated with WireGuard, SagerNet, or Amnezia.
