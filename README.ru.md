[English](README.md) · **Русский**

# wireguard-go (lx-форк) — sagernet + AmneziaWG 2.0

Рантайм WireGuard-Go для **[sing-box-lx](https://github.com/Leadaxe/sing-box-lx)**:
**[sagernet/wireguard-go](https://github.com/sagernet/wireguard-go)** (форк, на котором собирается sing-box) **+ обфускация AmneziaWG 2.0**, слитые вместе.

Это **не** универсальный проект. Он существует ради одной задачи (см. ниже) и живёт на ветке **`lx`**.

---

## Зачем этот форк

WireGuard-endpoint sing-box нуждается в добавках **sagernet/wireguard-go** (контракт `conn.Bind.Send(…, offset)`, `device.InputPacket`, reserved/control). Обфускация против DPI у AmneziaWG живёт в **[amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)**, который форкнут от *upstream* wireguard-go и потому этих sagernet-добавок **не имеет**.

Значит для sing-box-lx ни один форк по отдельности не подходит:

| | API под sing-box | обфускация AmneziaWG |
|---|:---:|:---:|
| `sagernet/wireguard-go` | ✅ | ❌ |
| `amnezia-vpn/amneziawg-go` | ❌ | ✅ |
| **этот форк** | ✅ | ✅ |

Подход: **берём sagernet-базу и граффтим обфускацию на неё** — а не наоборот (не дотачиваем sagernet-API к amneziawg-go, иначе даже обычный WireGuard шёл бы через чужой device). Так sing-box компилируется без изменений, обфускация аддитивна и выключена по умолчанию, а конфиг без AWG-полей ведёт себя как обычный WireGuard.

## Как устроен merge

И `sagernet/wireguard-go`, и `amneziawg-go` происходят от одного upstream `git.zx2c4.com/wireguard-go`, поэтому делят git-историю — а значит возможен настоящий **3-way merge** (а не ручной перенос).

- **База:** `sagernet/wireguard-go` (тот коммит, что пинит sing-box — сейчас `506b7631853c`).
- **Вливаем:** `amnezia-vpn/amneziawg-go` (тип с AWG2 / I1–I5 + фикс S4-keepalive).
- **Ключевой трюк:** `MessageEncapsulatingTransportSize` выставлен в **`0`** в `device/noise-protocol.go`. sing-box-lx не использует 8-байтный headroom sagernet для `Bind.Send`, и обнуление позволяет обфускации AmneziaWG встать чисто, без конфликтов в send-пути.
- **Изоляция:** обфускация замкнута в `device/` — новые файлы `device/obf*.go`, `device/magic-header.go` + графты в `device/{send,receive,device,uapi}.go`. **`conn/`, `tun/`, `ipc/` остаются чистым sagernet.**
- **Module-path не меняется** (`module github.com/sagernet/wireguard-go`), поэтому потребитель подключает форк через `replace` без правки импортов.

## Кто потребляет

[sing-box-lx](https://github.com/Leadaxe/sing-box-lx) подключает это как git submodule + `replace`:

```
# sing-box-lx/.gitmodules
[submodule "submodules/wireguard-go"]
    url = https://github.com/Leadaxe/wireguard-go-awg2-lx
    branch = lx

# sing-box-lx/go.mod   (// lx)
replace github.com/sagernet/wireguard-go => ./submodules/wireguard-go
```

Собранный с тегом `with_awg`, он **проверен живым** сервером AmneziaWG 2.0 (handshake + keepalive + трафик наружу) и кросс-компилируется на linux/darwin/windows × amd64/arm64.

## Сопровождение (ребейз на новый sagernet-тег)

Когда sing-box бампит `sagernet/wireguard-go`, повторяем merge:

```sh
git remote add origin  https://github.com/sagernet/wireguard-go    # база
git remote add amnezia https://github.com/amnezia-vpn/amneziawg-go # источник обфускации
git fetch --all
git checkout -b lx <новый-sagernet-коммит>
git merge amnezia/master          # настоящий 3-way merge через общего upstream-предка
```

Рецепт разрешения конфликтов:

1. Новые `device/obf*.go` + `device/magic-header.go` приходят чисто.
2. **Механические** конфликты (import-path amnezia → sagernet, `queueconstants*`, `sticky*`, `tun.go`) → берём **наши** (sagernet).
3. Удаляем amnezia-инфра-дубликаты: `conn/gso_*.go`, `outline/*`, `tun/*_test.go`.
4. `device/device.go` → **union** (sagernet `pauseManager` + obf-поля amnezia).
5. `device/send.go` / `receive.go` → берём обфускацию amnezia, ставим `MessageEncapsulatingTransportSize = 0`, сохраняем 3-арг `bind.Send(…, 0)`.
6. `conn/`, `tun/`, `ipc/`, module-path в `go.mod` → **наши** (sagernet).

Затем в sing-box-lx: бампим submodule, `make -f Makefile.lx lx-build` и пере-тест против AWG2-сервера.

## Ссылки

| | |
|---|---|
| Потребитель | [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx) |
| База | [sagernet/wireguard-go](https://github.com/sagernet/wireguard-go) |
| Источник обфускации | [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) · [docs.amnezia.org](https://docs.amnezia.org/documentation/amnezia-wg/) |
| Оригинал | [WireGuard/wireguard-go](https://git.zx2c4.com/wireguard-go/about/) |

## Лицензия

MIT, унаследована от WireGuard-Go (см. [`LICENSE`](LICENSE)). Обфускация AmneziaWG — тоже MIT (из amneziawg-go). Это неофициальный форк, не аффилирован с WireGuard, SagerNet или Amnezia.
