"""The interface.

The claim of this project is that boot integrity lives in the order of events,
so the screen shows the order: every measurement the kernel made, in sequence,
with the ones that broke the baseline marked. Underneath, the same four attacks
run past both detectors so you can see which ones an allowlist sleeps through.

Built on Textual.
"""
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Static

from . import detect, inject, parse, tokens

STATUS_STYLE = {
    "ok": "bold green",
    "sequence": "bold yellow",
    "unknown": "bold red",
    "tampered": "bold red",
}


class Stat(Static):
    def __init__(self, label):
        super().__init__()
        self.label = label

    def on_mount(self):
        self.set("-")

    def set(self, value, note="", style="bold"):
        self.update(Text.assemble(
            (self.label.upper() + "\n", "dim"),
            (value + "\n", style),
            (note, "dim italic")))


class Prahari(App):
    CSS = """
    Screen { background: $surface; }
    #stats { height: 7; margin: 1 2 0 2; }
    Stat {
        width: 1fr; height: 7; padding: 1 2; margin-right: 1;
        border: round $primary 40%;
    }
    #mode-bar { margin: 0 2; padding: 0 1; color: $accent; text-style: italic; }
    #table { margin: 1 2 0 2; height: 1fr; border: round $primary 30%; }
    #compare { margin: 1 2; height: 13; border: round $primary 30%; padding: 0 2; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "sim_clean", "Clean Boot"),
        ("t", "sim_tamper", "Tamper"),
        ("i", "sim_insert", "Insert"),
        ("r", "sim_reorder", "Reorder"),
        ("s", "sim_substitute", "Substitute"),
        ("a", "only_flagged", "Flagged only"),
        ("f", "show_all", "Full sequence"),
    ]
    TITLE = "PRAHARI"
    SUB_TITLE = " Behavioural Boot Attestation & Sequence Anomaly Detector"

    def __init__(self, logs="boots"):
        super().__init__()
        self.logs = Path(logs)
        self.events, self.marks, self.flagged_only = [], {}, False
        self.sim_mode = "substitute"
        self.base = None
        self.clean_boot = None
        self.comparison = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="stats"):
            yield Stat("baseline")
            yield Stat("this boot")
            yield Stat("flagged")
            yield Stat("verdict")
        yield Static("Active Simulation: substitute", id="mode-bar")
        yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
        yield Static(id="compare")
        yield Footer()

    def on_mount(self):
        t = self.query_one(DataTable)
        t.add_column("#", width=6)
        t.add_column("Status", width=12)
        t.add_column("Measurement")
        t.add_column("Why / Transition Detail", width=48)
        self.analyse()

    @work(thread=True)
    def analyse(self):
        files = sorted(self.logs.glob("*.log"))
        if len(files) < 2:
            self.call_from_thread(self.fail, f"need 2+ logs in {self.logs}/")
            return
        boots = [parse.read(f) for f in files]
        self.base = detect.Baseline(3)
        for b in boots[:-1]:
            self.base.learn(b)
        self.clean_boot = boots[-1]

        self.comparison = []
        for name in inject.ATTACKS:
            attacked, _ = inject.apply(self.clean_boot, name, 0)
            kinds = {f.kind for f in self.base.check(attacked)}
            self.comparison.append((name, bool(kinds & {"tampered", "unknown"}), bool(kinds)))

        self.call_from_thread(self.apply_mode, self.sim_mode)

    def fail(self, msg):
        self.query_one("#compare", Static).update(Text(msg, style="bold red"))

    def apply_mode(self, mode):
        self.sim_mode = mode
        if mode == "clean":
            events = self.clean_boot
            mode_desc = "CLEAN BOOT (Unmodified holdout sequence)"
        else:
            events, _ = inject.apply(self.clean_boot, mode, 0)
            mode_desc = f"{mode.upper()} ATTACK ({'Hash intact, anomalous order' if mode in ('reorder','substitute') else 'Hash corrupted or new token'})"

        findings = self.base.check(events)
        self.events = events
        self.marks = {}
        for f in findings:
            if f.kind != "sequence" or f.position not in self.marks:
                self.marks[f.position] = f

        self.query_one("#mode-bar", Static).update(
            Text.assemble(("Simulation: ", "dim"), (mode_desc, "bold cyan")))

        s = self.query(Stat)
        s[0].set(f"{self.base.boots} boots", f"{len(self.base.grams):,} known transitions")
        s[1].set(f"{len(events):,} events", "measured in order")
        s[2].set(f"{len(self.marks)}", "off baseline", style="bold red" if self.marks else "bold green")
        ok = not self.marks
        s[3].set("TRUSTED" if ok else "ANOMALOUS",
                 "baseline matched" if ok else ("hash valid, order broken" if mode in ("reorder", "substitute") else "signature/hash failed"),
                 style="bold green" if ok else "bold red")

        rows = []
        for name, allowlist, ours in self.comparison:
            is_active = (name == self.sim_mode)
            prefix = "▶ " if is_active else "  "
            style_name = "bold cyan" if is_active else "bold"
            rows.append(Text.assemble(
                (f"{prefix}{name:<14}", style_name),
                (f"{'DETECT' if allowlist else 'MISS':<12}",
                 "green" if allowlist else "bold red"),
                ("DETECT" if ours else "MISS", "green" if ours else "bold red")))
        header = Text.assemble(
            ("\n  same four attacks, both detectors (keys: [c]lean [t]amper [i]nsert [r]eorder [s]ubstitute)\n\n", "dim italic"),
            ("  attack        allowlist   behavioural\n", "dim"))
        self.query_one("#compare", Static).update(
            Text("\n").join([header] + rows))
        self.fill()

    def fill(self):
        t = self.query_one(DataTable)
        t.clear()
        labels = tokens.sequence(self.events)
        for i, label in enumerate(labels):
            f = self.marks.get(i)
            if self.flagged_only and not f:
                continue
            kind = f.kind if f else "ok"
            t.add_row(
                Text(str(i), justify="right", style="dim"),
                Text(kind.upper(), style=STATUS_STYLE[kind]),
                Text(label, style="bold" if f else "dim"),
                Text(f.detail[:48] if f else "matches baseline transition", style="dim" if not f else "bold yellow"))

    def action_sim_clean(self):
        if self.base: self.apply_mode("clean")

    def action_sim_tamper(self):
        if self.base: self.apply_mode("tamper")

    def action_sim_insert(self):
        if self.base: self.apply_mode("insert")

    def action_sim_reorder(self):
        if self.base: self.apply_mode("reorder")

    def action_sim_substitute(self):
        if self.base: self.apply_mode("substitute")

    def action_only_flagged(self):
        self.flagged_only = True
        self.fill()

    def action_show_all(self):
        self.flagged_only = False
        self.fill()


def run(logs="boots"):
    Prahari(logs).run()

