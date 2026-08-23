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
    "ok": "dim",
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
    #table { margin: 1 2 0 2; height: 1fr; border: round $primary 30%; }
    #compare { margin: 1 2; height: 12; border: round $primary 30%; padding: 0 2; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("a", "only_flagged", "Flagged only"),
        ("f", "show_all", "Full sequence"),
    ]
    TITLE = "PRAHARI"
    SUB_TITLE = " boot integrity"

    def __init__(self, logs="boots"):
        super().__init__()
        self.logs = Path(logs)
        self.events, self.marks, self.flagged_only = [], {}, False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="stats"):
            yield Stat("baseline")
            yield Stat("this boot")
            yield Stat("flagged")
            yield Stat("verdict")
        yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
        yield Static(id="compare")
        yield Footer()

    def on_mount(self):
        t = self.query_one(DataTable)
        t.add_column("#", width=6)
        t.add_column("Status", width=11)
        t.add_column("Measurement")
        t.add_column("Why", width=44)
        self.analyse()

    @work(thread=True)
    def analyse(self):
        files = sorted(self.logs.glob("*.log"))
        if len(files) < 2:
            self.call_from_thread(self.fail, f"need 2+ logs in {self.logs}/")
            return
        boots = [parse.read(f) for f in files]
        base = detect.Baseline(3)
        for b in boots[:-1]:
            base.learn(b)
        # show the holdout boot under the substitution attack: the case where
        # every hash is valid and only the ordering gives it away
        events, _ = inject.apply(boots[-1], "substitute", 0)
        findings = base.check(events)

        table = []
        for name in inject.ATTACKS:
            attacked, _ = inject.apply(boots[-1], name, 0)
            kinds = {f.kind for f in base.check(attacked)}
            table.append((name, bool(kinds & {"tampered", "unknown"}), bool(kinds)))

        self.call_from_thread(self.show, base, events, findings, table)

    def fail(self, msg):
        self.query_one("#compare", Static).update(Text(msg, style="bold red"))

    def show(self, base, events, findings, comparison):
        self.events = events
        self.marks = {}
        for f in findings:
            if f.kind != "sequence" or f.position not in self.marks:
                self.marks[f.position] = f

        s = self.query(Stat)
        s[0].set(f"{base.boots} boots", f"{len(base.grams):,} known transitions")
        s[1].set(f"{len(events):,} events", "measured in order")
        s[2].set(f"{len(self.marks)}", "off baseline")
        ok = not self.marks
        s[3].set("TRUSTED" if ok else "ANOMALOUS", "signatures all valid",
                 style="bold green" if ok else "bold red")

        rows = []
        for name, allowlist, ours in comparison:
            rows.append(Text.assemble(
                (f"  {name:<14}", "bold"),
                (f"{'DETECT' if allowlist else 'MISS':<12}",
                 "green" if allowlist else "bold red"),
                ("DETECT" if ours else "MISS", "green" if ours else "bold red")))
        header = Text.assemble(
            ("\n  same four attacks, both detectors\n\n", "dim italic"),
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
                Text(kind, style=STATUS_STYLE[kind]),
                Text(label, style="dim" if not f else ""),
                Text(f.detail[:44] if f else "", style="dim"))

    def action_only_flagged(self):
        self.flagged_only = True
        self.fill()

    def action_show_all(self):
        self.flagged_only = False
        self.fill()


def run(logs="boots"):
    Prahari(logs).run()
