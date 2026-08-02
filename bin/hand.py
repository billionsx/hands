#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
РУКА · орган исполнения (ст. 5).

Рука не классифицирует (ст. 6) и не решает, что чинить. Она исполняет ровно
то, что разрешил губернатор, ровно в тех пределах, что объявил паспорт, и
откатывает себя сама при любом расхождении инвариантов (ст. 35).

Порядок неизменен и обхода не имеет:
    диагност → губернатор → радиус → снимок ДО → правка → снимок ПОСЛЕ →
    сверка → (расхождение ⇒ откат) → хроника

Починка существует только у законов, объявивших вид `ast_equal` или `format`.
Для всех прочих рука строит дифф и НЕ прикладывает его: К2 есть инструкция
человеку, а не отложенное исполнение.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

import diagnose as D        # noqa: E402
import governor as G        # noqa: E402
import invariants as INV    # noqa: E402


# --------------------------------------------------------------- починки ----
def fix_unused_import(text: str, line_no: int, name: str) -> str | None:
    """ЗКН-Х112 · снять мёртвое имя из импорта. Механически обратимо."""
    lines = text.splitlines(keepends=True)
    if not (0 < line_no <= len(lines)):
        return None
    ln = lines[line_no - 1]
    if "{" in ln and "}" in ln:
        inner = ln[ln.index("{") + 1:ln.rindex("}")]
        kept = [p for p in (x.strip() for x in inner.split(","))
                if p and p.split(" as ")[-1].strip() != name]
        if len(kept) == len([p for p in (x.strip() for x in inner.split(",")) if p]):
            return None
        if not kept:
            lines[line_no - 1] = ""          # импорт опустел — строка уходит
        else:
            lines[line_no - 1] = ln[:ln.index("{") + 1] + " " + ", ".join(kept) + " " + ln[ln.rindex("}"):]
    elif re.search(rf"import\s+{re.escape(name)}\s+from", ln):
        lines[line_no - 1] = ""
    else:
        return None
    return "".join(lines)


FIXERS = {"ЗКН-Х112": fix_unused_import}


# ------------------------------------------------------------------ ход ----
def git(root: Path, *a) -> str:
    return subprocess.run(["git", *a], cwd=root, capture_output=True, text=True).stdout.strip()


def run(root: Path, passport: dict, apply: bool = False) -> dict:
    laws = G.load_laws()
    gov = G.Governor(laws, passport)
    radius = passport.get("radius", {})
    max_commits = radius.get("max_commits_per_day", 3)
    max_files = radius.get("max_files_per_commit", 4)

    scan = D.diagnose(root, passport)
    if scan["empty_walk"]:
        return {"status": "КРАСНЫЙ", "why": "пустой обход — промах адреса (ст. 43)"}

    decided = []
    for f in scan["findings"]:
        d = gov.classify(f["law"], f["address"].split(":")[0].replace("file:", ""))
        decided.append({**f, "class": d["class"], "executable": d["executable"],
                        "reasons": d["reasons"]})

    executable = [d for d in decided if d["executable"] and d["law"] in FIXERS]
    blocked = [d for d in decided if not d["executable"]]

    report = {
        "снято": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "проект": passport.get("project"),
        "обойдено": scan["walked"],
        "находок": len(decided),
        "по_законам": scan["by_law"],
        "по_классам": _tally(decided),
        "исполнимо": len(executable),
        "не_исполняется": len(blocked),
        "радиус": {"коммитов_в_сутки": max_commits, "файлов_в_коммите": max_files},
        "применено": [],
        "откат": None,
    }
    if not apply or not executable:
        report["status"] = "ДОКЛАД"
        return report

    # ---- окно и радиус: ровно один закон в коммите (ст. 30) ----
    law_id = executable[0]["law"]
    batch = [d for d in executable if d["law"] == law_id][:max_files]

    before = INV.snapshot(root, passport)
    touched = []
    for d in batch:
        rel, ln = d["address"].rsplit(":", 1)
        p = root / rel
        name = re.search(r"«([^»]+)»", d["why"])
        new = FIXERS[law_id](p.read_text(encoding="utf-8"), int(ln),
                             name.group(1) if name else "")
        if new is None:
            continue
        p.write_text(new, encoding="utf-8")
        touched.append(d["address"])

    after = INV.snapshot(root, passport)
    diffs = INV.compare(before, after, passport.get("intent"))

    if diffs:
        # Ст. 35 · расхождение не обсуждается и флагом не переопределяется.
        git(root, "checkout", "--", ".")
        report["status"] = "ОТКАЧЕНО"
        report["откат"] = INV.render(diffs)
        return report

    report["status"] = "ИСПОЛНЕНО"
    report["применено"] = touched
    report["коммит"] = f"{law_id} · {G.NAMES[batch[0]['class']]} · {len(touched)} мест"
    return report


def _tally(items):
    t: dict[str, int] = {}
    for i in items:
        t[i["class"]] = t.get(i["class"], 0) + 1
    return dict(sorted(t.items()))


def render(r: dict) -> str:
    if r.get("status") == "КРАСНЫЙ":
        return f"КРАСНЫЙ · {r['why']}"
    out = [f"{r['status']} · проект {r['проект']} · обойдено {r['обойдено']} · находок {r['находок']}"]
    out.append("  по классам: " + ", ".join(f"{k}={v}" for k, v in r["по_классам"].items()))
    out.append(f"  исполнимо рукой: {r['исполнимо']} · не исполняется: {r['не_исполняется']}")
    if r.get("применено"):
        out.append("  применено:")
        out += [f"    {a}" for a in r["применено"]]
    if r.get("откат"):
        out.append("  " + r["откат"].replace("\n", "\n  "))
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("использование: hand.py <корень> <паспорт.json> [--apply]")
        return 2
    passport = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    r = run(Path(argv[1]), passport, apply="--apply" in argv)
    print(render(r))
    return 1 if r.get("status") in ("КРАСНЫЙ", "ОТКАЧЕНО") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
