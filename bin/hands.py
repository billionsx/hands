#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BXH · вход департамента.  hands.py selftest | classify | snap

СУД (раздел VII). Каждая способность доказана живым нарушением в обе стороны:
ломаю → красный, чиню → зелёный. Красный суд запрещает руке всё.

Обязательный контур — суд над губернатором (ст. 38): доказывается, что
понижение класса невозможно НИ ОДНИМ входом. Это не один из тестов, это
главный тест: департамент, который может ошибиться в свою пользу, опаснее
отсутствующего департамента.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))

import governor as G          # noqa: E402
import invariants as INV      # noqa: E402

OK, BAD = "  ✓", "  ✗"
_fails: list[str] = []
_n = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _n
    _n += 1
    if cond:
        print(f"{OK} {name}")
    else:
        print(f"{BAD} {name}   {detail}")
        _fails.append(name)


# --------------------------------------------------------------------------
def court_governor() -> None:
    print("\n— СУД НАД ГУБЕРНАТОРОМ (ст. 38) —")
    laws = G.load_laws()
    passport = {
        "zones": {
            "forbidden": ["**/auth/**", "**/migrations/**", "**/*.sql", "**/payments/**"],
            "caution": ["**/api/**"],
        }
    }
    gov = G.Governor(laws, passport)

    # 1 · защищённая зона не получает класс ниже К3 — ни при каком законе.
    worst = G.K3
    for law_id in list(laws) + ["ЗКН-Х999", "мусор", ""]:
        d = gov.classify(law_id, "src/auth/session.ts")
        if G.ORDER[d["class"]] < G.ORDER[worst]:
            worst = d["class"]
    check("защищённая зона: ни один закон не опускает ниже К3", worst == G.K3,
          f"получено {worst}")

    # 2 · неизвестный закон падает в К2, а не в К0 (ЗКН-Х003).
    d = gov.classify("ЗКН-Х999", "src/util/plain.ts")
    check("неизвестный закон → не ниже К2", G.ORDER[d["class"]] >= G.ORDER[G.K2],
          f"получено {d['class']}")

    # 3 · неизвестный вид преобразования падает в К2.
    gov2 = G.Governor({"ЗКН-Т1": {"ceiling": G.K0, "probation": False}}, {})
    d = gov2.classify("ЗКН-Т1", "src/a.ts")
    check("вид не объявлен → не ниже К2", G.ORDER[d["class"]] >= G.ORDER[G.K2],
          f"получено {d['class']}")

    # 4 · закон на испытательном сроке не исполняется автоматом (ст. 32).
    gov3 = G.Governor(
        {"ЗКН-Т2": {"ceiling": G.K0, "kind": "format", "probation": True}}, {})
    d = gov3.classify("ЗКН-Т2", "src/a.ts")
    check("испытательный срок → не ниже К2", d["class"] == G.K2, f"получено {d['class']}")

    # 5 · тот же закон без испытательного срока проходит в К0 — обратная сторона.
    gov4 = G.Governor(
        {"ЗКН-Т2": {"ceiling": G.K0, "kind": "format", "probation": False}}, {})
    d = gov4.classify("ЗКН-Т2", "src/a.ts")
    check("снят испытательный срок → К0 (обратная сторона)", d["class"] == G.K0,
          f"получено {d['class']}")

    # 6 · удаление никогда не автомат, даже вне зон.
    gov5 = G.Governor(
        {"ЗКН-Т3": {"ceiling": G.K0, "kind": "deletion", "probation": False}}, {})
    d = gov5.classify("ЗКН-Т3", "src/free.ts")
    check("удаление вне зон → не ниже К2", G.ORDER[d["class"]] >= G.ORDER[G.K2],
          f"получено {d['class']}")

    # 7 · строжайший побеждает: сложение не имеет понижающих ветвей.
    mono = all(
        G.ORDER[G.stricter(a, b)] >= max(G.ORDER[a], G.ORDER[b])
        for a in G.ORDER for b in G.ORDER
    )
    check("сложение классов монотонно (ст. 28)", mono)

    # 8 · каждое решение объяснено: решение без причины неотличимо от произвола.
    d = gov.classify("ЗКН-Х101", "src/config/keys.ts")
    check("решение несёт причины", bool(d["reasons"]) and "class" in d)

    # 9 · К3 никогда не исполняется рукой.
    ex = [gov.classify(l, "src/migrations/001.sql")["executable"] for l in laws]
    check("К3 не помечается исполнимым", not any(ex))

    # 10 · полнота кодекса: каждый закон несёт статью, потолок и проверку.
    bad = [k for k, v in laws.items()
           if not all(v.get(f) for f in ("article", "ceiling", "check", "kind"))]
    check("каждый закон несёт статью · потолок · вид · проверку", not bad, str(bad))


# --------------------------------------------------------------------------
def court_invariants() -> None:
    print("\n— СУД НАД ИНВАРИАНТАМИ (ст. 33–36) —")
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "src"
    src.mkdir()
    (src / "routes.ts").write_text(
        'export const routes = [{ path: "/home" }, { path: "/about" }];\n'
        'export function mount() { return fetch("https://api.example.com/v1"); }\n',
        encoding="utf-8")
    (src / "cfg.ts").write_text(
        'export const key = process.env.SECRET_KEY;\n', encoding="utf-8")
    passport = {"globs": ["src/**/*.ts"], "invariants": ["routes", "exports", "hosts", "env"]}

    before = INV.snapshot(tmp, passport)
    check("снимок видит маршруты", before["routes"] == ["/about", "/home"], str(before["routes"]))
    check("снимок видит публичную поверхность", len(before["exports"]) == 3, str(before["exports"]))
    check("снимок видит хост исхода", before["hosts"] == ["api.example.com"], str(before["hosts"]))
    check("снимок видит переменную окружения", before["env"] == ["SECRET_KEY"], str(before["env"]))

    # неизменённое дерево → инварианты сходятся (обратная сторона).
    check("без правки расхождений нет", INV.compare(before, INV.snapshot(tmp, passport)) == [])

    # ломаю: «безобидный» рефакторинг роняет маршрут, тесты бы этого не увидели.
    (src / "routes.ts").write_text(
        'export const routes = [{ path: "/home" }];\n'
        'export function mount() { return fetch("https://api.example.com/v1"); }\n',
        encoding="utf-8")
    diffs = INV.compare(before, INV.snapshot(tmp, passport))
    lost = [d for d in diffs if d["invariant"] == "routes" and "/about" in d["gone"]]
    check("утрата маршрута поймана (ломаю → красный)", bool(lost), str(diffs))

    # чиню → зелёный.
    (src / "routes.ts").write_text(
        'export const routes = [{ path: "/home" }, { path: "/about" }];\n'
        'export function mount() { return fetch("https://api.example.com/v1"); }\n',
        encoding="utf-8")
    check("после починки расхождений нет (чиню → зелёный)",
          INV.compare(before, INV.snapshot(tmp, passport)) == [])

    # смена хоста исхода — красная независимо от намерения (ст. 11).
    (src / "routes.ts").write_text(
        'export const routes = [{ path: "/home" }, { path: "/about" }];\n'
        'export function mount() { return fetch("https://evil.example.net/v1"); }\n',
        encoding="utf-8")
    d = INV.compare(before, INV.snapshot(tmp, passport))
    check("новый хост исхода пойман", any(x["invariant"] == "hosts" and x["new"] for x in d))

    # заявленное намерение снимает контроль ТОЛЬКО с названного инварианта.
    d2 = INV.compare(before, INV.snapshot(tmp, passport), intent=["hosts"])
    check("намерение снимает только названный инвариант",
          all(x["invariant"] != "hosts" for x in d2))
    (src / "routes.ts").write_text('export const routes = [{ path: "/x" }];\n', encoding="utf-8")
    d3 = INV.compare(before, INV.snapshot(tmp, passport), intent=["hosts"])
    check("намерение по hosts не прикрывает routes",
          any(x["invariant"] == "routes" for x in d3))

    shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
def court_rollback() -> None:
    """Ст. 39: недоказанный откат равен отсутствующему."""
    print("\n— СУД НАД ОТКАТОМ (ст. 39) —")
    tmp = Path(tempfile.mkdtemp())
    run = lambda *a: subprocess.run(a, cwd=tmp, capture_output=True, text=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "hands@billionsx")
    run("git", "config", "user.name", "BXH")
    f = tmp / "a.ts"
    f.write_text('export const routes = [{ path: "/home" }];\n', encoding="utf-8")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "base")
    base = run("git", "rev-parse", "HEAD").stdout.strip()
    tree0 = run("git", "rev-parse", "HEAD^{tree}").stdout.strip()

    # рука пишет вредное изменение и коммитит
    f.write_text('export const routes = [];\n', encoding="utf-8")
    run("git", "add", "-A")
    run("git", "commit", "-qm", "ЗКН-Х110 · К1")
    check("вредный коммит лёг", run("git", "rev-parse", "HEAD").stdout.strip() != base)

    # инвариант разошёлся → откат обязателен
    run("git", "revert", "--no-edit", "HEAD")
    tree1 = run("git", "rev-parse", "HEAD^{tree}").stdout.strip()
    check("после отката дерево байт-в-байт исходное", tree0 == tree1, f"{tree0[:8]}≠{tree1[:8]}")
    check("откат оставил след в истории (хроника не переписывается)",
          len(run("git", "log", "--oneline").stdout.strip().splitlines()) == 3)
    shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
def court_constitution() -> None:
    """Ст. 40: каждый домен мандата несёт статью, каждый закон — статью кодекса."""
    print("\n— СУД НАД ПОЛНОТОЙ (ст. 40) —")
    text = (ROOT / "CONSTITUTION.md").read_text(encoding="utf-8")
    laws = G.load_laws()
    arts = set()
    for line in text.splitlines():
        if line.startswith("**Статья "):
            arts.add(line.split("Статья ", 1)[1].split(" ", 1)[0].rstrip("."))
    missing = sorted({str(v["article"]) for v in laws.values()} - arts)
    check("каждый закон опирается на существующую статью", not missing, str(missing))
    core = ["ЗКН-Х001", "ЗКН-Х002", "ЗКН-Х003", "ЗКН-Х004"]
    check("верховные законы объявлены", all(c in text for c in core))
    check("неизменяемое ядро объявлено (ст. 47)", "Статья 47" in text)
    check("хроника существует", (ROOT / "registry" / "state").is_dir())


def selftest() -> int:
    print("СУД ДЕПАРТАМЕНТА BXH")
    court_governor()
    court_invariants()
    court_rollback()
    court_constitution()
    print(f"\nпроверок: {_n} · провалено: {len(_fails)}")
    if _fails:
        print("КРАСНЫЙ — руке запрещено всё:")
        for f in _fails:
            print(f"   · {f}")
        return 1
    print("ЗЕЛЁНЫЙ")
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "selftest"
    if cmd == "selftest":
        return selftest()
    if cmd == "classify":
        return G.main(["governor.py"] + argv[2:])
    if cmd == "snap":
        return INV.main(["invariants.py", "snap"] + argv[2:])
    print("использование: hands.py selftest | classify <паспорт> <закон> <путь> | snap <корень> <паспорт>")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
