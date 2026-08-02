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
def court_hand() -> None:
    """Ст. 27–35: рука исполняет только разрешённое и откатывает себя сама."""
    print("\n— СУД НАД РУКОЙ (ст. 27–35) —")
    import hand as H  # noqa: PLC0415

    tmp = Path(tempfile.mkdtemp())
    src = tmp / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=tmp, capture_output=True)
    subprocess.run(["git", "config", "user.email", "h@b"], cwd=tmp, capture_output=True)
    subprocess.run(["git", "config", "user.name", "H"], cwd=tmp, capture_output=True)

    (src / "a.ts").write_text(
        'import { Used, Dead } from "./m";\n'
        'export const routes = [{ path: "/home" }];\n'
        'export const v = Used;\n', encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp, capture_output=True)

    base = {
        "project": "проба",
        "globs": ["src/**/*.ts"],
        "invariants": ["routes", "exports"],
        "zones": {"forbidden": [], "caution": []},
        "radius": {"max_commits_per_day": 1, "max_files_per_commit": 2},
    }

    # 1 · закон на испытательном сроке рукой не исполняется (ст. 32).
    r = H.run(tmp, base, apply=True)
    check("испытательный срок: рука не тронула ничего", r["исполнимо"] == 0)
    check("файл не изменён при отказе",
          "Dead" in (src / "a.ts").read_text(encoding="utf-8"))

    # 2 · снимаю испытательный срок — рука исполняет (обратная сторона).
    laws = json.loads((ROOT / "registry" / "library" / "laws.json").read_text(encoding="utf-8"))
    laws["laws"]["ЗКН-Х112"]["probation"] = False
    lp = tmp / "laws.json"
    lp.write_text(json.dumps(laws, ensure_ascii=False), encoding="utf-8")
    orig_load = G.load_laws
    G.load_laws = lambda p=None: json.loads(lp.read_text(encoding="utf-8"))["laws"]
    H.G.load_laws = G.load_laws
    r = H.run(tmp, base, apply=True)
    check("без испытательного срока рука исполнила", r["status"] == "ИСПОЛНЕНО", str(r["status"]))
    check("мёртвое имя снято", "Dead" not in (src / "a.ts").read_text(encoding="utf-8"))
    check("живое имя сохранено", "Used" in (src / "a.ts").read_text(encoding="utf-8"))

    # 3 · защищённая зона: та же находка, тот же закон — рука не имеет права.
    subprocess.run(["git", "checkout", "--", "."], cwd=tmp, capture_output=True)
    zoned = {**base, "zones": {"forbidden": ["src/**"], "caution": []}}
    r = H.run(tmp, zoned, apply=True)
    check("в защищённой зоне рука отказала", r["исполнимо"] == 0, str(r["по_классам"]))
    check("файл в защищённой зоне не тронут",
          "Dead" in (src / "a.ts").read_text(encoding="utf-8"))

    # 4 · радиус: больше max_files за раз не берётся.
    for i in range(6):
        (src / f"m{i}.ts").write_text(
            f'import {{ Alive, Dead{i} }} from "./m";\nexport const v{i} = Alive;\n',
            encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "many"], cwd=tmp, capture_output=True)
    r = H.run(tmp, {**base, "radius": {"max_files_per_commit": 2}}, apply=True)
    check("радиус соблюдён: взято не больше объявленного",
          len(r.get("применено", [])) <= 2, str(len(r.get("применено", []))))

    # 5 · откат при расхождении инварианта — главный контур (ст. 35).
    subprocess.run(["git", "checkout", "--", "."], cwd=tmp, capture_output=True)
    orig_fix = H.FIXERS["ЗКН-Х112"]

    def sabotage(text, line_no, name):
        """Починка, которая «заодно» роняет маршрут — ровно та системная
        стратегическая ошибка, ради которой построен раздел VI."""
        out = orig_fix(text, line_no, name)
        return None if out is None else out.replace('{ path: "/home" }', "")

    H.FIXERS["ЗКН-Х112"] = sabotage
    r = H.run(tmp, base, apply=True)
    check("вредная починка поймана инвариантом", r["status"] == "ОТКАЧЕНО", str(r["status"]))
    check("откат вернул дерево", subprocess.run(
        ["git", "status", "--porcelain"], cwd=tmp, capture_output=True, text=True
    ).stdout.strip() == "")
    check("откат назвал сдвинутый инвариант", "routes" in (r.get("откат") or ""))
    H.FIXERS["ЗКН-Х112"] = orig_fix
    G.load_laws = orig_load
    H.G.load_laws = orig_load

    # 6 · пустой обход рукой не исполняется вовсе.
    r = H.run(tmp, {**base, "globs": ["нет/**/*.ts"]}, apply=True)
    check("пустой обход останавливает руку", r.get("status") == "КРАСНЫЙ")

    shutil.rmtree(tmp, ignore_errors=True)


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
def court_diagnose() -> None:
    """Ст. 37: каждая проверка доказана живым нарушением в обе стороны."""
    print("\n— СУД НАД ДИАГНОСТОМ (ст. 37) —")
    import diagnose as D  # noqa: PLC0415

    tmp = Path(tempfile.mkdtemp())
    src = tmp / "src"
    src.mkdir()
    passport = {"globs": ["src/**/*.ts", "src/**/*.tsx"], "ignore": [r"node_modules/"]}

    def scan(name: str, code: str) -> set[str]:
        f = src / name
        f.write_text(code, encoding="utf-8")
        r = D.diagnose(tmp, passport)
        f.unlink()
        return {x["law"] for x in r["findings"]}

    # каждая пара: ломаю → закон сработал; чиню → закон молчит.
    cases = [
        ("ЗКН-Х101", "a.ts",
         'const k = "ghp_' + "A" * 36 + '";\n',
         'const k = process.env.TOKEN;\n'),
        ("ЗКН-Х105", "b.ts",
         'const q = "SELECT * FROM t WHERE id=" + id;\n',
         'const q = "SELECT * FROM t WHERE id=?";\n'),
        ("ЗКН-Х106", "c.tsx",
         'el.innerHTML = user;\n',
         'el.textContent = user;\n'),
        ("ЗКН-Х111", "d.ts",
         'const x: any = load();\nexport { x };\n',
         'const x: Payload = load();\nexport { x };\n'),
        ("ЗКН-Х113", "e.ts",
         'try { run(); } catch (e) {}\n',
         'try { run(); } catch (e) { report(e); }\n'),
        ("ЗКН-Х113", "e2.ts",
         'try { run(); } catch {}\n',
         'try { run(); } catch { /* приватный режим — молчим осознанно */ }\n'),
        ("ЗКН-Х112", "f.ts",
         'import { Unused } from "./m";\nexport const v = 1;\n',
         'import { Used } from "./m";\nexport const v = Used;\n'),
    ]
    for law, fname, broken, fixed in cases:
        check(f"{law}: ломаю → красный", law in scan(fname, broken))
        check(f"{law}: чиню → зелёный", law not in scan(fname, fixed))

    # адрес не едет: срезка комментариев сохраняет строки.
    code = "/* блок\n\n ещё */\nconst k = \"ghp_" + "B" * 36 + "\";\n"
    (src / "g.ts").write_text(code, encoding="utf-8")
    r = D.diagnose(tmp, passport)
    addr = [f["address"] for f in r["findings"] if f["law"] == "ЗКН-Х101"]
    check("адрес не сдвинут многострочным комментарием", addr == ["src/g.ts:4"], str(addr))

    # нарушитель В комментарии не есть нарушение (кроме секрета).
    (src / "g.ts").write_text('// const q = "SELECT * FROM t WHERE id=" + id;\n', encoding="utf-8")
    r = D.diagnose(tmp, passport)
    check("строка-нарушитель в комментарии не считается",
          "ЗКН-Х105" not in {f["law"] for f in r["findings"]})
    (src / "g.ts").unlink()

    # пустой обход не есть чистый код (ст. 43).
    r = D.diagnose(tmp, {"globs": ["нет-такого/**/*.ts"]})
    check("пустой обход помечен красным, а не нулевым долгом", r["empty_walk"])

    # поставка: метка вместо sha ловится, sha — нет.
    wf = tmp / ".github" / "workflows"
    wf.mkdir(parents=True)
    (src / "h.ts").write_text("export const z = 1;\n", encoding="utf-8")
    (wf / "x.yml").write_text("permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
                              "      - uses: actions/checkout@v4\n", encoding="utf-8")
    check("ЗКН-Х114: метка → красный",
          "ЗКН-Х114" in {f["law"] for f in D.diagnose(tmp, passport)["findings"]})
    (wf / "x.yml").write_text("permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
                              f"      - uses: actions/checkout@{'a' * 40}\n", encoding="utf-8")
    laws = {f["law"] for f in D.diagnose(tmp, passport)["findings"]}
    check("ЗКН-Х114: sha → зелёный", "ЗКН-Х114" not in laws)
    check("ЗКН-Х115: права объявлены → зелёный", "ЗКН-Х115" not in laws)
    (wf / "x.yml").write_text("jobs:\n  a:\n    steps:\n"
                              f"      - uses: actions/checkout@{'a' * 40}\n", encoding="utf-8")
    check("ЗКН-Х115: права не объявлены → красный",
          "ЗКН-Х115" in {f["law"] for f in D.diagnose(tmp, passport)["findings"]})

    # граница сети.
    (src / "n.ts").write_text('fetch("https://evil.example.net/x");\n', encoding="utf-8")
    p2 = {**passport, "egress_allow": ["api.brajs.com"]}
    check("ЗКН-Х107: чужой хост → красный",
          "ЗКН-Х107" in {f["law"] for f in D.diagnose(tmp, p2)["findings"]})
    (src / "n.ts").write_text('fetch("https://api.brajs.com/x");\n', encoding="utf-8")
    check("ЗКН-Х107: объявленный хост → зелёный",
          "ЗКН-Х107" not in {f["law"] for f in D.diagnose(tmp, p2)["findings"]})

    # Срезка не имеет права съесть код. Родословная: 02.08.2026, живой обход
    # клиента — `/*` внутри строкового литерала съел 2900 строк, и рабочий
    # импорт был объявлен мёртвым.
    poison = ('import { used } from "./m";\n'
              'const s = "путь /* не комментарий";\n'
              + "const filler = 0;\n" * 40
              + "export const r = used(s, filler);\n")
    laws_p = scan("poison.ts", poison)
    check("литерал с /* не открывает комментарий (срезка не ест код)",
          "ЗКН-Х112" not in laws_p)
    (src / "p2.ts").write_text(poison, encoding="utf-8")
    kept = D.strip_comments(poison)
    check("срезка сохраняет число строк",
          kept.count("\n") == poison.count("\n"),
          f"{kept.count(chr(10))} против {poison.count(chr(10))}")
    check("настоящий блочный комментарий всё же срезан",
          "уйти" not in D.strip_comments("const a=1; /* уйти */ const b=2;\n"))
    (src / "p2.ts").unlink()

    # ЗКН-Х002 · адрес не притворяется точнее себя.
    (src / "q.ts").write_text("export const z = 1;\n", encoding="utf-8")
    wfd = tmp / ".github" / "workflows"
    wfd.mkdir(parents=True, exist_ok=True)
    (wfd / "noperm.yml").write_text("jobs:\n  a:\n    steps: []\n", encoding="utf-8")
    addrs = {f["address"] for f in D.diagnose(tmp, passport)["findings"]
             if f["law"] == "ЗКН-Х115"}
    check("файловая находка несёт файловый адрес, а не мнимую строку",
          all(a.startswith("file:") for a in addrs), str(addrs))
    (wfd / "noperm.yml").unlink()
    (src / "q.ts").unlink()

    # ЗКН-Х005 · освобождение орудия. Доказывается в обе стороны и на злоупотребление.
    bad = 'const q = "SELECT * FROM t WHERE id=" + id;\n'
    (src / "tool.ts").write_text(bad, encoding="utf-8")
    (src / "plain.ts").write_text(bad, encoding="utf-8")
    p_named = {**passport, "specimen": ["src/tool.ts"]}
    r = D.diagnose(tmp, p_named)
    addrs = {f["address"] for f in r["findings"] if f["law"] == "ЗКН-Х105"}
    check("образец освобождён поимённо", not any(a.startswith("src/tool.ts") for a in addrs))
    check("тот же код вне образца остаётся нарушением",
          any(a.startswith("src/plain.ts") for a in addrs), str(addrs))

    p_glob = {**passport, "specimen": ["src/*.ts", "**"]}
    r = D.diagnose(tmp, p_glob)
    addrs = {f["address"] for f in r["findings"] if f["law"] == "ЗКН-Х105"}
    check("глоб-освобождение отвергнуто (ЗКН-Х005)",
          any(a.startswith("src/tool.ts") for a in addrs)
          and any(a.startswith("src/plain.ts") for a in addrs), str(addrs))
    (src / "tool.ts").unlink()
    (src / "plain.ts").unlink()

    # департамент проходит собственный закон первым (ст. 44).
    self_p = json.loads((ROOT / "adapters" / "self.json").read_text(encoding="utf-8"))
    rs = D.diagnose(ROOT, self_p)
    check("департамент чист по собственному диагносту (ст. 44)",
          not rs["findings"] and not rs["empty_walk"],
          f"{len(rs['findings'])} находок")

    # полнота: каждый закон кодекса несёт проверку в диагносте (ст. 40).
    laws_all = G.load_laws()
    declared = {v["check"] for v in laws_all.values()}
    covered = {"secret_scan", "sql_concat", "raw_html", "type_suppression", "empty_catch",
               "unused_import", "action_pin", "workflow_perms", "egress_host"}
    holes = sorted(declared - covered)
    lying = sorted(k for k, v in laws_all.items()
                   if v["check"] in holes and not v.get("hole"))
    check("закон без построенной проверки объявлен дырой, а не молча зелёным",
          not lying, str(lying))
    check("закон с построенной проверкой дырой не помечен",
          not sorted(k for k, v in laws_all.items()
                     if v["check"] in covered and v.get("hole")))
    print(f"      🕳 проверок ещё не построено: {len(holes)} → {', '.join(holes)}")

    shutil.rmtree(tmp, ignore_errors=True)


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
    court_diagnose()
    court_hand()
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
