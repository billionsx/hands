#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ДИАГНОСТ · орган обхода клиента (ст. 5).

Каждый закон кодекса обязан иметь здесь исполнимую проверку. Закон без
проверки — дыра 🕳, а не закон (ст. 26.1). Каждая находка несёт `путь:строка`
и номер закона: находка без адреса не существует (ЗКН-Х002).

Диагност НЕ исполняет и НЕ классифицирует. Он только видит.

Комментарии срезаются ДО проверки — в комментариях законно живут строки-
нарушители. Срезка сохраняет переводы строк: потеря строки есть сдвиг адреса,
а сдвинутый адрес хуже отсутствующего (родословная: та же ошибка стоила BXE
падения точности адреса до 11%).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------- срезка ----
def strip_comments(src: str) -> str:
    r"""
    Срезать комментарии, СОХРАНИВ переводы строк и не тронув строковые литералы.

    Разбор посимвольный, а не регуляркой. Причина установлена живьём
    (02.08.2026): последовательность `/*` внутри строкового литерала открывает
    для регулярки мнимый комментарий, и `.*?\*/` съедает всё до следующего
    закрытия — в живом файле клиента так пропало 2900 строк, и рабочий импорт
    был объявлен мёртвым. Регулярка не различает код и данные по построению;
    состояние различает.
    """
    out = []
    i, n = 0, len(src)
    state = "code"      # code | line | block | str
    quote = ""
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state, i = "line", i + 2
                continue
            if c == "/" and nxt == "*":
                state, i = "block", i + 2
                continue
            if c in "\"'`":
                state, quote = "str", c
            out.append(c)
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append(c)
        elif state == "block":
            if c == "*" and nxt == "/":
                state, i = "code", i + 2
                continue
            out.append("\n" if c == "\n" else "")
        else:  # str — литерал неприкосновенен, комментариев внутри не бывает
            out.append(c)
            if c == "\\":
                if i + 1 < n:
                    out.append(nxt)
                    i += 2
                    continue
            elif c == quote:
                state = "code"
        i += 1
    return "".join(out)


def blank_strings(src: str) -> str:
    """Обнулить содержимое строковых литералов, сохранив длину и переводы."""
    def f(m):
        t = m.group(0)
        return t[0] + "".join("\n" if c == "\n" else " " for c in t[1:-1]) + t[-1]
    return _STR.sub(f, src)


def lines_of(src: str):
    return list(enumerate(src.splitlines(), start=1))


# ------------------------------------------------------------- правила ----
SECRET_PATTERNS = [
    (r"github_pat_[A-Za-z0-9_]{20,}", "github fine-grained pat"),
    (r"ghp_[A-Za-z0-9]{30,}", "github classic pat"),
    (r"sk-[A-Za-z0-9]{20,}", "openai-подобный ключ"),
    (r"AKIA[0-9A-Z]{16}", "aws access key id"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "приватный ключ"),
    (r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
     "присвоение секрета литералом"),
]
RE_SQL_CONCAT = re.compile(
    r"""(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;'"]{0,200}?"""
    r"""(?:['"`]\s*\+|\$\{|%\s*\(|\+\s*['"`])""")
RE_RAW_HTML = re.compile(
    r"(dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|v-html\s*=|document\.write\s*\()")
RE_TYPE_SUPPRESS = re.compile(r"(@ts-ignore|@ts-nocheck|\beslint-disable\b|:\s*any\b|\bas\s+any\b)")
RE_EMPTY_CATCH = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}")
RE_IMPORT = re.compile(r"^\s*import\s+(?:type\s+)?([^;]+?)\s+from\s+['\"]([^'\"]+)['\"]", re.M)
RE_USES = re.compile(r"\buses\s*:\s*([A-Za-z0-9_.\-]+/[^\s@]+)@([^\s#]+)")
RE_EVAL = re.compile(r"\beval\s*\(|new\s+Function\s*\(")


def _iter_files(root: Path, passport: dict):
    ignore = passport.get("ignore", [r"node_modules/"])
    seen = set()
    for g in passport.get("globs", ["**/*.ts", "**/*.tsx"]):
        for p in sorted(root.glob(g)):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if any(re.search(x, rel) for x in ignore) or rel in seen:
                continue
            seen.add(rel)
            yield rel, p


def _find(rel, src, rx, law, why, findings, raw=None):
    """Ищем в очищенном тексте, показываем живую строку по тому же адресу."""
    real = (raw or src).splitlines()
    for n, line in lines_of(src):
        if rx.search(line):
            shown = real[n - 1].strip() if n <= len(real) else line.strip()
            findings.append({"law": law, "address": f"{rel}:{n}", "why": why,
                             "excerpt": shown[:120]})


# --------------------------------------------------------------- обход ----
def diagnose(root: Path, passport: dict) -> dict:
    findings: list[dict] = []
    walked = 0
    # ЗКН-Х005 · орудие содержит образ добычи. Освобождение только поимённое:
    # глоб здесь запрещён конституцией — широкое освобождение прячет долг.
    specimen = {s for s in passport.get("specimen", [])
                if not any(c in s for c in "*?[")}

    for rel, p in _iter_files(root, passport):
        walked += 1
        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if rel in specimen:
            continue
        src = strip_comments(raw)

        # ЗКН-Х101 · секреты. Ищем в СЫРОМ тексте: секрет в комментарии — секрет.
        for pat, why in SECRET_PATTERNS:
            _find(rel, raw, re.compile(pat), "ЗКН-Х101", why, findings)

        _find(rel, src, RE_SQL_CONCAT, "ЗКН-Х105", "конкатенация в SQL", findings, raw)
        _find(rel, src, RE_RAW_HTML, "ЗКН-Х106", "разметка из переменной", findings, raw)
        _find(rel, src, RE_EVAL, "ЗКН-Х106", "исполнение строки как кода", findings, raw)
        _find(rel, src, RE_TYPE_SUPPRESS, "ЗКН-Х111", "подавление типовой проверки", findings, raw)
        # ЗКН-Х113 · пустой перехват. Молчание, ОБЪЯСНЁННОЕ комментарием, —
        # принятое решение, а не проглоченная ошибка: ищем по живому тексту.
        _find(rel, raw, RE_EMPTY_CATCH, "ЗКН-Х113",
              "перехват молчит без объяснения", findings)

        # ЗКН-Х112 · мёртвый импорт. Имя не встречается вне своей строки импорта.
        body = strip_comments(raw)
        for m in RE_IMPORT.finditer(body):
            clause = m.group(1)
            if clause.strip().startswith("*"):
                continue
            names = re.findall(r"[A-Za-z_$][\w$]*", clause.split("{")[-1].replace("}", "")) \
                if "{" in clause else re.findall(r"[A-Za-z_$][\w$]*", clause)
            rest = body[: m.start()] + body[m.end():]
            line_no = body[: m.start()].count("\n") + 1
            for nm in names:
                if nm in ("type", "as", "default", "from"):
                    continue
                if not re.search(rf"\b{re.escape(nm)}\b", rest):
                    live = raw.splitlines()
                    shown = live[line_no - 1].strip() if line_no <= len(live) else ""
                    findings.append({
                        "law": "ЗКН-Х112", "address": f"{rel}:{line_no}",
                        "why": f"импорт «{nm}» не используется",
                        "excerpt": shown[:120]})

    # ЗКН-Х114/115 · поставка. Воркфлоу читаются отдельно от глобов кода.
    for wf in sorted((root / ".github" / "workflows").glob("*.y*ml")) \
            if (root / ".github" / "workflows").is_dir() else []:
        walked += 1
        rel = wf.relative_to(root).as_posix()
        text = wf.read_text(encoding="utf-8", errors="ignore")
        for n, line in lines_of(text):
            m = RE_USES.search(line)
            if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                findings.append({"law": "ЗКН-Х114", "address": f"{rel}:{n}",
                                 "why": f"действие закреплено меткой «{m.group(2)}», не sha",
                                 "excerpt": line.strip()[:120]})
        if "permissions:" not in text:
            # Адрес файловый, а не строчный: адрес, притворяющийся точнее
            # себя, нарушает ЗКН-Х002 так же, как отсутствующий.
            findings.append({"law": "ЗКН-Х115", "address": f"file:{rel}",
                             "why": "права воркфлоу не объявлены — наследуются по умолчанию",
                             "excerpt": "блок permissions отсутствует"})

    # ЗКН-Х107 · граница сети. Хост вне объявленного паспортом множества.
    allowed = set(passport.get("egress_allow", []))
    if allowed:
        sys.path.insert(0, str(ROOT / "bin"))
        import invariants as INV  # noqa: PLC0415
        snap = INV.snapshot(root, {**passport, "invariants": ["hosts"]})
        for h in snap.get("hosts", []):
            if h not in allowed:
                findings.append({"law": "ЗКН-Х107", "address": f"egress:{h}",
                                 "why": "хост исхода вне объявленной границы", "excerpt": h})

    # ЗКН-Э006 перенятое: пустой обход не есть погашенный долг (ст. 43).
    return {"walked": walked, "findings": findings,
            "empty_walk": walked == 0,
            "by_law": _tally(findings)}


def _tally(findings):
    t: dict[str, int] = {}
    for f in findings:
        t[f["law"]] = t.get(f["law"], 0) + 1
    return dict(sorted(t.items()))


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("использование: diagnose.py <корень> <паспорт.json> [--json]")
        return 2
    passport = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    r = diagnose(Path(argv[1]), passport)
    if "--json" in argv:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0
    if r["empty_walk"]:
        print("КРАСНЫЙ · обойдено 0 файлов — промах адреса, а не чистый код (ст. 43)")
        return 1
    print(f"обойдено файлов: {r['walked']} · находок: {len(r['findings'])}")
    for law, n in r["by_law"].items():
        print(f"  {law}: {n}")
    for f in r["findings"][:25]:
        print(f"    {f['law']}  {f['address']}  {f['why']}")
    if len(r["findings"]) > 25:
        print(f"    … ещё {len(r['findings']) - 25}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
