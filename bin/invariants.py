#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ИНВАРИАНТЫ · раздел VI конституции (ЗКН-Х004).

Зелёный тест доказывает, что работает ПРОВЕРЕННОЕ.
Инвариант доказывает, что не сдвинулось НЕПРОВЕРЕННОЕ.

Именно здесь живёт защита от системной стратегической ошибки. Рефакторинг
может пройти все тесты и молча уронить маршрут, которого нет в тестах;
удалить «мёртвый» экспорт, на который ссылаются снаружи; сменить хост исхода;
съесть переменную окружения. Тесты этого не видят по построению — их писали
под то, что помнили. Инвариант видит, потому что сравнивает форму приложения
целиком, а не поведение отдельных мест.

Только stdlib: орган обязан идти на любом раннере без установки (ст. 44.1 BXE
как перенятая практика — молчаливая зависимость есть красный).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------- шаблоны ----
RE_HOST = re.compile(r"https?://([A-Za-z0-9._-]+\.[A-Za-z]{2,})")
RE_ENV = re.compile(
    r"(?:process\.env\.([A-Za-z_][A-Za-z0-9_]*)"
    r"|import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)"
    r"|env\.([A-Z][A-Z0-9_]{2,}))"
)
RE_EXPORT = re.compile(
    r"^\s*export\s+(?:default\s+)?"
    r"(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)",
    re.M,
)
RE_EXPORT_LIST = re.compile(r"^\s*export\s*\{([^}]*)\}", re.M)
RE_ROUTE = re.compile(r"""path\s*[:=]\s*['"`]([^'"`]+)['"`]""")

TEXT_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".go"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _iter(root: Path, globs: list[str], ignore: list[str]):
    seen = set()
    for g in globs:
        for p in sorted(root.glob(g)):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if any(re.search(x, rel) for x in ignore):
                continue
            if rel in seen:
                continue
            seen.add(rel)
            yield rel, p


def snapshot(root: Path, passport: dict) -> dict:
    """Снять форму приложения. Числа не выдумываются: чего нет — пустое."""
    globs = passport.get("globs", ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"])
    ignore = passport.get("ignore", [r"node_modules/", r"^dist/", r"^build/", r"\.min\."])
    declared = set(passport.get("invariants", []))

    routes, exports, hosts, envs, files = set(), set(), set(), set(), []
    sql: dict[str, str] = {}

    for rel, p in _iter(root, globs, ignore):
        files.append(rel)
        if p.suffix not in TEXT_EXT:
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in RE_ROUTE.finditer(src):
            v = m.group(1)
            if v.startswith("/"):
                routes.add(v)
        for m in RE_EXPORT.finditer(src):
            exports.add(f"{rel}::{m.group(1)}")
        for m in RE_EXPORT_LIST.finditer(src):
            for n in m.group(1).split(","):
                n = n.strip().split(" as ")[-1].strip()
                if n:
                    exports.add(f"{rel}::{n}")
        for m in RE_HOST.finditer(src):
            hosts.add(m.group(1).lower())
        for m in RE_ENV.finditer(src):
            envs.add(next(g for g in m.groups() if g))

    for p in sorted(root.rglob("*.sql")):
        rel = p.relative_to(root).as_posix()
        if "node_modules" in rel:
            continue
        sql[rel] = _sha(p.read_bytes())

    deps: dict[str, str] = {}
    pkg = root / "package.json"
    if pkg.exists():
        try:
            j = json.loads(pkg.read_text(encoding="utf-8"))
            for sec in ("dependencies", "devDependencies"):
                deps.update(j.get(sec, {}))
        except json.JSONDecodeError:
            pass

    full = {
        "routes": sorted(routes),
        "exports": sorted(exports),
        "sql": sql,
        "hosts": sorted(hosts),
        "env": sorted(envs),
        "files": sorted(files),
        "deps": deps,
    }
    # Инвариант, не объявленный паспортом, не сравнивается: незаявленный
    # контроль даёт ложную красную так же, как его отсутствие — ложную зелёную.
    return {k: v for k, v in full.items() if not declared or k in declared}


def compare(before: dict, after: dict, intent: list[str] | None = None) -> list[dict]:
    """
    Сличить два снимка. Заявленное намерение (ст. 36) снимает контроль
    ТОЛЬКО с названного инварианта и ни с какого другого.
    """
    intent = set(intent or [])
    out: list[dict] = []
    for key in sorted(set(before) | set(after)):
        if key in intent:
            continue
        b, a = before.get(key), after.get(key)
        if b == a:
            continue
        if isinstance(b, dict) and isinstance(a, dict):
            gone = sorted(set(b) - set(a))
            new = sorted(set(a) - set(b))
            moved = sorted(k for k in set(a) & set(b) if a[k] != b[k])
            out.append({"invariant": key, "gone": gone, "new": new, "changed": moved})
        else:
            b, a = list(b or []), list(a or [])
            out.append({
                "invariant": key,
                "gone": sorted(set(b) - set(a)),
                "new": sorted(set(a) - set(b)),
                "changed": [],
            })
    return out


def render(diffs: list[dict]) -> str:
    if not diffs:
        return "инварианты сошлись"
    lines = ["РАСХОЖДЕНИЕ ИНВАРИАНТОВ — откат обязателен (ст. 35)"]
    for d in diffs:
        lines.append(f"  · {d['invariant']}")
        for k, mark in (("gone", "пропало"), ("new", "появилось"), ("changed", "изменилось")):
            for v in d.get(k, [])[:12]:
                lines.append(f"      {mark}: {v}")
            if len(d.get(k, [])) > 12:
                lines.append(f"      {mark}: … ещё {len(d[k]) - 12}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("использование: invariants.py snap <корень> <паспорт.json> [выход.json]")
        print("               invariants.py diff <до.json> <после.json>")
        return 2
    cmd = argv[1]
    if cmd == "snap":
        passport = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
        snap = snapshot(Path(argv[2]), passport)
        out = json.dumps(snap, ensure_ascii=False, indent=2, sort_keys=True)
        if len(argv) > 4:
            Path(argv[4]).write_text(out, encoding="utf-8")
            print(f"снимок записан: {argv[4]}")
        else:
            print(out)
        return 0
    if cmd == "diff":
        b = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        a = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
        d = compare(b, a)
        print(render(d))
        return 1 if d else 0
    print(f"неизвестная команда: {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
