#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
РАЗВЕДКА · раздел IV конституции. Суточное пополнение экспертизы.

Разведка приносит ИЗМЕНЕНИЯ, а не объёмы (ст. 24), и производит КАНДИДАТОВ,
а не законы (ст. 26). Кандидат становится законом только когда у него есть
исполнимая проверка, тест в обе стороны и объявленный потолок класса.
Правило, которое разведка знает, но проверить не умеет, объявляется дырой 🕳
с адресом источника: правдоподобная проверка хуже отсутствующей, потому что
даёт ложную зелёную (ст. 26.1).

Только stdlib. Источники объявлены в registry/sources.json (ст. 25).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "registry" / "sources.json"
CAND = ROOT / "registry" / "library" / "candidates.json"
STATE = ROOT / "registry" / "state" / "intake.json"
UA = "billionsx-hands/1 (department intake)"


def get(url: str, token: str | None = None, accept: str = "application/json"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_url": url}
    except Exception as e:  # noqa: BLE001 — источник может исчезнуть; это не падение
        return {"_error": str(e), "_url": url}


# ------------------------------------------------------------ уязвимости ----
def advisories(ecosystem: str, since: str, token: str | None) -> list[dict]:
    """GitHub Advisory Database. Публичный, структурный, с датой публикации."""
    url = (f"https://api.github.com/advisories?ecosystem={ecosystem}"
           f"&published=%3E{since}&per_page=100&sort=published")
    d = get(url, token)
    return d if isinstance(d, list) else []


def osv_batch(packages: dict[str, str], ecosystem: str = "npm") -> list[dict]:
    """OSV.dev — второй независимый источник. Расхождение источников само по
    себе находка: одна база молчит там, где другая знает."""
    q = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}}
                     for n in list(packages)[:900]]}
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(q).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode()).get("results", [])
    except Exception:  # noqa: BLE001
        return []


def _clean(v: str) -> str:
    return (v or "").lstrip("^~>=< v").split(" ")[0]


def _major(a: str, b: str) -> bool:
    try:
        return _clean(a).split(".")[0] != _clean(b).split(".")[0]
    except (IndexError, AttributeError):
        return True


def match_deps(adv: list[dict], deps: dict[str, str]) -> list[dict]:
    """Сопоставить советы с зависимостями паспорта. Закон выбирается по
    расстоянию подъёма: патч — ЗКН-Х102 (К1), мажор — ЗКН-Х103 (К2)."""
    out = []
    for a in adv:
        for v in a.get("vulnerabilities") or []:
            name = ((v.get("package") or {}).get("name") or "")
            if name not in deps:
                continue
            fix = v.get("first_patched_version") or ""
            law = "ЗКН-Х103" if (not fix or _major(deps[name], fix)) else "ЗКН-Х102"
            out.append({
                "law": law,
                "package": name,
                "have": deps[name],
                "patched": fix or "🕳",
                "severity": a.get("severity"),
                "ghsa": a.get("ghsa_id"),
                "cve": a.get("cve_id"),
                "address": f"ghsa:{a.get('ghsa_id')}",
                "published": a.get("published_at"),
            })
    return out


# --------------------------------------------------- кандидаты в законы ----
def rule_candidates(token: str | None, sources: dict) -> list[dict]:
    """
    Новые правила из открытых реестров. Каждый кандидат несёт адрес источника.
    Кандидат без исполнимой проверки остаётся дырой 🕳 — это законное состояние.
    """
    out = []
    for s in sources.get("rules", []):
        rel = get(s["url"], token)
        if isinstance(rel, dict) and rel.get("_error"):
            out.append({"source": s["name"], "hole": True,
                        "address": s["url"], "why": rel["_error"]})
            continue
        items = rel if isinstance(rel, list) else [rel]
        for it in items[: s.get("take", 3)]:
            tag = it.get("tag_name") or it.get("name") or ""
            body = (it.get("body") or "")[:4000]
            if not tag:
                continue
            out.append({
                "source": s["name"],
                "release": tag,
                "address": it.get("html_url") or s["url"],
                "published": it.get("published_at"),
                "check_buildable": False,   # 🕳 пока не построена проверка
                "excerpt": body[:600],
            })
    return out


# ------------------------------------------------------------------ ход ----
def run(deps: dict[str, str], days: int = 1) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("HANDS_TOKEN")
    sources = json.loads(SOURCES.read_text(encoding="utf-8")) if SOURCES.exists() else {}
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    adv = []
    for eco in sources.get("ecosystems", ["npm"]):
        adv += advisories(eco, since, token)

    findings = match_deps(adv, deps)
    osv = osv_batch(deps)
    osv_hits = sum(1 for r in osv if r.get("vulns"))

    report = {
        "снято": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "окно_суток": days,
        "советов_просмотрено": len(adv),
        "зависимостей_паспорта": len(deps),
        "находок_по_зависимостям": findings,
        "osv_пакетов_с_записями": osv_hits,
        "расхождение_источников": (
            "🕳 osv недоступен" if not osv else
            f"ghsa:{len(findings)} osv:{osv_hits}"
        ),
        "кандидаты_в_законы": rule_candidates(token, sources),
    }
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Кандидаты копятся отдельно от свода. Разведка не пишет в кодекс (ст. 6).
    prev = json.loads(CAND.read_text(encoding="utf-8")) if CAND.exists() else {"кандидаты": []}
    known = {c.get("address") for c in prev["кандидаты"]}
    for c in report["кандидаты_в_законы"]:
        if c.get("address") not in known:
            prev["кандидаты"].append(c)
    CAND.write_text(json.dumps(prev, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def deps_of(project_root: Path) -> dict[str, str]:
    pkg = project_root / "package.json"
    if not pkg.exists():
        return {}
    j = json.loads(pkg.read_text(encoding="utf-8"))
    d = {}
    for sec in ("dependencies", "devDependencies"):
        d.update(j.get(sec, {}))
    return d


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else ROOT
    days = int(argv[2]) if len(argv) > 2 else 1
    r = run(deps_of(root), days)
    print(f"советов просмотрено: {r['советов_просмотрено']}")
    print(f"зависимостей паспорта: {r['зависимостей_паспорта']}")
    print(f"находок: {len(r['находок_по_зависимостям'])}")
    for f in r["находок_по_зависимостям"][:20]:
        print(f"  {f['law']}  {f['package']} {f['have']} → {f['patched']}  "
              f"[{f['severity']}]  {f['address']}")
    print(f"кандидатов в законы: {len(r['кандидаты_в_законы'])}")
    print(f"сверка источников: {r['расхождение_источников']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
