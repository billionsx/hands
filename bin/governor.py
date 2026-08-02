#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ГУБЕРНАТОР · регулятор автономии департамента BXH.
Раздел V конституции.

Единственная задача органа: присвоить находке класс автономии.
Губернатор НЕ чинит. Рука НЕ классифицирует (ст. 6).

Причина разделения механическая: инструмент, который сам определяет границу
своей власти, границы не имеет. Ошибка губернатора — единственная ошибка
департамента, которая масштабируется: неверно понижённый класс проходит по
всему коду раньше, чем его увидит человек.

Правило сложения одно и понижающих правил не существует (ст. 28):
    класс = МАКСИМУМ( потолок закона, класс зоны, класс вида, испытательный срок )
"""
from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- классы ----
# Порядок строгости. Больше — строже. Сравнение только по этому порядку.
K0, K1, K2, K3 = "К0", "К1", "К2", "К3"
ORDER = {K0: 0, K1: 1, K2: 2, K3: 3}
NAMES = {
    K0: "АВТОМАТ",
    K1: "АВТОМАТ ПОД ПРОТОКОЛОМ",
    K2: "ПРЕДЛОЖЕНИЕ",
    K3: "ЗАПРЕТ РУКИ",
}


def stricter(a: str, b: str) -> str:
    """Строжайший побеждает (ст. 28). Понижающих правил не существует."""
    return a if ORDER[a] >= ORDER[b] else b


# ------------------------------------------------- виды преобразования ----
# Вид объявляется законом, а не выводится по факту диффа (ст. 29).
KIND_FLOOR = {
    "format": K0,      # пробелы, порядок импортов — дерево не меняется
    "ast_equal": K0,   # доказано равенство деревьев до и после
    "additive": K1,    # только добавление, ничего не удалено и не заменено
    "semantic": K2,    # смысл меняется — требует суждения
    "deletion": K2,    # удаление никогда не бывает автоматом (ЗКН-Х003)
    "report": K3,      # закон только докладывает, руки не имеет
}
UNKNOWN_KIND_FLOOR = K2  # ЗКН-Х003: отсутствие признака — не разрешение


class Governor:
    def __init__(self, laws: dict, passport: dict):
        self.laws = laws
        self.passport = passport or {}
        zones = self.passport.get("zones", {})
        self.forbidden = zones.get("forbidden", [])
        self.caution = zones.get("caution", [])

    # ------------------------------------------------------------ зона ----
    def zone_floor(self, path: str) -> tuple[str, str | None]:
        """Класс по зоне пути. Возвращает (класс, совпавший глоб)."""
        p = str(path).replace("\\", "/").lstrip("./")
        for g in self.forbidden:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch("/" + p, g):
                return K3, g
        for g in self.caution:
            if fnmatch.fnmatch(p, g) or fnmatch.fnmatch("/" + p, g):
                return K2, g
        return K0, None

    # ---------------------------------------------------------- решение ----
    def classify(self, law_id: str, path: str, kind: str | None = None) -> dict:
        """
        Присвоить находке класс. Всегда возвращает решение с причинами:
        решение без объяснимой причины неотличимо от произвола.
        """
        reasons: list[str] = []
        verdict = K0

        law = self.laws.get(law_id)

        # 1 · закон. Неизвестный закон не может быть автоматом (ЗКН-Х003).
        if law is None:
            verdict = stricter(verdict, K2)
            reasons.append(f"закон {law_id} не объявлен в кодексе → К2 (ЗКН-Х003)")
            law = {}
        else:
            ceiling = law.get("ceiling", K2)
            verdict = stricter(verdict, ceiling)
            reasons.append(f"потолок закона {law_id} = {ceiling}")

        # 2 · вид преобразования. Объявлен законом; аргумент лишь уточняет.
        declared = law.get("kind", kind)
        if declared in KIND_FLOOR:
            floor = KIND_FLOOR[declared]
            verdict = stricter(verdict, floor)
            reasons.append(f"вид «{declared}» → не ниже {floor}")
        else:
            verdict = stricter(verdict, UNKNOWN_KIND_FLOOR)
            reasons.append(f"вид не объявлен → {UNKNOWN_KIND_FLOOR} (ЗКН-Х003)")

        # 3 · зона пути по паспорту.
        zfloor, glob = self.zone_floor(path)
        if glob:
            verdict = stricter(verdict, zfloor)
            reasons.append(f"зона «{glob}» → не ниже {zfloor}")

        # 3.1 · удаление в защищённой зоне — вечный запрет (ст. 29).
        if declared == "deletion" and zfloor == K3:
            verdict = stricter(verdict, K3)
            reasons.append("удаление в защищённой зоне → К3")

        # 4 · испытательный срок закона (ст. 32).
        # Право писать зарабатывается, а не назначается.
        if law.get("probation", True):
            verdict = stricter(verdict, K2)
            reasons.append("закон на испытательном сроке → не ниже К2 (ст. 32)")

        return {
            "law": law_id,
            "path": path,
            "class": verdict,
            "name": NAMES[verdict],
            "executable": verdict in (K0, K1),
            "reasons": reasons,
        }


# ---------------------------------------------------------- загрузка ----
def load_laws(path: Path | None = None) -> dict:
    p = path or ROOT / "registry" / "library" / "laws.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8")).get("laws", {})


def load_passport(name: str) -> dict:
    p = ROOT / "adapters" / f"{name}.json"
    if not p.exists():
        raise SystemExit(f"паспорт не найден: adapters/{name}.json")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("использование: governor.py <паспорт> <закон> <путь> [вид]")
        return 2
    g = Governor(load_laws(), load_passport(argv[1]))
    d = g.classify(argv[2], argv[3], argv[4] if len(argv) > 4 else None)
    print(f"{d['class']} · {d['name']}   {d['law']}   {d['path']}")
    for r in d["reasons"]:
        print(f"   ← {r}")
    print(f"   исполнение рукой: {'да' if d['executable'] else 'НЕТ'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
