"""Планы подписки (Telegram Stars, ADR 0014).

Одно место с ценами и сроками: их читают и клавиатура выбора плана, и обработчик
оплаты (проверка суммы инвойса, продление premium_until). Цена — в Stars (XTR),
целыми единицами. Значения подобраны на старте и правятся здесь же.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    days: int          # срок подписки
    stars: int         # цена в Telegram Stars (XTR)
    title: str         # подпись на кнопке и в инвойсе


# Порядок = порядок кнопок. days уникальны — по ним ищем план в обработчике.
PLANS: tuple[Plan, ...] = (
    Plan(days=30, stars=150, title="Подписка на 30 дней"),
    Plan(days=90, stars=400, title="Подписка на 90 дней"),
    Plan(days=365, stars=1400, title="Подписка на год"),
)


def plan_by_days(days: int) -> Plan | None:
    """План по сроку, либо None (защита от подделанного callback)."""
    for plan in PLANS:
        if plan.days == days:
            return plan
    return None
