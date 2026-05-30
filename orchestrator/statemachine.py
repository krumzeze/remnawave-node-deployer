"""State-машина задачи провижининга.

queued → bootstrapping → provisioning → registering → online
                                                    ↘ failed | rolled_back

Принцип «не навреди» (ADR 0002): необратимые действия (отключение парольного
входа) выполняются только после проверки, что новое состояние работает.
При сбое — откат к предыдущему рабочему состоянию.
"""
from __future__ import annotations

import enum


class NodeState(str, enum.Enum):
    QUEUED = "queued"
    BOOTSTRAPPING = "bootstrapping"
    PROVISIONING = "provisioning"
    REGISTERING = "registering"
    ONLINE = "online"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# Допустимые переходы. Любой шаг может уйти в failed.
TRANSITIONS: dict[NodeState, set[NodeState]] = {
    NodeState.QUEUED: {NodeState.BOOTSTRAPPING, NodeState.FAILED},
    NodeState.BOOTSTRAPPING: {NodeState.PROVISIONING, NodeState.FAILED,
                              NodeState.ROLLED_BACK},
    NodeState.PROVISIONING: {NodeState.REGISTERING, NodeState.FAILED,
                             NodeState.ROLLED_BACK},
    NodeState.REGISTERING: {NodeState.ONLINE, NodeState.FAILED},
    NodeState.ONLINE: set(),
    NodeState.FAILED: {NodeState.ROLLED_BACK},
    NodeState.ROLLED_BACK: set(),
}


def can_transition(src: NodeState, dst: NodeState) -> bool:
    return dst in TRANSITIONS.get(src, set())
