from orchestrator.statemachine import NodeState, can_transition


def test_happy_path_transitions():
    assert can_transition(NodeState.QUEUED, NodeState.BOOTSTRAPPING)
    assert can_transition(NodeState.BOOTSTRAPPING, NodeState.PROVISIONING)
    assert can_transition(NodeState.PROVISIONING, NodeState.REGISTERING)
    assert can_transition(NodeState.REGISTERING, NodeState.ONLINE)


def test_invalid_transition():
    assert not can_transition(NodeState.QUEUED, NodeState.ONLINE)
    assert not can_transition(NodeState.ONLINE, NodeState.FAILED)


def test_rollback_available_mid_provision():
    assert can_transition(NodeState.BOOTSTRAPPING, NodeState.ROLLED_BACK)
    assert can_transition(NodeState.PROVISIONING, NodeState.ROLLED_BACK)
