"""Regression: a successful retry after a fenced rejection must not be reported
as "safely rejected, no funds moved".

Sequence:
  1. Dispatch passes the authority gate.
  2. Authority is superseded (epoch bump, authority still ACTIVE) before the
     receiver call, so the receiver fences the first attempt.
  3. A fresh release at the new epoch is accepted; the refund is IN_FLIGHT.

The verifier must not classify the operation as REJECTED_STALE_AUTHORITY,
because a live refund exists.
"""
from __future__ import annotations

from app.domain.enums import (
    OperationState,
    ReceiverResponseClass,
    TerminalClassification,
    VerificationStatus,
)
from app.connector.hooks import DispatchContext


def test_successful_retry_after_fenced_rejection_is_not_reported_as_no_funds(world) -> None:
    bo = world.create_operation()
    signed = world.issue_release(bo)

    def supersede_mid_dispatch(ctx: DispatchContext) -> None:
        world.revocation.supersede(bo, source="regression-fenced-retry", receiver=world.receiver)

    world.hooks.on_before_receiver_call(supersede_mid_dispatch)
    try:
        first = world.coordinator.dispatch(
            business_operation_id=bo, release=signed, idempotency_key="idem_1"
        )
    finally:
        world.hooks.clear()

    assert first.response_class is ReceiverResponseClass.REJECTED_FENCED
    assert first.operation_state is OperationState.DISPATCH_REJECTED

    fresh = world.issue_release(bo)
    assert fresh.payload.release_epoch == 1

    second = world.coordinator.dispatch(
        business_operation_id=bo, release=fresh, idempotency_key="idem_2"
    )
    assert second.operation_state is OperationState.IN_FLIGHT
    assert world.oracle.refund_count() == 1

    report = world.verifier.verify(bo)
    assert report.terminal_classification is not TerminalClassification.REJECTED_STALE_AUTHORITY
    assert "dispatch was safely rejected; no funds moved" not in report.warnings
    assert report.verification_status is not VerificationStatus.VERIFIED
