"""Independent verifier.

Contract
--------
* Takes exactly ONE dependency: ``EvidenceLedgerReader``.
* Cannot import or reference the receiver, dispatch coordinator, or operation
  repository.
* Reasons only from evidence: hash-chain integrity, event ordering, terminal
  classifications, and the receiver response classes recorded in evidence.

Terminal classification rules (from evidence ALONE)
---------------------------------------------------
1. COMPLETION_CONFIRMED: must carry STATUS_TERMINAL_COMPLETED.
2. CANCELLATION_CONFIRMED: must carry STATUS_TERMINAL_CANCELLED.
3. OUTCOME_UNKNOWN: terminal unknown; retry blocked.
4. REJECTED_STALE_AUTHORITY: dispatch was safely rejected due to fencing or
   local admissibility denial. No funds moved. Retry permitted with new release.
5. REJECTED_NO_FUNDS: dispatch was rejected by the receiver (invalid/duplicate).
   No funds moved. Retry permitted.
6. REJECTED_REPLAY: release replay was detected by atomic consumption.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..domain.enums import (
    EvidenceEventType,
    OperationState,
    ReceiverResponseClass,
    TerminalClassification,
    VerificationStatus,
)
from ..domain.models import EvidenceEvent, VerificationReport
from ..evidence.ledger import event_from_row
from ..evidence.storage import EvidenceLedgerReader
from .assertions import ALL_ASSERTIONS, AssertionContext
from .report import build_report


_TERMINAL_TYPES = (
    EvidenceEventType.COMPLETION_CONFIRMED,
    EvidenceEventType.CANCELLATION_CONFIRMED,
    EvidenceEventType.OUTCOME_UNKNOWN,
    EvidenceEventType.DISPATCH_REJECTED,
    EvidenceEventType.ADMISSIBILITY_DENIED,
    EvidenceEventType.RELEASE_REPLAY_ATTEMPTED,
)

_LIVE_DISPATCH_TYPES = (
    EvidenceEventType.DISPATCH_ATTEMPTED,
    EvidenceEventType.DISPATCH_ACCEPTED,
    EvidenceEventType.IN_FLIGHT,
)

_RETRY_SAFE_STATES = (
    OperationState.CREATED,
    OperationState.RELEASE_ISSUED,
    OperationState.RELEASE_VERIFIED,
    OperationState.ADMISSIBILITY_DENIED,
    OperationState.DISPATCH_REJECTED,
)


class IndependentVerifier:
    def __init__(self, ledger: EvidenceLedgerReader) -> None:
        self._ledger = ledger

    def verify(self, business_operation_id: str) -> VerificationReport:
        chain_valid = self._ledger.verify_chain()
        raw_rows = self._ledger.read_for_operation(business_operation_id)
        last_seq = int(raw_rows[-1]["_sequence"]) if raw_rows else 0
        last_hash = raw_rows[-1]["_hash"] if raw_rows else None

        if not chain_valid:
            return build_report(
                business_operation_id=business_operation_id,
                verification_status=VerificationStatus.FAILED,
                terminal_classification=None,
                evidence_events_examined=len(raw_rows),
                failed_assertions=["chain_invalid"],
                unresolved_conditions=["evidence ledger integrity check failed"],
                retry_eligible=False,
                reconciliation_required=True,
                chain_valid=False,
                last_event_sequence=last_seq,
                last_event_hash=last_hash,
            )

        if not raw_rows:
            return build_report(
                business_operation_id=business_operation_id,
                verification_status=VerificationStatus.INCONCLUSIVE,
                terminal_classification=None,
                evidence_events_examined=0,
                failed_assertions=["no_evidence_events"],
                unresolved_conditions=["no evidence for business_operation_id"],
                retry_eligible=False,
                reconciliation_required=True,
                chain_valid=True,
                last_event_sequence=0,
                last_event_hash=None,
            )

        events: List[EvidenceEvent] = []
        parse_failures = 0
        for r in raw_rows:
            try:
                events.append(event_from_row(r))
            except Exception:
                parse_failures += 1

        failed: List[str] = []
        warnings: List[str] = []
        ctx = AssertionContext(business_operation_id=business_operation_id, events=events)

        for name, check in ALL_ASSERTIONS:
            result = check(events, ctx)
            if result:
                failed.append(f"{name}:{result}")

        if parse_failures:
            failed.append(f"unparseable_events:{parse_failures}")

        terminal_event = self._find_last_terminal(events)
        # A terminal event recorded before a later live dispatch (e.g. a fenced
        # rejection followed by a successful retry) no longer describes the
        # operation. Ignore it so the live dispatch is not reported as safely
        # rejected.
        if terminal_event is not None and self._live_dispatch_after(events, terminal_event):
            terminal_event = None
        terminal_classification: Optional[TerminalClassification] = None
        terminal_assert_failed = False

        if terminal_event is not None:
            if terminal_event.event_type is EvidenceEventType.COMPLETION_CONFIRMED:
                if terminal_event.receiver_response_class is not None and \
                   terminal_event.receiver_response_class.name == "STATUS_TERMINAL_COMPLETED":
                    terminal_classification = TerminalClassification.COMPLETION_CONFIRMED
                else:
                    failed.append("completion_confirmed_without_terminal_receiver_evidence")
                    terminal_assert_failed = True
            elif terminal_event.event_type is EvidenceEventType.CANCELLATION_CONFIRMED:
                if terminal_event.receiver_response_class is not None and \
                   terminal_event.receiver_response_class.name == "STATUS_TERMINAL_CANCELLED":
                    terminal_classification = TerminalClassification.CANCELLATION_CONFIRMED
                else:
                    failed.append("cancellation_confirmed_without_terminal_receiver_evidence")
                    terminal_assert_failed = True
            elif terminal_event.event_type is EvidenceEventType.OUTCOME_UNKNOWN:
                terminal_classification = TerminalClassification.OUTCOME_UNKNOWN
            elif terminal_event.event_type is EvidenceEventType.DISPATCH_REJECTED:
                if terminal_event.receiver_response_class is not None:
                    if terminal_event.receiver_response_class == ReceiverResponseClass.REJECTED_FENCED:
                        terminal_classification = TerminalClassification.REJECTED_STALE_AUTHORITY
                    elif terminal_event.receiver_response_class.name.startswith("REJECTED_"):
                        terminal_classification = TerminalClassification.REJECTED_NO_FUNDS
                    else:
                        failed.append("dispatch_rejected_with_invalid_receiver_evidence")
                        terminal_assert_failed = True
                else:
                    failed.append("dispatch_rejected_without_valid_receiver_rejection_evidence")
                    terminal_assert_failed = True
            elif terminal_event.event_type is EvidenceEventType.ADMISSIBILITY_DENIED:
                terminal_classification = TerminalClassification.REJECTED_STALE_AUTHORITY
            elif terminal_event.event_type is EvidenceEventType.RELEASE_REPLAY_ATTEMPTED:
                terminal_classification = TerminalClassification.REJECTED_REPLAY

        unresolved: List[str] = []
        if terminal_classification is TerminalClassification.COMPLETION_CONFIRMED:
            retry_eligible = False
            reconciliation_required = False
        elif terminal_classification is TerminalClassification.CANCELLATION_CONFIRMED:
            retry_eligible = False
            reconciliation_required = False
            unresolved.append("new refund requires explicit new authorization")
        elif terminal_classification is TerminalClassification.OUTCOME_UNKNOWN:
            retry_eligible = False
            reconciliation_required = True
            unresolved.append("terminal outcome could not be independently established")
        elif terminal_classification in (
            TerminalClassification.REJECTED_NO_FUNDS,
            TerminalClassification.REJECTED_STALE_AUTHORITY,
            TerminalClassification.REJECTED_REPLAY,
        ):
            retry_eligible = True
            reconciliation_required = False
            warnings.append("dispatch was safely rejected; no funds moved")
        else:
            last_state = self._infer_last_state(events)
            retry_eligible = last_state in _RETRY_SAFE_STATES
            reconciliation_required = not retry_eligible
            if retry_eligible:
                warnings.append("operation not terminal; retry permitted subject to duplicate guard")
            else:
                unresolved.append(f"last state {last_state.value} requires further evidence")

        if failed or terminal_assert_failed:
            status = VerificationStatus.FAILED
        elif terminal_classification in (
            TerminalClassification.COMPLETION_CONFIRMED,
            TerminalClassification.CANCELLATION_CONFIRMED,
            TerminalClassification.REJECTED_NO_FUNDS,
            TerminalClassification.REJECTED_STALE_AUTHORITY,
            TerminalClassification.REJECTED_REPLAY,
        ):
            status = VerificationStatus.VERIFIED
        else:
            status = VerificationStatus.INCONCLUSIVE

        return build_report(
            business_operation_id=business_operation_id,
            verification_status=status,
            terminal_classification=terminal_classification,
            evidence_events_examined=len(events),
            failed_assertions=failed,
            warnings=warnings,
            unresolved_conditions=unresolved,
            retry_eligible=retry_eligible,
            reconciliation_required=reconciliation_required,
            chain_valid=True,
            last_event_sequence=last_seq,
            last_event_hash=last_hash,
        )

    def verify_ledger(self) -> Tuple[bool, int]:
        return self._ledger.verify_chain(), len(self._ledger.read_all())

    def _live_dispatch_after(self, events: List[EvidenceEvent], terminal: EvidenceEvent) -> bool:
        seen_terminal = False
        for e in events:
            if e is terminal:
                seen_terminal = True
                continue
            if seen_terminal and e.event_type in _LIVE_DISPATCH_TYPES:
                return True
        return False

    def _find_last_terminal(self, events: List[EvidenceEvent]) -> Optional[EvidenceEvent]:
        for e in reversed(events):
            if e.event_type in _TERMINAL_TYPES:
                return e
        return None

    def _infer_last_state(self, events: List[EvidenceEvent]) -> OperationState:
        last: Optional[OperationState] = None
        for e in events:
            if e.new_state is not None:
                last = e.new_state
        return last or OperationState.CREATED