"""Static, exact-envelope send-session authority for W08/W09-A.

This module does not resolve credentials, construct a client, or perform
network I/O.  It consumes one exact ``EgressApproval``, freezes the authority
that the W09 runtime must honor, and atomically binds a one-shot consent use to
the exact issued session when required.
"""
from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Callable, TypeVar
from uuid import UUID, uuid5

from snapquiz.domain._validation import (
    HTTP_TOKEN_RE,
    require_aware_datetime,
    require_canonical_http_url,
    require_digest,
    require_plain_int,
    require_text,
    require_uuid,
    runtime_final,
)
from snapquiz.domain.digest import Digest256, digest256
from snapquiz.domain.errors import EndpointPolicyError
from snapquiz.domain.outbound import PreparedOutbound
from snapquiz.domain.plan import (
    ExecutionPlanNetworkOperation,
    ExecutionPlanStage,
    OutboundDataKind,
)
from snapquiz.domain.policy import ContractMarker
from snapquiz.pipelines.contracts import StageInvocation
from snapquiz.privacy.consent import (
    AuthorizationContext,
    ConsentGrant,
    ConsentLedger,
    PrivacyGate,
    _ATOMIC_PRIVACY_AUTHORITY,
    _CONSENT_SESSION_AUTHORITY,
)
from snapquiz.privacy.egress import (
    EGRESS_POLICY_VERSION,
    EgressApproval,
    EgressApprovalLedger,
    _EGRESS_SESSION_AUTHORITY,
    _validate_exact_egress_binding,
)
from snapquiz.routing.planner import PlannedExecution


AUTHORIZED_SEND_SESSION_SCHEMA_VERSION = "snapquiz.authorized-send-session.v1"
SEND_SESSION_POLICY_VERSION = "snapquiz.send-session.static-w08.v1"

_SESSION_LEDGER_AUTHORITY = object()
_SESSION_ATTEMPT_AUTHORITY = object()
_SESSION_UUID_NAMESPACE = UUID("29b51c62-11ea-5707-ad4d-12f7e2cb96c4")
_T = TypeVar("_T")


def _session_error(
    message: str,
    *,
    stage: str = "send_session_factory",
) -> EndpointPolicyError:
    return EndpointPolicyError(
        stage=stage,
        safe_message=message,
        retryable=False,
    )


def _marker_payload(value: Digest256 | ContractMarker) -> object:
    return value.value if isinstance(value, ContractMarker) else value


def _billable_payload(value: bool | ContractMarker) -> object:
    return value.value if isinstance(value, ContractMarker) else value


def _session_identifier_payload(
    session: "AuthorizedSendSession",
) -> dict[str, object]:
    return {
        "policy_version": session.policy_version,
        "approval_id": session.approval_id,
        "approval_terms_digest": session.approval_terms_digest,
        "consumed_approval_digest": session.consumed_approval_digest,
        "request_id": session.request_id,
        "plan_id": session.plan_id,
        "plan_digest": session.plan_digest,
        "planned_execution_digest": session.planned_execution_digest,
        "registry_revision": session.registry_revision,
        "registry_digest": session.registry_digest,
        "privacy_authorization_id": session.privacy_authorization_id,
        "privacy_authorization_digest": session.privacy_authorization_digest,
        "stage_id": session.stage_id,
        "operation_id": session.operation_id,
        "invocation_id": session.invocation_id,
        "invocation_digest": session.invocation_digest,
        "source_ids": session.source_ids,
        "source_digests": session.source_digests,
        "capture_scope_fingerprint": _marker_payload(
            session.capture_scope_fingerprint
        ),
        "http_method": session.http_method,
        "canonical_url": session.canonical_url,
        "content_type": session.content_type,
        "non_secret_headers_digest": session.non_secret_headers_digest,
        "credential_binding_digest": _marker_payload(
            session.credential_binding_digest
        ),
        "outbound_data": tuple(item.value for item in session.outbound_data),
        "body_digest": session.body_digest,
        "payload_byte_size": session.payload_byte_size,
        "request_envelope_digest": session.request_envelope_digest,
        "max_network_attempts": session.max_network_attempts,
        "billable": _billable_payload(session.billable),
        "issued_at": session.issued_at,
        "valid_until": session.valid_until,
    }


def _session_identifier_payload_from_approval(
    *,
    approval: EgressApproval,
    issued_at: datetime,
    valid_until: datetime,
) -> dict[str, object]:
    return {
        "policy_version": SEND_SESSION_POLICY_VERSION,
        "approval_id": approval.approval_id,
        "approval_terms_digest": approval.approval_terms_digest,
        "consumed_approval_digest": approval.approval_digest,
        "request_id": approval.request_id,
        "plan_id": approval.plan_id,
        "plan_digest": approval.plan_digest,
        "planned_execution_digest": approval.planned_execution_digest,
        "registry_revision": approval.registry_revision,
        "registry_digest": approval.registry_digest,
        "privacy_authorization_id": approval.privacy_authorization_id,
        "privacy_authorization_digest": approval.privacy_authorization_digest,
        "stage_id": approval.stage_id,
        "operation_id": approval.operation_id,
        "invocation_id": approval.invocation_id,
        "invocation_digest": approval.invocation_digest,
        "source_ids": approval.source_ids,
        "source_digests": approval.source_digests,
        "capture_scope_fingerprint": _marker_payload(
            approval.capture_scope_fingerprint
        ),
        "http_method": approval.http_method,
        "canonical_url": approval.canonical_url,
        "content_type": approval.content_type,
        "non_secret_headers_digest": approval.non_secret_headers_digest,
        "credential_binding_digest": _marker_payload(
            approval.credential_binding_digest
        ),
        "outbound_data": tuple(item.value for item in approval.outbound_data),
        "body_digest": approval.body_digest,
        "payload_byte_size": approval.payload_byte_size,
        "request_envelope_digest": approval.request_envelope_digest,
        "max_network_attempts": approval.max_network_attempts,
        "billable": _billable_payload(approval.billable),
        "issued_at": issued_at,
        "valid_until": valid_until,
    }


def _session_id_for(payload: dict[str, object]) -> UUID:
    seed = digest256(
        "AuthorizedSendSessionIdentifier",
        AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
        payload,
    )
    return uuid5(_SESSION_UUID_NAMESPACE, str(seed))


def _session_terms_payload(
    session: "AuthorizedSendSession",
) -> dict[str, object]:
    return {
        "session_id": session.session_id,
        **_session_identifier_payload(session),
    }


@runtime_final
class AuthorizedSendSession:
    """Immutable static authority for one approved outbound envelope.

    Attempt counters, monotonic deadline, cancellation, credential handles and
    HTTP state intentionally do not exist until W09.
    """

    __slots__ = (
        "session_id",
        "policy_version",
        "approval_id",
        "approval_terms_digest",
        "consumed_approval_digest",
        "request_id",
        "plan_id",
        "plan_digest",
        "planned_execution_digest",
        "registry_revision",
        "registry_digest",
        "privacy_authorization_id",
        "privacy_authorization_digest",
        "stage_id",
        "operation_id",
        "invocation_id",
        "invocation_digest",
        "source_ids",
        "source_digests",
        "capture_scope_fingerprint",
        "http_method",
        "canonical_url",
        "content_type",
        "non_secret_headers_digest",
        "credential_binding_digest",
        "outbound_data",
        "body_digest",
        "payload_byte_size",
        "request_envelope_digest",
        "max_network_attempts",
        "billable",
        "issued_at",
        "valid_until",
        "revoked_at",
        "session_terms_digest",
        "session_digest",
        "_approval_ledger",
        "_session_ledger",
    )

    def __init__(
        self,
        *,
        session_id: UUID,
        consumed_approval: EgressApproval,
        issued_at: datetime,
        valid_until: datetime,
        session_ledger: "SendSessionLedger",
        _authority: object | None = None,
    ) -> None:
        if _authority is not _EGRESS_SESSION_AUTHORITY:
            raise TypeError(
                "AuthorizedSendSession can only be created by SendSessionFactory"
            )
        if type(consumed_approval) is not EgressApproval:
            raise TypeError("consumed_approval must be EgressApproval")
        if type(session_ledger) is not SendSessionLedger:
            raise TypeError("session_ledger must be SendSessionLedger")
        try:
            consumed_approval.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("consumed approval integrity mismatch") from error
        if consumed_approval.consumed_at != issued_at:
            raise ValueError("session issue time must equal approval consumption time")
        if consumed_approval.revoked_at is not None:
            raise ValueError("a revoked approval cannot create a session")
        if valid_until != consumed_approval.expires_at:
            raise ValueError("session validity must equal the approval validity bound")

        values = (
            ("session_id", session_id),
            ("policy_version", SEND_SESSION_POLICY_VERSION),
            ("approval_id", consumed_approval.approval_id),
            ("approval_terms_digest", consumed_approval.approval_terms_digest),
            ("consumed_approval_digest", consumed_approval.approval_digest),
            ("request_id", consumed_approval.request_id),
            ("plan_id", consumed_approval.plan_id),
            ("plan_digest", consumed_approval.plan_digest),
            (
                "planned_execution_digest",
                consumed_approval.planned_execution_digest,
            ),
            ("registry_revision", consumed_approval.registry_revision),
            ("registry_digest", consumed_approval.registry_digest),
            (
                "privacy_authorization_id",
                consumed_approval.privacy_authorization_id,
            ),
            (
                "privacy_authorization_digest",
                consumed_approval.privacy_authorization_digest,
            ),
            ("stage_id", consumed_approval.stage_id),
            ("operation_id", consumed_approval.operation_id),
            ("invocation_id", consumed_approval.invocation_id),
            ("invocation_digest", consumed_approval.invocation_digest),
            ("source_ids", consumed_approval.source_ids),
            ("source_digests", consumed_approval.source_digests),
            (
                "capture_scope_fingerprint",
                consumed_approval.capture_scope_fingerprint,
            ),
            ("http_method", consumed_approval.http_method),
            ("canonical_url", consumed_approval.canonical_url),
            ("content_type", consumed_approval.content_type),
            (
                "non_secret_headers_digest",
                consumed_approval.non_secret_headers_digest,
            ),
            (
                "credential_binding_digest",
                consumed_approval.credential_binding_digest,
            ),
            ("outbound_data", consumed_approval.outbound_data),
            ("body_digest", consumed_approval.body_digest),
            ("payload_byte_size", consumed_approval.payload_byte_size),
            (
                "request_envelope_digest",
                consumed_approval.request_envelope_digest,
            ),
            ("max_network_attempts", consumed_approval.max_network_attempts),
            ("billable", consumed_approval.billable),
            ("issued_at", issued_at),
            ("valid_until", valid_until),
            ("revoked_at", None),
            ("_approval_ledger", consumed_approval._approval_ledger),
            ("_session_ledger", session_ledger),
        )
        for name, value in values:
            object.__setattr__(self, name, value)
        self._validate_fields()
        if session_id != _session_id_for(_session_identifier_payload(self)):
            raise ValueError("session_id does not bind its terms")
        object.__setattr__(
            self,
            "session_terms_digest",
            digest256(
                "AuthorizedSendSessionTerms",
                AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
                _session_terms_payload(self),
            ),
        )
        object.__setattr__(
            self,
            "session_digest",
            digest256(
                "AuthorizedSendSession",
                AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
                {
                    "session_terms_digest": self.session_terms_digest,
                    "revoked_at": self.revoked_at,
                },
            ),
        )

    def _validate_fields(self) -> None:
        for name in (
            "session_id",
            "approval_id",
            "request_id",
            "plan_id",
            "privacy_authorization_id",
            "stage_id",
            "operation_id",
            "invocation_id",
        ):
            require_uuid(getattr(self, name), name)
        for name in (
            "approval_terms_digest",
            "consumed_approval_digest",
            "plan_digest",
            "planned_execution_digest",
            "registry_digest",
            "privacy_authorization_digest",
            "invocation_digest",
            "non_secret_headers_digest",
            "body_digest",
            "request_envelope_digest",
        ):
            require_digest(getattr(self, name), name)
        require_text(self.policy_version, "policy_version", max_length=256)
        if self.policy_version != SEND_SESSION_POLICY_VERSION:
            raise ValueError("unsupported send-session policy version")
        require_text(self.registry_revision, "registry_revision", max_length=512)
        method = require_text(self.http_method, "http_method", max_length=32)
        if method != method.upper() or HTTP_TOKEN_RE.fullmatch(method) is None:
            raise ValueError("http_method must be an uppercase HTTP token")
        require_canonical_http_url(
            self.canonical_url,
            "canonical_url",
            allow_query=False,
        )
        content_type = require_text(
            self.content_type,
            "content_type",
            max_length=256,
        )
        if content_type != content_type.lower():
            raise ValueError("content_type must be normalized lowercase text")
        if type(self.source_ids) is not tuple or not self.source_ids:
            raise ValueError("source_ids must be a non-empty tuple")
        if type(self.source_digests) is not tuple or len(
            self.source_digests
        ) != len(self.source_ids):
            raise ValueError("source_digests must align with source_ids")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("source_ids must be unique")
        if len(set(self.source_digests)) != len(self.source_digests):
            raise ValueError("source_digests must be unique")
        for source_id in self.source_ids:
            require_uuid(source_id, "source id")
        for source_digest in self.source_digests:
            require_digest(source_digest, "source digest")
        if self.capture_scope_fingerprint is not ContractMarker.NOT_APPLICABLE:
            if isinstance(self.capture_scope_fingerprint, ContractMarker):
                raise ValueError("capture_scope_fingerprint cannot be unknown")
            require_digest(
                self.capture_scope_fingerprint,
                "capture_scope_fingerprint",
            )
        if self.credential_binding_digest is not ContractMarker.NOT_APPLICABLE:
            if isinstance(self.credential_binding_digest, ContractMarker):
                raise ValueError("credential_binding_digest cannot be unknown")
            require_digest(
                self.credential_binding_digest,
                "credential_binding_digest",
            )
        if type(self.outbound_data) is not tuple or not self.outbound_data:
            raise ValueError("outbound_data must be a non-empty tuple")
        if not all(type(item) is OutboundDataKind for item in self.outbound_data):
            raise ValueError("outbound_data must contain outbound data kinds")
        expected_outbound = tuple(
            sorted(self.outbound_data, key=lambda item: item.value)
        )
        if (
            self.outbound_data != expected_outbound
            or len(set(self.outbound_data)) != len(self.outbound_data)
        ):
            raise ValueError("outbound_data must be unique and canonical")
        require_plain_int(self.payload_byte_size, "payload_byte_size", minimum=1)
        require_plain_int(
            self.max_network_attempts,
            "max_network_attempts",
            minimum=1,
        )
        if type(self.billable) is not bool and self.billable is not ContractMarker.UNKNOWN:
            raise ValueError("billable must be bool or unknown")
        require_aware_datetime(self.issued_at, "issued_at")
        require_aware_datetime(self.valid_until, "valid_until")
        if self.valid_until <= self.issued_at:
            raise ValueError("session validity must end after issue time")
        if self.revoked_at is not None:
            require_aware_datetime(self.revoked_at, "revoked_at")
            if not self.issued_at <= self.revoked_at < self.valid_until:
                raise ValueError("session revocation must occur while active")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("AuthorizedSendSession is immutable")

    def __deepcopy__(self, memo: dict[int, object]) -> "AuthorizedSendSession":
        del memo
        return self

    def __repr__(self) -> str:
        return (
            "AuthorizedSendSession("
            f"session_id={self.session_id!r}, approval_id={self.approval_id!r}, "
            f"request_id={self.request_id!r}, stage_id={self.stage_id!r}, "
            f"operation_id={self.operation_id!r}, payload_byte_size="
            f"{self.payload_byte_size!r}, max_network_attempts="
            f"{self.max_network_attempts!r}, issued_at={self.issued_at!r}, "
            f"valid_until={self.valid_until!r}, revoked="
            f"{self.revoked_at is not None!r})"
        )

    def validate_integrity(self) -> None:
        self._validate_fields()
        if type(self._approval_ledger) is not EgressApprovalLedger:
            raise ValueError("approval ledger authority changed")
        if type(self._session_ledger) is not SendSessionLedger:
            raise ValueError("session ledger authority changed")
        if self.session_id != _session_id_for(_session_identifier_payload(self)):
            raise ValueError("session identifier integrity mismatch")
        if self.session_terms_digest != digest256(
            "AuthorizedSendSessionTerms",
            AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
            _session_terms_payload(self),
        ):
            raise ValueError("session terms integrity mismatch")
        if self.session_digest != digest256(
            "AuthorizedSendSession",
            AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
            {
                "session_terms_digest": self.session_terms_digest,
                "revoked_at": self.revoked_at,
            },
        ):
            raise ValueError("session integrity mismatch")

    def validate_active_at(self, now: datetime) -> None:
        require_aware_datetime(now, "now")
        self.validate_integrity()
        if now < self.issued_at:
            raise ValueError("session is not active yet")
        if now >= self.valid_until:
            raise ValueError("session has expired")
        if self.revoked_at is not None:
            raise ValueError("session has been revoked")

    def _with_revocation(
        self,
        *,
        revoked_at: datetime,
        _authority: object | None = None,
    ) -> "AuthorizedSendSession":
        if _authority is not _SESSION_LEDGER_AUTHORITY:
            raise TypeError("session state changes require its ledger")
        replacement = object.__new__(AuthorizedSendSession)
        for name in self.__slots__:
            if name not in ("revoked_at", "session_digest"):
                object.__setattr__(replacement, name, getattr(self, name))
        object.__setattr__(replacement, "revoked_at", revoked_at)
        object.__setattr__(
            replacement,
            "session_digest",
            digest256(
                "AuthorizedSendSession",
                AUTHORIZED_SEND_SESSION_SCHEMA_VERSION,
                {
                    "session_terms_digest": replacement.session_terms_digest,
                    "revoked_at": revoked_at,
                },
            ),
        )
        replacement.validate_integrity()
        return replacement

    def safe_metadata(self) -> dict[str, object]:
        return {
            "session_id": str(self.session_id),
            "approval_id": str(self.approval_id),
            "request_id": str(self.request_id),
            "stage_id": str(self.stage_id),
            "operation_id": str(self.operation_id),
            "http_method": self.http_method,
            "canonical_url": self.canonical_url,
            "outbound_data": tuple(item.value for item in self.outbound_data),
            "payload_byte_size": self.payload_byte_size,
            "max_network_attempts": self.max_network_attempts,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "revoked": self.revoked_at is not None,
        }


@runtime_final
class SendSessionLedger:
    """Process-local authority for immutable send-session revisions."""

    __slots__ = (
        "_sessions",
        "_issued_terms",
        "_current_digests",
        "_approval_ids",
        "_lock",
        "_revision",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_sessions", {})
        object.__setattr__(self, "_issued_terms", {})
        object.__setattr__(self, "_current_digests", {})
        object.__setattr__(self, "_approval_ids", {})
        object.__setattr__(self, "_lock", RLock())
        object.__setattr__(self, "_revision", 0)

    def _issue(
        self,
        session: AuthorizedSendSession,
        *,
        _authority: object | None = None,
    ) -> None:
        if _authority is not _SESSION_LEDGER_AUTHORITY:
            raise TypeError("send sessions can only be issued by SendSessionFactory")
        self._validate_new_session(session)
        with self._lock:
            self._require_issue_slot_locked(session)
            original_revision = self._revision
            try:
                self._publish_locked(session)
            except BaseException:
                try:
                    self._rollback_publish_locked(
                        session,
                        original_revision=original_revision,
                    )
                except BaseException as rollback_error:
                    raise _session_error(
                        "发送会话无法安全回滚。"
                    ) from rollback_error
                raise

    def _issue_with_one_shot_consent(
        self,
        session: AuthorizedSendSession,
        *,
        consent_ledger: ConsentLedger,
        grant: ConsentGrant,
        authorization: AuthorizationContext,
        planned: PlannedExecution,
        stage: ExecutionPlanStage,
        consumed_at: datetime,
        _authority: object | None = None,
    ) -> AuthorizedSendSession:
        """Publish one session and its one-shot consent lease atomically.

        SendSessionFactory enters this method while the exact Consent and
        Approval locks are already held.  This method acquires only the
        Session lock, then invokes the fixed ConsentLedger transition; it does
        not accept an arbitrary callback capable of changing the lock graph.
        """

        if _authority is not _SESSION_LEDGER_AUTHORITY:
            raise TypeError("send sessions can only be issued by SendSessionFactory")
        if type(consent_ledger) is not ConsentLedger:
            raise TypeError("consent_ledger must be ConsentLedger")
        if type(grant) is not ConsentGrant:
            raise TypeError("grant must be ConsentGrant")
        if type(authorization) is not AuthorizationContext:
            raise TypeError("authorization must be AuthorizationContext")
        if type(planned) is not PlannedExecution:
            raise TypeError("planned must be PlannedExecution")
        if type(stage) is not ExecutionPlanStage:
            raise TypeError("stage must be ExecutionPlanStage")
        require_aware_datetime(consumed_at, "consumed_at")
        self._validate_new_session(session)
        with self._lock:
            self._require_issue_slot_locked(session)
            original_session_revision = self._revision
            original_consent_revision = consent_ledger._revision
            try:
                self._publish_locked(session)
                consent_ledger._consume_for_session(
                    grant=grant,
                    authorization=authorization,
                    planned=planned,
                    stage=stage,
                    session=session,
                    session_ledger=self,
                    consumed_at=consumed_at,
                    _authority=_CONSENT_SESSION_AUTHORITY,
                )
            except BaseException:
                rollback_error: BaseException | None = None
                try:
                    consent_ledger._rollback_session_use(
                        original_grant=grant,
                        session_id=session.session_id,
                        original_revision=original_consent_revision,
                        _authority=_CONSENT_SESSION_AUTHORITY,
                    )
                except BaseException as error:
                    rollback_error = error
                try:
                    self._rollback_publish_locked(
                        session,
                        original_revision=original_session_revision,
                    )
                except BaseException as error:
                    if rollback_error is None:
                        rollback_error = error
                if rollback_error is not None:
                    raise _session_error(
                        "发送会话与一次性同意事务无法安全回滚。"
                    ) from rollback_error
                raise
            return session

    @staticmethod
    def _validate_new_session(session: AuthorizedSendSession) -> None:
        if type(session) is not AuthorizedSendSession:
            raise TypeError("session must be AuthorizedSendSession")
        try:
            session.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _session_error("发送会话完整性校验失败。") from error

    def _require_issue_slot_locked(
        self,
        session: AuthorizedSendSession,
    ) -> None:
        if session._session_ledger is not self:
            raise _session_error("发送会话不属于当前账本。")
        if session.session_id in self._sessions:
            raise _session_error("发送会话标识已存在。")
        if session.approval_id in self._approval_ids:
            raise _session_error("同一出站批准已经创建发送会话。")

    def _publish_locked(self, session: AuthorizedSendSession) -> None:
        self._sessions[session.session_id] = session
        self._issued_terms[session.session_id] = session.session_terms_digest
        self._current_digests[session.session_id] = session.session_digest
        self._approval_ids[session.approval_id] = session.session_id
        object.__setattr__(self, "_revision", self._revision + 1)

    def _rollback_publish_locked(
        self,
        session: AuthorizedSendSession,
        *,
        original_revision: int,
    ) -> None:
        expected_entries = (
            (self._sessions, session.session_id, session),
            (
                self._issued_terms,
                session.session_id,
                session.session_terms_digest,
            ),
            (
                self._current_digests,
                session.session_id,
                session.session_digest,
            ),
            (
                self._approval_ids,
                session.approval_id,
                session.session_id,
            ),
        )
        for mapping, key, expected in expected_entries:
            current = mapping.get(key)
            if current is not None and current != expected:
                raise _session_error("发送会话临时事务状态已经变化。")
        if self._revision not in (
            original_revision,
            original_revision + 1,
        ):
            raise _session_error("发送会话临时事务版本已经变化。")
        for mapping, key, expected in reversed(expected_entries):
            if mapping.get(key) == expected:
                del mapping[key]
        object.__setattr__(self, "_revision", original_revision)

    def _require_current_locked(self, session: AuthorizedSendSession) -> None:
        if type(session) is not AuthorizedSendSession:
            raise TypeError("session must be AuthorizedSendSession")
        try:
            session.validate_integrity()
        except (ValueError, TypeError, AttributeError) as error:
            raise _session_error("发送会话完整性校验失败。") from error
        current = self._sessions.get(session.session_id)
        if (
            current is not session
            or session._session_ledger is not self
            or self._issued_terms.get(session.session_id)
            != session.session_terms_digest
            or self._current_digests.get(session.session_id)
            != session.session_digest
            or self._approval_ids.get(session.approval_id) != session.session_id
        ):
            raise _session_error("发送会话不属于当前账本或状态已经变化。")

    def snapshot(self, session_id: UUID) -> AuthorizedSendSession:
        require_uuid(session_id, "session_id")
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                raise _session_error("发送会话不存在。")
            self._require_current_locked(current)
            return current

    def validate_active(
        self,
        session: AuthorizedSendSession,
        *,
        now: datetime,
    ) -> None:
        require_aware_datetime(now, "now")
        with self._lock:
            self._require_current_locked(session)
            try:
                session.validate_active_at(now)
            except ValueError as error:
                raise _session_error("发送会话当前不可用。") from error

    def _run_active_action(
        self,
        *,
        session: AuthorizedSendSession,
        now: datetime,
        action: Callable[[], _T],
        _authority: object | None = None,
    ) -> _T:
        """Run W09 authority checks under the current session revision."""

        if _authority is not _SESSION_ATTEMPT_AUTHORITY:
            raise TypeError("session attempt checks require AttemptGate")
        require_aware_datetime(now, "now")
        if not callable(action):
            raise TypeError("action must be callable")
        with self._lock:
            self._require_current_locked(session)
            try:
                session.validate_active_at(now)
            except ValueError as error:
                raise _session_error(
                    "发送会话当前不可用于新 attempt。",
                    stage="attempt_gate",
                ) from error
            return action()

    def revoke(
        self,
        *,
        session_id: UUID,
        revoked_at: datetime,
    ) -> AuthorizedSendSession:
        require_uuid(session_id, "session_id")
        require_aware_datetime(revoked_at, "revoked_at")
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                raise _session_error("无法撤销不存在的发送会话。")
            self._require_current_locked(current)
            try:
                current.validate_active_at(revoked_at)
                replacement = current._with_revocation(
                    revoked_at=revoked_at,
                    _authority=_SESSION_LEDGER_AUTHORITY,
                )
            except ValueError as error:
                raise _session_error("发送会话当前不可撤销。") from error
            self._sessions[session_id] = replacement
            self._current_digests[session_id] = replacement.session_digest
            object.__setattr__(self, "_revision", self._revision + 1)
            return replacement

    def safe_metadata(self) -> dict[str, int]:
        with self._lock:
            return {
                "revision": self._revision,
                "session_count": len(self._sessions),
            }


def _validate_approval_binding(
    *,
    approval: EgressApproval,
    approval_ledger: EgressApprovalLedger,
    planned: PlannedExecution,
    invocation: StageInvocation,
    prepared: PreparedOutbound,
    authorization: AuthorizationContext,
    stage: ExecutionPlanStage,
    operation: ExecutionPlanNetworkOperation,
) -> None:
    if type(approval) is not EgressApproval:
        raise TypeError("approval must be EgressApproval")
    try:
        approval.validate_integrity()
    except (ValueError, TypeError, AttributeError) as error:
        raise _session_error("出站批准完整性校验失败。") from error
    capture = invocation.input
    if (
        approval._approval_ledger is not approval_ledger
        or approval.policy_version != EGRESS_POLICY_VERSION
        or approval.request_id != planned.plan.request_id
        or approval.plan_id != planned.plan.plan_id
        or approval.plan_digest != planned.plan.plan_digest
        or approval.planned_execution_digest != planned.planned_execution_digest
        or approval.registry_revision
        != planned.resolved_pipeline.registry_revision
        or approval.registry_digest != planned.resolved_pipeline.registry_digest
        or approval.privacy_authorization_id != authorization.authorization_id
        or approval.privacy_authorization_digest
        != authorization.authorization_digest
        or approval.stage_id != stage.stage_id
        or approval.operation_id != operation.operation_id
        or approval.invocation_id != invocation.invocation_id
        or approval.invocation_digest != invocation.invocation_digest
        or approval.source_ids != prepared.source_ids
        or approval.source_digests != prepared.source_digests
        or approval.source_ids != (capture.capture_id, invocation.invocation_id)
        or approval.source_digests
        != (capture.validation_digest, invocation.invocation_digest)
        or approval.capture_scope_fingerprint
        != prepared.capture_scope_fingerprint
        or approval.capture_scope_fingerprint != capture.scope_fingerprint
        or approval.http_method != prepared.http_method
        or approval.canonical_url != prepared.canonical_url
        or approval.content_type != prepared.content_type
        or approval.non_secret_headers_digest
        != prepared.non_secret_headers_digest
        or approval.credential_binding_digest
        != prepared.credential_binding_digest
        or approval.outbound_data != prepared.outbound_data
        or approval.body_digest != prepared.body_digest
        or approval.payload_byte_size != prepared.payload_byte_size
        or approval.request_envelope_digest
        != prepared.request_envelope_digest
        or approval.max_network_attempts != stage.max_attempts_per_operation
        or approval.billable != operation.billable
        or approval.consumed_at is not None
        or approval.revoked_at is not None
        or (
            authorization.valid_until is not None
            and approval.expires_at > authorization.valid_until
        )
    ):
        raise _session_error(
            "出站批准未精确绑定当前计划、授权、调用或请求包络。"
        )


@runtime_final
class SendSessionFactory:
    """Atomically consume one approval and issue one exact send session."""

    __slots__ = ()

    @staticmethod
    def create(
        *,
        planned: PlannedExecution,
        invocation: StageInvocation,
        prepared: PreparedOutbound,
        authorization: AuthorizationContext,
        consent_ledger: ConsentLedger,
        approval: EgressApproval,
        approval_ledger: EgressApprovalLedger,
        session_ledger: SendSessionLedger,
        now: datetime,
    ) -> AuthorizedSendSession:
        if type(approval_ledger) is not EgressApprovalLedger:
            raise TypeError("approval_ledger must be EgressApprovalLedger")
        if type(session_ledger) is not SendSessionLedger:
            raise TypeError("session_ledger must be SendSessionLedger")
        require_aware_datetime(now, "now")

        def consume_and_issue() -> AuthorizedSendSession:
            stage, operation = _validate_exact_egress_binding(
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                consent_ledger=consent_ledger,
                now=now,
            )
            if (
                type(stage) is not ExecutionPlanStage
                or type(operation) is not ExecutionPlanNetworkOperation
            ):
                raise _session_error("冻结计划中的网络操作无效。")
            grants = consent_ledger.snapshot_for_ids(
                authorization.consent_grant_ids
            )
            matching_grants = tuple(
                grant for grant in grants if grant.binding_id == stage.binding_id
            )
            if len(matching_grants) != 1:
                raise _session_error("当前阶段没有唯一同意记录覆盖。")
            matching_grant: ConsentGrant = matching_grants[0]
            if any(grant.one_shot for grant in grants) and (
                len(grants) != 1
                or not matching_grant.one_shot
                or len(
                    tuple(
                        candidate
                        for candidate in planned.plan.stages
                        if candidate.network_operations
                    )
                )
                != 1
                or len(stage.network_operations) != 1
            ):
                raise _session_error(
                    "一次性同意暂不支持多阶段或多操作发送计划。"
                )
            _validate_approval_binding(
                approval=approval,
                approval_ledger=approval_ledger,
                planned=planned,
                invocation=invocation,
                prepared=prepared,
                authorization=authorization,
                stage=stage,
                operation=operation,
            )

            def issue_session(
                consumed_approval: EgressApproval,
            ) -> AuthorizedSendSession:
                if consumed_approval.consumed_at != now:
                    raise _session_error("出站批准消费时间与会话签发时间不一致。")
                identifier_payload = _session_identifier_payload_from_approval(
                    approval=consumed_approval,
                    issued_at=now,
                    valid_until=consumed_approval.expires_at,
                )
                session = AuthorizedSendSession(
                    session_id=_session_id_for(identifier_payload),
                    consumed_approval=consumed_approval,
                    issued_at=now,
                    valid_until=consumed_approval.expires_at,
                    session_ledger=session_ledger,
                    _authority=_EGRESS_SESSION_AUTHORITY,
                )
                if not matching_grant.one_shot:
                    session_ledger._issue(
                        session,
                        _authority=_SESSION_LEDGER_AUTHORITY,
                    )
                    return session

                return session_ledger._issue_with_one_shot_consent(
                    session,
                    consent_ledger=consent_ledger,
                    grant=matching_grant,
                    authorization=authorization,
                    planned=planned,
                    stage=stage,
                    consumed_at=now,
                    _authority=_SESSION_LEDGER_AUTHORITY,
                )

            return approval_ledger._consume_with(
                approval=approval,
                now=now,
                action=issue_session,
                _authority=_EGRESS_SESSION_AUTHORITY,
            )

        return PrivacyGate()._run_authorized_action(
            planned=planned,
            authorization=authorization,
            ledger=consent_ledger,
            now=now,
            action=consume_and_issue,
            _authority=_ATOMIC_PRIVACY_AUTHORITY,
        )


__all__ = [
    "AUTHORIZED_SEND_SESSION_SCHEMA_VERSION",
    "SEND_SESSION_POLICY_VERSION",
    "AuthorizedSendSession",
    "SendSessionFactory",
    "SendSessionLedger",
]
