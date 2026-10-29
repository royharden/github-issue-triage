"""Explicit signed intake/token/capture composition; no credential or transport discovery."""

from ..ingest.capture import CaptureIntake
from ..shared.ghapp.tokens import acquire_reader_token
from ..shared.ghapp.webhook import parse_delivery


def receive_signed_capture(
    jobs,
    identity,
    raw_body,
    *,
    signature_header,
    webhook_secret,
    delivery_id,
    event,
    received_at,
    captured_at,
    issuer,
    signer,
    registered_permissions,
    transport,
    now_seconds,
    clock,
    provenance,
    app_actor_id=None,
):
    """Authenticate first; atomic replay/coalescing precedes any token exchange.

    The caller supplies an open store and the entire trusted host configuration. The
    existing token and capture APIs keep separate cooperative 30-second budgets.
    This queues captured input, not classification, proposals or a completed job.
    Neither configured nor synthetic transport proves authenticated GitHub origin.
    """
    delivery = parse_delivery(
        raw_body,
        signature_header=signature_header,
        secret=webhook_secret,
        delivery_id=delivery_id,
        event=event,
        received_at=received_at,
        installation_id=identity.installation_id,
        repository_id=identity.repository_id,
        app_actor_id=app_actor_id,
    )

    def token_factory():
        return acquire_reader_token(
            identity.installation_id,
            identity.repository_id,
            issuer=issuer,
            signer=signer,
            registered_permissions=registered_permissions,
            transport=transport,
            now_seconds=now_seconds,
            clock=clock,
        ).token

    return CaptureIntake(jobs, identity).receive(
        delivery,
        token_factory=token_factory,
        transport=transport,
        clock=clock,
        captured_at=captured_at,
        provenance=provenance,
    )
