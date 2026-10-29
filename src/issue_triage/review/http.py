"""FastAPI/Jinja local review adapter. Explicit injected configuration, zero remote apply.

No credential/environment files, GitHub client, provider dispatch or listener is opened here.
All admitted reviews remain agent_provisional, including sessions exercised by real browsers.
"""

import asyncio
import hashlib
import json
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, Request
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from ..apply.dry_run import dry_run
from ..shared.rulings.store import JournalError
from ..worker.local import LocalWorkflow, WorkflowError
from .local import DecisionRequest, current_views
from .security import BoundaryError, BrowserMutation
from .service import provisional_form, submit_provisional
from .web_auth import WebAuth

COOKIE = "s6_local_review"
LIMIT = 65536
ISSUE = re.compile(r"[1-9][0-9]{0,18}:[1-9][0-9]{0,18}:[1-9][0-9]{0,18}")
SECURITY = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    # no-referrer makes native browser form POST Origin:null. Keep exact-Origin checks;
    # same-origin preserves that request origin without sending cross-origin referrers.
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'",
}


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = item
        return result

    def constant(_):
        raise ValueError("nonfinite_json")

    return json.loads(value, object_pairs_hook=pairs, parse_constant=constant)


def cookie_session(raw):
    values = {}
    if raw is not None:
        for piece in raw.split(";"):
            key, separator, value = piece.strip().partition("=")
            if (
                not separator
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key) is None
                or key in values
                or len(value) > 256
                or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in value)
                or len(values) >= 32
            ):
                raise ValueError("ambiguous_cookie")
            values[key] = value
    return values.get(COOKIE)


class HttpBoundary:
    """Validate actual ASGI bytes before FastAPI/form parsing; forwarded authority is refused."""

    def __init__(self, app, *, origin):
        self.app, self.origin = app, origin
        parsed = urlsplit(origin)
        self.host, self.scheme = parsed.netloc, parsed.scheme

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secured(message):
            if message["type"] == "http.response.start":
                message["headers"] = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.decode("latin1").lower() not in {k.lower() for k in SECURITY}
                ] + [(k.lower().encode(), v.encode()) for k, v in SECURITY.items()]
            await send(message)

        async def refuse(status):
            await PlainTextResponse("request_refused", status_code=status)(scope, receive, secured)

        try:
            headers = scope["headers"]
            if len(headers) > 64 or sum(len(k) + len(v) for k, v in headers) > 8192:
                raise ValueError
            values = {}
            for key, value in headers:
                key, value = key.decode("ascii").lower(), value.decode("ascii")
                if key in values or key == "forwarded" or key.startswith("x-forwarded-"):
                    raise ValueError
                values[key] = value
            if values.get("host") != self.host or scope.get("scheme") != self.scheme:
                await refuse(421)
                return
            if values.get("sec-fetch-site") not in {None, "none", "same-origin"}:
                await refuse(403)
                return
            if scope.get("query_string") or "transfer-encoding" in values:
                raise ValueError
            if scope["method"] == "GET" and values.get("content-length") not in {None, "0"}:
                raise ValueError
            session = cookie_session(values.get("cookie"))
            method = scope["method"]
            if method not in {"GET", "POST"}:
                await refuse(405)
                return
            form = {}
            if method == "POST":
                if values.get("origin") != self.origin:
                    await refuse(403)
                    return
                if values.get("content-type") != "application/x-www-form-urlencoded":
                    await refuse(415)
                    return
                length = values.get("content-length", "")
                if re.fullmatch(r"0|[1-9][0-9]{0,5}", length) is None:
                    raise ValueError
                if int(length) > LIMIT:
                    await refuse(413)
                    return
                data = bytearray()
                async with asyncio.timeout(5):
                    for _ in range(1024):
                        message = await receive()
                        if message["type"] != "http.request":
                            raise ValueError
                        data.extend(message.get("body", b""))
                        if len(data) > LIMIT:
                            await refuse(413)
                            return
                        if not message.get("more_body", False):
                            break
                    else:
                        raise ValueError
                if len(data) != int(length):
                    raise ValueError
                encoded = data.decode("ascii")
                if re.search(r"%(?![0-9A-Fa-f]{2})", encoded):
                    raise ValueError
                for key, value in parse_qsl(
                    encoded,
                    keep_blank_values=True,
                    strict_parsing=True,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=16,
                ):
                    if key in form:
                        raise ValueError
                    form[key] = value
            elif "origin" in values and values["origin"] != self.origin:
                await refuse(403)
                return
            scope.setdefault("state", {}).update(
                form=form, session=session, actual_origin=values.get("origin")
            )
        except (ValueError, UnicodeError, TimeoutError):
            await refuse(400)
            return
        await self.app(scope, receive, secured)


def create_app(*, state_root, boundary, clock=None):
    """Explicit app factory. Caller owns its path, keys, trusted origin and any listener."""
    root = Path(state_root).absolute()
    with LocalWorkflow(root):
        pass  # Existing app path validation precedes opening the separate auth database.
    auth = WebAuth(root)
    clock = clock or (lambda: int(time.time()))
    templates = Environment(
        loader=FileSystemLoader(Path(__file__).with_name("templates")),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, debug=False)
    app.add_middleware(HttpBoundary, origin=boundary.origin)

    def render(page, **context):
        return HTMLResponse(templates.get_template(page + ".html").render(**context))

    def sealed(session, action, data, now):
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return {
            "payload": payload,
            "seal": boundary.form_seal(session, action=action, payload=payload, now=now),
        }

    def verified(request, action, keys, now):
        form = request.state.form
        if set(form) != keys:
            raise BoundaryError("form_invalid")
        boundary.verify_form(
            request.state.session,
            action=action,
            payload=form["payload"],
            seal=form["seal"],
            now=now,
        )
        return strict_json(form["payload"])

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    def handle(request: Request, path: str):
        method, session = request.method, request.state.session
        try:
            now = clock()
            if method == "GET" and path == "style.css":
                return PlainTextResponse(
                    templates.get_template("style.css").render(), media_type="text/css"
                )
            if method == "GET" and (path == "login" or (path == "" and session is None)):
                return render("login")
            if method == "POST" and path == "login":
                if set(request.state.form) != {"credential"}:
                    raise BoundaryError("form_invalid")
                denied = None
                with auth.transaction() as connection:
                    if not auth.attempt(connection, now):
                        denied = 429
                    else:
                        try:
                            issued = boundary.login(
                                method=method,
                                origin=request.state.actual_origin,
                                credential=request.state.form["credential"].encode("utf-8"),
                                now=now,
                            )
                        except BoundaryError:
                            denied = 403
                        else:
                            auth.admit(connection, issued, now)
                if denied:
                    return PlainTextResponse("authentication_refused", status_code=denied)
                response = RedirectResponse("/", status_code=303)
                response.set_cookie(
                    COOKIE,
                    issued.value,
                    max_age=boundary.lifetime,
                    httponly=True,
                    secure=boundary.origin.startswith("https:"),
                    samesite="strict",
                    path="/",
                )
                return response
            with auth.transaction() as connection:
                auth.require(connection, boundary, session, now)
                logout = sealed(session, "logout", {}, now)
                if method == "POST" and path == "logout":
                    if verified(request, "logout", {"payload", "seal"}, now) != {}:
                        raise BoundaryError("form_invalid")
                    auth.revoke(connection, session)
                    response = RedirectResponse("/login", status_code=303)
                    response.delete_cookie(
                        COOKIE,
                        path="/",
                        httponly=True,
                        secure=boundary.origin.startswith("https:"),
                        samesite="strict",
                    )
                    return response
                with LocalWorkflow(root) as workflow:
                    if method == "GET" and path == "":
                        return render("queue", jobs=workflow.queue(), logout=logout)
                    if method == "GET" and path.startswith("issue/"):
                        issue = path.removeprefix("issue/")
                        if ISSUE.fullmatch(issue) is None:
                            raise BoundaryError("form_invalid")
                        stored = workflow.result(issue)
                        if stored.suggestions is None or stored.judgment is None:
                            return render(
                                "hold",
                                issue=issue,
                                logout=logout,
                                reasons=stored.reason_codes,
                            )
                        bundle, _, result = workflow.current(issue)
                        forms = []
                        for proposed in result.suggestions.fields:
                            value = provisional_form(
                                workflow,
                                boundary,
                                session,
                                issue_key=issue,
                                field_name=proposed.field,
                                now=now,
                            )
                            decision = DecisionRequest(
                                event_id="web-" + uuid.uuid4().hex,
                                issue_key=issue,
                                field=proposed.field,
                                expected_revision=value.revision,
                                expected_prior_event_id=value.prior,
                                disposition="accept",
                                actor_label="local-operator-rehearsal",
                                reason="Local browser rehearsal",
                                at_utc=datetime.fromtimestamp(now, UTC)
                                .isoformat()
                                .replace("+00:00", "Z"),
                            )
                            forms.append(
                                {
                                    **sealed(
                                        session,
                                        "review_form",
                                        decision.model_dump(mode="json"),
                                        now,
                                    ),
                                    "field": proposed.field,
                                    "status": proposed.status,
                                    "csrf": value.csrf,
                                    "value": json.dumps(value.proposed_value, ensure_ascii=True),
                                }
                            )
                        current_views(workflow, result.suggestions)
                        journal_sha = hashlib.sha256(
                            workflow.journal.path.read_bytes()
                            if workflow.journal.path.exists()
                            else b""
                        ).hexdigest()
                        preview = sealed(
                            session,
                            "dry_run",
                            {
                                "issue": issue,
                                "revision": result.suggestions.revision_sha256,
                                "journal_sha256": journal_sha,
                            },
                            now,
                        )
                        return render(
                            "issue",
                            issue=issue,
                            title=bundle.issue.title,
                            body=bundle.issue.body,
                            proposal=json.dumps(
                                result.model_dump(mode="json"), indent=2, ensure_ascii=True
                            ),
                            forms=forms,
                            preview=preview,
                            logout=logout,
                        )
                    if method == "POST" and path == "review":
                        value = verified(
                            request,
                            "review_form",
                            {"payload", "seal", "csrf", "disposition", "edit_value", "reason"},
                            now,
                        )
                        form = request.state.form
                        value.update(disposition=form["disposition"], reason=form["reason"])
                        value["value"] = (
                            strict_json(form["edit_value"])
                            if form["disposition"] == "edit"
                            else None
                        )
                        decision = DecisionRequest.model_validate(value)
                        receipt = submit_provisional(
                            workflow,
                            boundary,
                            BrowserMutation(
                                method, request.state.actual_origin, session, form["csrf"]
                            ),
                            decision.canonical_bytes(),
                            now=now,
                        )
                        return render(
                            "receipt",
                            issue=decision.issue_key,
                            logout=logout,
                            result=json.dumps(receipt.model_dump(mode="json"), indent=2),
                        )
                    if method == "POST" and path == "preview":
                        value = verified(request, "dry_run", {"payload", "seal"}, now)
                        if set(value) != {"issue", "revision", "journal_sha256"}:
                            raise BoundaryError("form_invalid")
                        receipts = dry_run(
                            workflow,
                            value["issue"],
                            provisional=True,
                            expected_revision=value["revision"],
                            expected_journal_sha256=value["journal_sha256"],
                        )
                        return render(
                            "receipt",
                            issue=value["issue"],
                            logout=logout,
                            result=json.dumps(
                                {
                                    "receipts": receipts,
                                    "http_writes": 0,
                                    "remote_apply_allowed": False,
                                },
                                indent=2,
                            ),
                        )
                return PlainTextResponse("not_found", status_code=404)
        except BoundaryError:
            return PlainTextResponse("authorization_refused", status_code=403)
        except (WorkflowError, JournalError):
            return PlainTextResponse("current_state_unavailable", status_code=409)
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            return PlainTextResponse("invalid_request", status_code=400)
        except Exception:
            return PlainTextResponse("local_service_unavailable", status_code=503)

    return app


def serve_demo(*, state_root, origin):
    """An explicitly public fixture rehearsal, never a real-credential deployment."""
    from .security import OperatorBoundary

    parsed = urlsplit(origin)
    boundary = OperatorBoundary(
        origin=origin,
        operator_credential=b"public-local-demo-operator-control-01",
        session_key=b"different-public-demo-session-control-01",
    )
    if parsed.scheme != "http":
        raise BoundaryError("demo_requires_local_http")
    app = create_app(state_root=state_root, boundary=boundary)
    import uvicorn

    uvicorn.run(
        app,
        host=parsed.hostname,
        port=parsed.port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        server_header=False,
        timeout_keep_alive=5,
        limit_concurrency=16,
    )
