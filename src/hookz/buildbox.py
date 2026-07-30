"""Client for the canonical Xahau C-to-WASM build service.

This is deliberately separate from ``hookz.wasm.pipeline``.  Those pipelines
run local binaries; this module sends the exact source to the public buildbox
and returns the artifact it produced.  A remote failure never falls back to a
local compiler.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import math
import os
import socket
import time
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from hookz.annotations import strip as strip_annotations

DEFAULT_ENDPOINT = "https://hook-buildbox.xrpl.org/api/build"
DEFAULT_OPTIONS = "-O3"
DEFAULT_TIMEOUT = 120.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})

logger = logging.getLogger("hookz.buildbox")


class BuildboxError(RuntimeError):
    """Base class for a buildbox request that produced no usable artifact."""


class BuildboxRejected(BuildboxError):
    """The service ran successfully but rejected the source or artifact."""


class BuildboxUnavailable(BuildboxError):
    """Transient service failures exhausted the retry policy."""


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded exponential retry policy.

    CI gets more attempts because a remote sanity gate is otherwise needlessly
    sensitive to one dropped connection.  Explicit environment configuration
    wins in every environment.
    """

    attempts: int
    initial_delay: float = 1.0
    max_delay: float = 8.0

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "RetryPolicy":
        env = os.environ if environment is None else environment
        raw = env.get("HOOKZ_BUILDBOX_ATTEMPTS")
        try:
            attempts = int(raw) if raw else (4 if env.get("CI") else 2)
        except ValueError as exc:
            raise BuildboxError(
                "HOOKZ_BUILDBOX_ATTEMPTS must be an integer"
            ) from exc
        if not 1 <= attempts <= 10:
            raise BuildboxError(
                "HOOKZ_BUILDBOX_ATTEMPTS must be between 1 and 10"
            )
        return cls(attempts=attempts)

    def delay_after(self, failed_attempt: int) -> float:
        return min(
            self.initial_delay * (2 ** max(failed_attempt - 1, 0)),
            self.max_delay,
        )


@dataclass(frozen=True)
class BuildboxRequest:
    """Canonical JSON request bytes and their identity."""

    body: bytes
    sha256: str
    source_sha256: str
    filename: str
    options: str


@dataclass(frozen=True)
class BuildboxResult:
    """A remote artifact plus enough provenance to identify the request."""

    wasm: bytes
    endpoint: str
    request_sha256: str
    source_sha256: str
    wasm_sha256: str
    filename: str
    options: str
    attempts: int
    tasks: tuple[dict, ...] = ()


@dataclass(frozen=True)
class _Response:
    status: int
    body: bytes
    headers: Mapping[str, str]


@dataclass(frozen=True)
class _TransientFailure(Exception):
    message: str
    retry_after: float | None = None


def endpoint_from_environment() -> str:
    return os.environ.get("HOOKZ_BUILDBOX_URL", DEFAULT_ENDPOINT)


def timeout_from_environment() -> float:
    raw = os.environ.get("HOOKZ_BUILDBOX_TIMEOUT")
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise BuildboxError(
            "HOOKZ_BUILDBOX_TIMEOUT must be a number of seconds"
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise BuildboxError(
            "HOOKZ_BUILDBOX_TIMEOUT must be a finite number greater than zero"
        )
    return timeout


def _safe_filename(filename: str) -> str:
    name = Path(filename).name
    if (
        not name
        or len(name.rsplit(".", 1)) != 2
        or not all(
            part and all(c.isalnum() or c in "_-" for c in part)
            for part in name.rsplit(".", 1)
        )
    ):
        return "hook.c"
    return name


def prepare_request(
    source: str,
    *,
    filename: str = "hook.c",
    options: str = DEFAULT_OPTIONS,
) -> BuildboxRequest:
    """Create the exact request sent to the service.

    Audit annotations are removed here rather than in individual callers, so
    ``build`` and ``build-test-hooks`` cannot disagree about the source.
    """

    stripped = strip_annotations(source)
    safe_name = _safe_filename(filename)
    payload = {
        "output": "wasm",
        "compress": False,
        "strip": True,
        "files": [
            {
                "type": "c",
                "name": safe_name,
                "options": options,
                "src": stripped,
            }
        ],
    }
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return BuildboxRequest(
        body=body,
        sha256=hashlib.sha256(body).hexdigest(),
        source_sha256=hashlib.sha256(stripped.encode("utf-8")).hexdigest(),
        filename=safe_name,
        options=options,
    )


def _read_bounded(response) -> bytes:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise _TransientFailure(
            f"response exceeded {MAX_RESPONSE_BYTES} bytes"
        )
    return body


def _post(endpoint: str, body: bytes, timeout: float) -> _Response:
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "hookz-buildbox/1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return _Response(
                status=response.status,
                body=_read_bounded(response),
                headers=dict(response.headers.items()),
            )
    except HTTPError as exc:
        try:
            body_bytes = exc.read(MAX_RESPONSE_BYTES + 1)
        except (
            TimeoutError,
            socket.timeout,
            OSError,
            HTTPException,
        ) as read_exc:
            raise _TransientFailure(
                f"HTTP {exc.code} response read failed: "
                f"{type(read_exc).__name__}: {read_exc}"
            ) from read_exc
        if len(body_bytes) > MAX_RESPONSE_BYTES:
            raise _TransientFailure(
                f"HTTP {exc.code} response exceeded "
                f"{MAX_RESPONSE_BYTES} bytes"
            ) from exc
        return _Response(
            status=exc.code,
            body=body_bytes,
            headers=dict(exc.headers.items()) if exc.headers else {},
        )
    except (
        URLError,
        TimeoutError,
        socket.timeout,
        OSError,
        HTTPException,
    ) as exc:
        raise _TransientFailure(f"{type(exc).__name__}: {exc}") from exc


def _retry_after(headers: Mapping[str, str]) -> float | None:
    raw = next(
        (value for key, value in headers.items() if key.lower() == "retry-after"),
        None,
    )
    if raw is None:
        return None
    try:
        return min(max(float(raw), 0.0), 30.0)
    except ValueError:
        return None


def _response_message(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    return text[:1000] or "(empty response)"


def _decode_success(response: _Response) -> tuple[bytes, tuple[dict, ...]]:
    if response.status != 200:
        message = f"HTTP {response.status}: {_response_message(response.body)}"
        if response.status in TRANSIENT_HTTP_STATUSES:
            raise _TransientFailure(message, _retry_after(response.headers))
        raise BuildboxRejected(message)

    try:
        data = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _TransientFailure(f"invalid JSON response: {exc}") from exc
    if not isinstance(data, dict):
        raise _TransientFailure("JSON response is not an object")

    tasks_value = data.get("tasks", [])
    if not isinstance(tasks_value, list):
        raise _TransientFailure("JSON response field 'tasks' is not a list")
    tasks = tuple(task for task in tasks_value if isinstance(task, dict))
    if data.get("success") is not True:
        details = []
        for task in tasks:
            if task.get("success") is False and task.get("console"):
                details.append(
                    f"{task.get('name', 'build task')}: {task['console']}"
                )
        message = str(data.get("message") or "build rejected")
        if details:
            message += "\n" + "\n".join(details)
        raise BuildboxRejected(message[:8000])

    output = data.get("output")
    if not isinstance(output, str) or not output:
        raise _TransientFailure("successful response has no output")
    try:
        wasm = base64.b64decode(output, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _TransientFailure(f"output is not valid base64: {exc}") from exc
    if not wasm.startswith(b"\x00asm\x01\x00\x00\x00"):
        raise _TransientFailure("decoded output is not a WebAssembly module")
    return wasm, tasks


def compile_source(
    source: str,
    *,
    filename: str = "hook.c",
    options: str = DEFAULT_OPTIONS,
    endpoint: str | None = None,
    timeout: float | None = None,
    retry_policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> BuildboxResult:
    """Compile source through the canonical service, with bounded retries."""

    target = endpoint or endpoint_from_environment()
    request = prepare_request(source, filename=filename, options=options)
    policy = retry_policy or RetryPolicy.from_environment()
    request_timeout = timeout if timeout is not None else timeout_from_environment()
    last_failure = "unknown transient failure"

    for attempt in range(1, policy.attempts + 1):
        try:
            response = _post(target, request.body, request_timeout)
            wasm, tasks = _decode_success(response)
            return BuildboxResult(
                wasm=wasm,
                endpoint=target,
                request_sha256=request.sha256,
                source_sha256=request.source_sha256,
                wasm_sha256=hashlib.sha256(wasm).hexdigest(),
                filename=request.filename,
                options=request.options,
                attempts=attempt,
                tasks=tasks,
            )
        except _TransientFailure as exc:
            last_failure = exc.message
            if attempt >= policy.attempts:
                break
            delay = (
                exc.retry_after
                if exc.retry_after is not None
                else policy.delay_after(attempt)
            )
            logger.warning(
                "buildbox attempt %d/%d failed (%s); retrying in %.1fs",
                attempt,
                policy.attempts,
                exc.message,
                delay,
            )
            sleep(delay)

    raise BuildboxUnavailable(
        f"buildbox unavailable after {policy.attempts} attempt(s): "
        f"{last_failure}"
    )
