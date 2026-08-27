"""HTTP surface for the generation gateway.

A seller submits a brief; the gateway screens it, calls the internal inference
cluster, screens what comes back, and stores the artifact under its digest.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
from pathlib import Path
from typing import Annotated, Final

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import moderation, prompts
from .artifacts import ArtifactStore, ArtifactTooLargeError, UnsupportedMediaTypeError

logger = logging.getLogger("slopshop.generation")

# The gateway speaks only to the inference cluster inside the mesh.
INFERENCE_ENDPOINT: Final = "https://inference.internal.slopshop.example/v1/render"

REQUEST_TIMEOUT: Final = httpx.Timeout(connect=2.0, read=60.0, write=10.0, pool=2.0)
MAX_ARTIFACT_BYTES: Final = 16 * 1024 * 1024

app = FastAPI(title="SlopShop Generation", version="1.5.0", docs_url=None, redoc_url=None)


def require_service_caller(request: Request) -> None:
    """Rejects any request that does not present the gateway's service token."""
    expected = _required_env("GENERATION_SERVICE_TOKEN")

    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthenticated")

    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthenticated")


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


class RenderRequest(BaseModel):
    title: str = Field(min_length=1, max_length=prompts.MAX_TITLE_CHARS)
    brief: str = Field(min_length=1, max_length=prompts.MAX_BRIEF_CHARS)
    style: str = Field(pattern="^(flat|painterly|photographic|isometric)$")


class RenderResponse(BaseModel):
    digest: str
    media_type: str
    size_bytes: int
    review_required: bool


def get_store() -> ArtifactStore:
    return ArtifactStore(Path(_required_env("GENERATION_ARTIFACT_ROOT")))


def get_client() -> httpx.Client:
    """Builds the inference client.

    Timeouts, connection limits and the service token are set once here.
    """
    return httpx.Client(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        verify=True,
        headers={"authorization": f"Bearer {_required_env('INFERENCE_SERVICE_TOKEN')}"},
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
    )


@app.post(
    "/v1/renders",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_service_caller)],
)
def create_render(
    body: RenderRequest,
    store: Annotated[ArtifactStore, Depends(get_store)],
    client: Annotated[httpx.Client, Depends(get_client)],
) -> RenderResponse:
    brief_verdict = moderation.screen_text(f"{body.title}\n{body.brief}")
    if brief_verdict.blocked:
        logger.info("render refused reasons=%s", ",".join(brief_verdict.reasons))
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "brief_refused")

    try:
        messages = prompts.build_messages(body.title, body.brief, body.style)
    except (prompts.BriefTooLongError, prompts.UnknownStyleError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_brief") from exc

    payload = {
        "messages": [{"role": m.role, "content": m.content} for m in messages],
        "max_output_bytes": MAX_ARTIFACT_BYTES,
    }

    try:
        response = client.post(INFERENCE_ENDPOINT, json=payload)
        response.raise_for_status()
        rendered = response.json()
    except httpx.HTTPError as exc:
        logger.warning("inference call failed: %s", exc.__class__.__name__)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "inference_unavailable") from exc

    media_type = str(rendered.get("mediaType", ""))
    try:
        artifact = base64.b64decode(str(rendered.get("body", "")), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "malformed_artifact") from exc

    artifact_verdict = moderation.screen_artifact(media_type, artifact, MAX_ARTIFACT_BYTES)
    if artifact_verdict.blocked:
        logger.info("artifact refused reasons=%s", ",".join(artifact_verdict.reasons))
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "artifact_refused")

    try:
        stored = store.put(artifact, media_type)
    except (ArtifactTooLargeError, UnsupportedMediaTypeError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "artifact_refused") from exc

    logger.info("render stored digest=%s bytes=%d", stored.digest, stored.size_bytes)

    return RenderResponse(
        digest=stored.digest,
        media_type=stored.media_type,
        size_bytes=stored.size_bytes,
        review_required=brief_verdict.decision is moderation.Decision.REVIEW,
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
