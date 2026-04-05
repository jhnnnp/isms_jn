from __future__ import annotations

import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

from . import __version__
from .models import DetectedMatch, ProcessedMatch
from .rate_limit import RateLimitMiddleware
from .redactor import decrypt_tokens, detect_pii, redact_text
from .schemas import (
    DecryptResponse,
    DecryptTextRequest,
    DetectedMatchResponse,
    FileMetadata,
    HealthResponse,
    PiiType,
    ProcessedMatchResponse,
    RedactResponse,
    RedactTextRequest,
    ScanResponse,
    ScanSummary,
    ScanTextRequest,
)

COMPLIANCE_NOTES = [
    "ISMS-P 2.6: 개인정보 식별 결과를 구조화해 후속 통제와 감사를 지원합니다.",
    "ISMS-P 3.2: 마스킹 및 암호화 결과를 분리해 최소 권한 기반 처리 흐름을 지원합니다.",
]
ALLOWED_TEXT_CONTENT_TYPES = {"text/plain"}
MAX_UPLOAD_BYTES = 256 * 1024
GENERIC_DECRYPT_ERROR = "Unable to decrypt the provided token."
_DEMO_DIR = Path(__file__).resolve().parent


def _load_demo_html() -> str:
    return (_DEMO_DIR / "demo_page.html").read_text(encoding="utf-8")


DEMO_HTML = _load_demo_html()


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes")


def _build_summary(pii_types: list[PiiType]) -> ScanSummary:
    counts = Counter(pii_types)
    return ScanSummary(totalMatches=len(pii_types), counts=dict(counts))


def _detected_response_items(matches: list[DetectedMatch]) -> list[DetectedMatchResponse]:
    return [DetectedMatchResponse(**asdict(match)) for match in matches]


def _processed_response_items(matches: list[ProcessedMatch]) -> list[ProcessedMatchResponse]:
    return [ProcessedMatchResponse(**asdict(match)) for match in matches]


def _client_error(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _normalize_encrypt_types(encrypt_types: list[PiiType] | None) -> list[PiiType]:
    return list(dict.fromkeys(encrypt_types or []))


async def _read_text_upload(upload: UploadFile) -> tuple[str, FileMetadata]:
    if upload.content_type not in ALLOWED_TEXT_CONTENT_TYPES:
        raise _client_error("Only text/plain uploads are supported.")

    payload = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(payload) > MAX_UPLOAD_BYTES:
        raise _client_error("Uploaded file exceeds the maximum allowed size.")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _client_error("Uploaded file must be valid UTF-8 text.") from error

    return text, FileMetadata(
        filename=upload.filename or "upload.txt",
        contentType=upload.content_type or "text/plain",
        sizeBytes=len(payload),
    )


def _ensure_encryption_key(encrypt_types: list[PiiType], encryption_key: str | None) -> None:
    if encrypt_types and not encryption_key:
        raise _client_error("encryptionKey is required when encryptTypes is provided.")


def _redact_response(text: str, encrypt_types: list[PiiType], encryption_key: str | None) -> RedactResponse:
    try:
        output_text, processed = redact_text(
            text,
            encrypt_types=encrypt_types,
            encryption_key=encryption_key,
        )
    except ValueError as error:
        raise _client_error(str(error)) from error

    return RedactResponse(
        summary=_build_summary([match.pii_type for match in processed]),
        matches=_processed_response_items(processed),
        outputText=output_text,
        complianceNotes=COMPLIANCE_NOTES,
    )


def _decrypt_response(text: str, encryption_key: str) -> DecryptResponse:
    try:
        output_text = decrypt_tokens(text, encryption_key)
    except ValueError as error:
        raise _client_error(GENERIC_DECRYPT_ERROR) from error

    return DecryptResponse(outputText=output_text, complianceNotes=COMPLIANCE_NOTES)


def create_app() -> FastAPI:
    application = FastAPI(
        title="ISMS-P PII Toolkit API",
        description="개인정보 탐지, 비식별화, 복호화를 HTTP API와 Swagger UI로 제공합니다.",
        version=__version__,
    )

    if _env_flag("PII_TOOLKIT_RATE_LIMIT_ENABLED", "0"):
        limit = int(os.getenv("PII_TOOLKIT_RATE_LIMIT_PER_MINUTE", "120"))
        application.add_middleware(RateLimitMiddleware, calls_per_minute=limit)

    @application.get("/", response_class=HTMLResponse, include_in_schema=False)
    def demo_page() -> HTMLResponse:
        if os.getenv("PII_TOOLKIT_ENABLE_DEMO", "1").lower() in ("0", "false", "no"):
            raise HTTPException(status_code=404, detail="Demo UI is disabled.")
        return HTMLResponse(
            content=DEMO_HTML,
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @application.post("/scan/text", response_model=ScanResponse, tags=["scan"])
    def scan_text(request: ScanTextRequest) -> ScanResponse:
        matches = detect_pii(request.text)
        return ScanResponse(
            summary=_build_summary([match.pii_type for match in matches]),
            matches=_detected_response_items(matches),
            complianceNotes=COMPLIANCE_NOTES,
        )

    @application.post("/redact/text", response_model=RedactResponse, tags=["redact"])
    def redact_text_endpoint(request: RedactTextRequest) -> RedactResponse:
        _ensure_encryption_key(request.encrypt_types, request.encryption_key)
        return _redact_response(request.text, request.encrypt_types, request.encryption_key)

    @application.post("/scan/file", response_model=ScanResponse, tags=["scan"])
    async def scan_file(upload: Annotated[UploadFile, File(...)]) -> ScanResponse:
        text, metadata = await _read_text_upload(upload)
        matches = detect_pii(text)
        return ScanResponse(
            summary=_build_summary([match.pii_type for match in matches]),
            matches=_detected_response_items(matches),
            complianceNotes=COMPLIANCE_NOTES,
            file=metadata,
        )

    @application.post("/redact/file", response_model=RedactResponse, tags=["redact"])
    async def redact_file(
        upload: Annotated[UploadFile, File(...)],
        encrypt_types: Annotated[list[PiiType] | None, Form(alias="encryptTypes")] = None,
        encryption_key: Annotated[str | None, Form(alias="encryptionKey")] = None,
    ) -> RedactResponse:
        requested_encrypt_types = _normalize_encrypt_types(encrypt_types)
        _ensure_encryption_key(requested_encrypt_types, encryption_key)

        text, metadata = await _read_text_upload(upload)
        response = _redact_response(text, requested_encrypt_types, encryption_key)
        response.file = metadata
        return response

    @application.post("/decrypt/text", response_model=DecryptResponse, tags=["decrypt"])
    def decrypt_text_endpoint(request: DecryptTextRequest) -> DecryptResponse:
        return _decrypt_response(request.text, request.encryption_key)

    return application


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run(
        "isms_pii_toolkit.api:app",
        host=os.getenv("PII_TOOLKIT_API_HOST", "127.0.0.1"),
        port=int(os.getenv("PII_TOOLKIT_API_PORT", "8000")),
    )
