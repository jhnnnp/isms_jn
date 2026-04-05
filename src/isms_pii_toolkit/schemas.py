from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .pii_types import PiiType, SUPPORTED_PII_TYPES

ProcessingStrategy = Literal["mask", "encrypt"]
ValidationMethod = Literal["rrn_checksum", "regex_pattern"]
MAX_TEXT_LENGTH = 50_000
MAX_ENCRYPT_TYPES = len(SUPPORTED_PII_TYPES)


class ApiModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class FileMetadata(ApiModel):
    filename: str
    content_type: str = Field(alias="contentType")
    size_bytes: int = Field(alias="sizeBytes")


class ScanSummary(ApiModel):
    total_matches: int = Field(alias="totalMatches")
    counts: dict[PiiType, int]


class DetectedMatchResponse(ApiModel):
    pii_type: PiiType = Field(alias="piiType")
    value: str
    start: int
    end: int
    validation_method: ValidationMethod = Field(
        alias="validationMethod",
        description="rrn_checksum: checksum and birth-date validation; regex_pattern: pattern match only.",
    )


class ProcessedMatchResponse(ApiModel):
    pii_type: PiiType = Field(alias="piiType")
    original: str
    transformed: str
    strategy: ProcessingStrategy
    validation_method: ValidationMethod = Field(
        alias="validationMethod",
        description="Same as the detection step for this span.",
    )
    start: int = Field(description="Start offset in the input string (0-based, Unicode code points).")
    end: int = Field(description="End offset in the input string (exclusive).")


class ScanTextRequest(ApiModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)


class RedactTextRequest(ScanTextRequest):
    encrypt_types: list[PiiType] = Field(
        default_factory=list,
        alias="encryptTypes",
        max_length=MAX_ENCRYPT_TYPES,
    )
    encryption_key: str | None = Field(default=None, alias="encryptionKey")

    @field_validator("encrypt_types")
    @classmethod
    def deduplicate_encrypt_types(cls, value: list[PiiType]) -> list[PiiType]:
        return list(dict.fromkeys(value))


class DecryptTextRequest(ApiModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)
    encryption_key: str = Field(min_length=1, alias="encryptionKey")


class ScanResponse(ApiModel):
    summary: ScanSummary
    matches: list[DetectedMatchResponse]
    compliance_notes: list[str] = Field(alias="complianceNotes")
    file: FileMetadata | None = None


class RedactResponse(ApiModel):
    summary: ScanSummary
    matches: list[ProcessedMatchResponse]
    output_text: str = Field(alias="outputText")
    compliance_notes: list[str] = Field(alias="complianceNotes")
    file: FileMetadata | None = None


class DecryptResponse(ApiModel):
    output_text: str = Field(alias="outputText")
    compliance_notes: list[str] = Field(alias="complianceNotes")


class HealthResponse(ApiModel):
    status: str
    version: str
