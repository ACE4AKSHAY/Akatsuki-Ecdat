"""
Pydantic schemas for ECDAT.
Strictly conforms to ECDAT — CONTRACT.md and CycloneDX 1.6 CBOM standard.
"""
from typing import Optional, List, Literal, Any, Dict
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ==============================================================================
# 1. Raw finding — A → B (M1/M2/M3 -> M4)
# ==============================================================================
class RawFinding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sourceModule: str = Field(
        ...,
        description="Must be 'M1_source_scanner', 'M2_dep_binary_scanner', or 'M3_container_config_scanner'",
    )
    scanTargetId: str = Field(..., description="Unique scan job identifier")
    filePath: str = Field(..., description="Relative or absolute path to scanned file")
    lineNumber: Optional[int] = Field(None, description="Line number where signal was detected")
    language: Optional[str] = Field(None, description="Programming or markup language")
    library: Optional[str] = Field(None, description="Library name or package (e.g. pyca/cryptography)")
    rawSignal: str = Field(..., description="Exact matched code string or banner")
    detectedPrimitive: str = Field(..., description="Canonical or raw detected primitive name (e.g. SHA1)")
    primitiveCategory: str = Field(..., description="Category: hash, asymmetric_kem, asymmetric_sig, symmetric, mac, kdf, protocol, cert")
    keySizeBits: Optional[int] = Field(None, description="Key length in bits if applicable")
    mode: Optional[str] = Field(None, description="Cipher mode (e.g. CBC, GCM) or null")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0 - 1.0")
    detectionTier: str = Field(..., description="'ast', 'regex', 'manifest', 'cert-parse', etc.")
    # Optional evidence used by the context, readiness and certificate engines.
    usageContext: Optional[str] = Field(None, description="Inferred use: encryption, signing, password-storage, transport…")
    artifactType: Optional[str] = Field(None, description="algorithm, certificate, protocol, library, hardware-module, cloud-service")
    protocol: Optional[str] = Field(None, description="Protocol version observed, e.g. TLS 1.2")
    certificateFacts: Optional[Dict[str, Any]] = Field(None, description="Parsed X.509 facts for certificate findings")
    referencedPaths: Optional[List[str]] = Field(None, description="Paths referenced by a config directive (e.g. ssl_certificate)")


# ==============================================================================
# 2. Canonical CBOM Asset — B → C (M4/M5/M6 -> M7/M8/M9)
# ==============================================================================
class AlgorithmProperties(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    primitive: str
    parameterSetIdentifier: Optional[str] = None
    executionEnvironment: Optional[str] = "software-plain-ram"
    implementationPlatform: Optional[str] = "generic"
    cryptoFunctions: Optional[List[str]] = Field(default_factory=list)
    classicalSecurityLevel: Optional[int] = None
    nistQuantumSecurityLevel: Optional[int] = None


class CryptoProperties(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assetType: str = "algorithm"
    algorithmProperties: AlgorithmProperties
    oid: Optional[str] = None


class Occurrence(BaseModel):
    location: str
    line: Optional[int] = None


class EcdatEnrichment(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    quantumVulnerable: bool
    vulnerabilityReason: str
    businessCriticality: Literal["Critical", "High", "Medium", "Low"]
    dataClassification: str
    exposure: str  # "external-facing" or "internal-only"
    estimatedShelfLifeYears: float
    estimatedMigrationEffortYears: float
    moscaX: float
    moscaY: float
    moscaZ: float
    moscaR: float
    moscaRiskTier: Literal["Critical", "High", "Medium", "Low"]
    recommendedReplacement: str
    referenceStandard: str
    # Optional extensions for rich UI & scoring transparency
    riskScore: Optional[float] = None
    autoEscalated: Optional[bool] = False
    escalationReason: Optional[str] = None
    recommendationMode: Optional[str] = None
    migrationComplexity: Optional[str] = None
    relativeSizeDelta: Optional[str] = None
    # Four independent classification axes and migration guidance (M5/M6).
    usageContext: str = "unknown"
    contextConfidence: float = 0.0
    artifactType: str = "algorithm"
    classicalStatus: str = "unknown"
    quantumStatus: str = "unknown"
    standardsMaturity: str = "not-applicable"
    migrationAction: str = "manual-review"
    migrationPhase: str = "monitor"
    complianceTarget: str = "NIST-general"
    hndlApplicable: bool = False
    hndlTier: str = "Unknown"
    hndlScore: Optional[float] = None
    hndlExplanation: Optional[str] = None
    readinessScore: Optional[int] = None
    readinessTier: str = "Unknown"
    readinessComponents: Dict[str, Any] = Field(default_factory=dict)
    blockers: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    candidates: List[Dict[str, Any]] = Field(default_factory=list)
    playbook: List[Dict[str, Any]] = Field(default_factory=list)
    strategyRationale: Optional[str] = None
    certificateFacts: Optional[Dict[str, Any]] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    relatedAssetRefs: List[str] = Field(default_factory=list)


class CanonicalCBOMAsset(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    bom_ref: str = Field(..., alias="bom-ref")
    type: str = "cryptographic-asset"
    name: str
    cryptoProperties: CryptoProperties
    occurrences: List[Occurrence] = Field(default_factory=list)
    ecdatEnrichment: EcdatEnrichment


class CycloneDXDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    bomFormat: str = "CycloneDX"
    specVersion: str = "1.6"
    serialNumber: str
    version: int = 1
    # Schema-valid component dictionaries produced by to_schema_component;
    # raw CanonicalCBOMAsset instances would carry non-standard fields.
    components: List[Dict[str, Any]] = Field(default_factory=list)


# ==============================================================================
# API Request / Response Schemas for M7
# ==============================================================================
class ScanCreate(BaseModel):
    sourceType: Literal["git", "upload", "image", "path"] = Field(
        default="path",
        description="Scan input source type"
    )
    target: str = Field(..., description="Target repository URL, local path, container image reference, or uploaded file")
    complianceTarget: Optional[Literal["NIST-general", "CNSA2.0"]] = "NIST-general"
    threatTimelineOverride: Optional[float] = Field(None, ge=0.5, le=50.0, description="Optional custom Z (years until CRQC) override")


class ScanResponse(BaseModel):
    scanId: str
    sourceType: str
    target: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: float
    assetCount: int
    createdAt: str
    completedAt: Optional[str] = None
    error: Optional[str] = None


class AssetSummaryResponse(BaseModel):
    items: List[CanonicalCBOMAsset]
    total: int
    page: int
    pageSize: int
    pages: int
    zUsed: float
    criticalCount: int
    highCount: int
    mediumCount: int
    lowCount: int


class AssetDetailResponse(BaseModel):
    asset: CanonicalCBOMAsset
    moscaBreakdown: Dict[str, Any]
    recommendation: Dict[str, Any]
    assessment: Dict[str, Any] = Field(default_factory=dict)
    strategy: Dict[str, Any] = Field(default_factory=dict)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)


class AssetContextUpdateRequest(BaseModel):
    usageContext: Optional[Literal[
        "encryption", "signing", "token-signing", "firmware-signing", "hashing",
        "integrity", "password-storage", "key-establishment", "transport",
        "key-management", "certificate", "data-protection", "unknown",
    ]] = None
    artifactType: Optional[Literal[
        "algorithm", "certificate", "protocol", "library", "hardware-module", "cloud-service", "key-reference",
    ]] = None
    complianceTarget: Optional[Literal["NIST-general", "CNSA2.0"]] = None
    protocol: Optional[str] = None
    operator: Optional[str] = Field(
        None, max_length=128, description="Who applied the override; recorded in the audit trail"
    )


class ThreatModelUpdateRequest(BaseModel):
    threatTimelineYears: Optional[float] = Field(None, ge=1.0, le=50.0, description="Z: Years until CRQC")
    weightQuantum: Optional[float] = Field(None, ge=0.0, le=1.0)
    weightRatio: Optional[float] = Field(None, ge=0.0, le=1.0)
    weightBusiness: Optional[float] = Field(None, ge=0.0, le=1.0)
    weightExposure: Optional[float] = Field(None, ge=0.0, le=1.0)
    shelfLifeDefaults: Optional[Dict[str, float]] = None
    migrationEffortDefaults: Optional[Dict[str, float]] = None

    @field_validator('shelfLifeDefaults', 'migrationEffortDefaults')
    @classmethod
    def positive_years(cls, value):
        import math
        if value is not None and any(not math.isfinite(years) or years < 0 or years > 100 for years in value.values()):
            raise ValueError('Custom timeline values must be finite and between 0 and 100 years.')
        return value
