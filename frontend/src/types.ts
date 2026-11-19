export type RiskTier = 'critical' | 'high' | 'medium' | 'low';

export type Screen = 'overview' | 'inventory' | 'heatmap' | 'detail' | 'recommend' | 'roadmap';

export type MigrationAction =
  | 'retain' | 'monitor' | 'deprecate' | 'replace' | 'hybridize' | 'rotate'
  | 'reissue-certificate' | 'upgrade-library' | 'reconfigure' | 'manual-review';

export interface MigrationCandidate {
  id: string;
  label: string;
  action: string;
  standard: string;
  maturity: string;
  fit: string;
  latencyImpact?: string;
  costImpact?: string;
  constraints?: string[];
  rationale?: string;
}

export interface PlaybookStep {
  order: number;
  phase: string;
  action: string;
  ownerRole: string;
  evidence: string;
  rollback: string;
  blocking?: boolean;
  blockers?: string[];
}

export interface CertificateFacts {
  issuer?: string;
  subject?: string;
  notBefore?: string;
  notAfter?: string;
  daysToExpiry?: number;
  keyAlgorithm?: string;
  signatureAlgorithm?: string;
  keySizeBits?: number;
  selfSigned?: boolean;
  sanCount?: number;
}

export interface FrontendAsset {
  id?: string;
  name: string;
  type: string;
  algo: string;
  rec: string;
  std: string;
  complexity: string;
  loc: string;
  bu: string;
  x: number;
  y: number;
  z?: number;
  autoEsc: boolean;
  r?: number;
  tier?: RiskTier;
  quantumVulnerable?: boolean;
  businessCriticality?: string;
  exposure?: string;
  vulnerabilityReason?: string;
  sizeDelta?: string;
  usageContext?: string;
  artifactType?: string;
  action?: MigrationAction;
  phase?: 'immediate' | 'transition' | 'target' | 'monitor' | string;
  classicalStatus?: string;
  quantumStatus?: string;
  maturity?: string;
  readinessTier?: string;
  readinessScore?: number;
  readinessComponents?: Record<string, { label: string; score: number; maximum: number }>;
  hndlTier?: string;
  hndlApplicable?: boolean;
  blockers?: string[];
  assumptions?: string[];
  candidates?: MigrationCandidate[];
  playbook?: PlaybookStep[];
  strategyRationale?: string;
  certificateFacts?: CertificateFacts;
  evidence?: Record<string, unknown>;
  relatedAssetRefs?: string[];
}

export interface AssetDetailResponse {
  asset: any;
  moscaBreakdown: Record<string, unknown>;
  recommendation: Record<string, unknown>;
  assessment: Record<string, any>;
  strategy: Record<string, any>;
  relationships: { bomRef: string; name: string; artifactType?: string; relation: string }[];
}

export interface RoadmapItem {
  id: string;
  bomRef: string;
  name: string;
  artifactType?: string;
  usageContext?: string;
  action?: string;
  readinessTier?: string;
  hndlTier?: string;
  riskTier: string;
  target?: string;
}

export interface RoadmapPhase {
  id: string;
  label: string;
  description: string;
  count: number;
  items: RoadmapItem[];
}

export interface RoadmapResponse {
  scanId: string;
  total: number;
  summary: Record<string, number>;
  phases: RoadmapPhase[];
}

export interface StandardEntry {
  id: string;
  displayName: string;
  family: string;
  standard: string;
  status: string;
  classicalStatus: string;
  quantumStatus: string;
  references?: string[];
}

export interface AssetSummaryResponse {
  items: any[];
  total: number;
  page: number;
  pageSize: number;
  pages: number;
  zUsed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export interface ScanResponse {
  scanId: string;
  sourceType: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  assetCount: number;
  createdAt: string;
  completedAt?: string;
  error?: string;
}
