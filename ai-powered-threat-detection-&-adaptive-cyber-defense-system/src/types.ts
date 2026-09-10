/**
 * Domain types for AI-Powered Threat Detection & Adaptive Cyber Defense System
 * Honours Computer Science Project
 */

export type ThreatClass = 
  | 'BENIGN'
  | 'DOS'
  | 'PROBE'
  | 'BRUTE_FORCE'
  | 'BOT'
  | 'WEB_ATTACK'
  | 'OTHER_MALICIOUS';

export type HighLevelCategory = 'NORMAL' | 'SUSPICIOUS' | 'MALICIOUS';

export type RiskLevel = 'Low' | 'Moderate' | 'High' | 'Critical';

export type AlertStatus = 'New' | 'Investigating' | 'Resolved' | 'False Positive';

export type UserRole = 'Analyst' | 'Administrator';

export interface User {
  id: string;
  username: string;
  name: string;
  email: string;
  role: UserRole;
}

export interface NetworkTelemetry {
  id?: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'DNS' | 'SSH';
  duration: number; // in seconds
  srcBytes: number;
  dstBytes: number;
  packetCount: number;
  failedLoginAttempts: number;
  requestFrequency: number; // requests per sec
  connectionState: 'SF' | 'S0' | 'REJ' | 'RSTO' | 'SH' | 'OTHER';
  service: 'http' | 'ftp' | 'smtp' | 'ssh' | 'dns' | 'private' | 'other';
  sameSrvRate: number; // 0.0 - 1.0
  diffSrvRate: number; // 0.0 - 1.0
  dstHostCount: number;
  dstHostSrvCount: number;
}

export interface FeatureContribution {
  featureName: string;
  displayName: string;
  value: number | string;
  contribution: number; // Normalized importance contribution (-1.0 to +1.0)
  impact: 'positive' | 'negative' | 'neutral';
  explanation: string;
}

export interface RiskBreakdown {
  mlProbabilityScore: number; // weighted contribution (0-45)
  threatSeverityBase: number; // weighted contribution (0-25)
  trafficAnomalyIndex: number; // weighted contribution (0-15)
  behavioralAnomalyPenalty: number; // failed logins & rate (0-15)
  benignMitigationCredit: number; // subtracted (-15 to 0)
  rawScore: number;
  finalScore: number; // clamped 0-100
  formulaDescription: string;
}

export interface AdaptiveDefenseAction {
  id: string;
  actionType: 'LOG_ONLY' | 'INCREASE_MONITORING' | 'MFA_CHALLENGE' | 'RATE_LIMIT' | 'QUARANTINE_IP' | 'ISOLATE_CONTAINER' | 'ADMIN_ESCALATION';
  summary: string;
  description: string;
  target: string;
  riskThresholdTriggered: RiskLevel;
  simulated: true;
  executionTimestamp: string;
  status: 'PENDING' | 'SIMULATED_ACTIVE' | 'REVOKED' | 'EXPIRED';
  technicalDetails: {
    commandSimulated: string;
    subsystem: 'Firewall (iptables/nftables)' | 'WAF' | 'Identity Provider' | 'Network Segmenter' | 'SIEM';
    reversionPolicy: string;
  };
}

export interface MLPrediction {
  eventId: string;
  predictedClass: ThreatClass;
  highLevelCategory: HighLevelCategory;
  confidence: number; // 0.0 to 1.0
  probabilities: Record<ThreatClass, number>;
  modelUsed: 'Random Forest Ensemble' | 'Logistic Regression' | 'Rule-Based Baseline';
  inferenceLatencyMs: number;
  topFeatures: FeatureContribution[];
  explainableSummary: string[];
}

export interface AnalyzedEvent {
  id: string;
  timestamp: string;
  telemetry: NetworkTelemetry;
  prediction: MLPrediction;
  riskScore: number; // 0-100
  riskLevel: RiskLevel;
  riskBreakdown: RiskBreakdown;
  adaptiveAction: AdaptiveDefenseAction;
  hasAlert: boolean;
  alertId?: string;
  analyzedBy: string;
}

export interface SecurityAlert {
  id: string;
  eventId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  threatType: ThreatClass;
  highLevelCategory: HighLevelCategory;
  riskScore: number;
  severity: RiskLevel;
  status: AlertStatus;
  explanation: string;
  recommendedAction: string;
  analystNotes?: string;
  updatedAt: string;
  assignedTo?: string;
}

export interface SOCDashboardMetrics {
  totalEventsAnalyzed: number;
  normalCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  criticalAlertsCount: number;
  overallRiskIndex: number; // average recent risk (0-100)
  overallRiskLevel: RiskLevel;
  modelAccuracy: number;
  modelPrecision: number;
  modelRecall: number;
  modelF1Score: number;
  activeSimulatedDefenses: number;
  threatDistribution: { name: string; value: number; color: string }[];
  timelineData: { time: string; normal: number; suspicious: number; malicious: number; avgRisk: number }[];
  riskDistribution: { range: string; count: number }[];
}

export interface ModelEvaluationMetrics {
  modelName: string;
  description: string;
  trainingSamples: number;
  testingSamples: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  rocAuc: number;
  inferenceTimePer1000EventsMs: number;
  confusionMatrix: {
    labels: string[];
    matrix: number[][]; // rows: actual, cols: predicted
  };
  classificationReport: Record<string, { precision: number; recall: number; f1: number; support: number }>;
}

export interface ResearchExperiment {
  id: number;
  name: string;
  hypothesis: string;
  methodology: string;
  keyFindings: string;
  status: 'Completed' | 'In Progress';
  metricsTable: {
    columnHeaders: string[];
    rows: (string | number)[][];
  };
  conclusion: string;
}

export interface RiskWeightConfig {
  mlProbabilityWeight: number;
  threatSeverityWeight: number;
  trafficAnomalyWeight: number;
  behavioralAnomalyWeight: number;
  benignMitigationCredit: number;
}
