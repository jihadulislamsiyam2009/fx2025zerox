import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, boolean, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const scans = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  target: text("target").notNull(),
  scanType: text("scan_type").notNull(),
  status: text("status").notNull().default("pending"), // pending, running, completed, failed
  progress: integer("progress").default(0),
  startedAt: timestamp("started_at").default(sql`now()`),
  completedAt: timestamp("completed_at"),
  results: jsonb("results").default({}),
  vulnerabilities: jsonb("vulnerabilities").default([]),
  toolsUsed: text("tools_used").array().default([]),
  successRate: integer("success_rate").default(0),
  logs: jsonb("logs").default([]),
  riskScore: integer("risk_score").default(0),
  riskLevel: text("risk_level").default("unknown"), // critical, high, medium, low, unknown
  aiAnalysis: jsonb("ai_analysis").default({}),
  wordlistsUsed: text("wordlists_used").array().default([]),
  executionTime: integer("execution_time").default(0), // in seconds
  criticalVulns: integer("critical_vulns").default(0),
  highVulns: integer("high_vulns").default(0),
  mediumVulns: integer("medium_vulns").default(0),
  lowVulns: integer("low_vulns").default(0),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id).notNull(),
  type: text("type").notNull(), // xss, sql_injection, rce, etc.
  severity: text("severity").notNull(), // critical, high, medium, low
  title: text("title").notNull(),
  description: text("description").notNull(),
  target: text("target").notNull(),
  evidence: jsonb("evidence").default({}),
  recommendation: text("recommendation"),
  discoveredAt: timestamp("discovered_at").default(sql`now()`),
  cveId: text("cve_id"), // CVE identifier if applicable
  exploitability: integer("exploitability").default(0), // 0-10 scale
  impact: integer("impact").default(0), // 0-10 scale
  remediation: text("remediation"), // detailed remediation steps
  references: text("references").array().default([]), // external references
  toolUsed: text("tool_used").notNull(), // which tool discovered this
  confidenceLevel: integer("confidence_level").default(50), // 0-100%
  verified: boolean("verified").default(false), // manually verified
  falsePositive: boolean("false_positive").default(false),
  tags: text("tags").array().default([]), // classification tags
});

export const toolStatus = pgTable("tool_status", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  status: text("status").notNull().default("ready"), // ready, running, error, disabled
  successRate: integer("success_rate").default(100),
  lastUsed: timestamp("last_used"),
  version: text("version"),
  isActive: boolean("is_active").default(true),
  category: text("category").default("general"), // subdomain, xss, sqli, network, etc.
  reliability: integer("reliability").default(85), // 0-100%
  averageExecutionTime: integer("average_execution_time").default(0), // in seconds
  vulnerabilitiesFound: integer("vulnerabilities_found").default(0),
  totalScans: integer("total_scans").default(0),
  configuration: jsonb("configuration").default({}),
});

// New table for scan reports and analytics
export const scanReports = pgTable("scan_reports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  scanId: varchar("scan_id").references(() => scans.id).notNull(),
  reportType: text("report_type").notNull(), // pdf, html, json, csv
  reportData: jsonb("report_data").default({}),
  generatedAt: timestamp("generated_at").default(sql`now()`),
  downloadCount: integer("download_count").default(0),
});

// New table for threat intelligence
export const threatIntelligence = pgTable("threat_intelligence", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  cveId: text("cve_id").unique(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  cvssScore: integer("cvss_score").default(0), // 0-100 (CVSS * 10)
  publishedDate: timestamp("published_date"),
  modifiedDate: timestamp("modified_date"),
  references: text("references").array().default([]),
  affectedProducts: text("affected_products").array().default([]),
  exploitAvailable: boolean("exploit_available").default(false),
  patchAvailable: boolean("patch_available").default(false),
  tags: text("tags").array().default([]),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertScanSchema = createInsertSchema(scans).pick({
  target: true,
  scanType: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  discoveredAt: true,
});

export const insertToolStatusSchema = createInsertSchema(toolStatus).omit({
  id: true,
});

export const insertScanReportSchema = createInsertSchema(scanReports).omit({
  id: true,
  generatedAt: true,
});

export const insertThreatIntelligenceSchema = createInsertSchema(threatIntelligence).omit({
  id: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertToolStatus = z.infer<typeof insertToolStatusSchema>;
export type ToolStatus = typeof toolStatus.$inferSelect;
export type InsertScanReport = z.infer<typeof insertScanReportSchema>;
export type ScanReport = typeof scanReports.$inferSelect;
export type InsertThreatIntelligence = z.infer<typeof insertThreatIntelligenceSchema>;
export type ThreatIntelligence = typeof threatIntelligence.$inferSelect;
