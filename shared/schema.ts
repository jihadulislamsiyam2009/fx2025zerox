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
});

export const toolStatus = pgTable("tool_status", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  status: text("status").notNull().default("ready"), // ready, running, error, disabled
  successRate: integer("success_rate").default(100),
  lastUsed: timestamp("last_used"),
  version: text("version"),
  isActive: boolean("is_active").default(true),
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

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertToolStatus = z.infer<typeof insertToolStatusSchema>;
export type ToolStatus = typeof toolStatus.$inferSelect;
