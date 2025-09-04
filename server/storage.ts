import { type User, type InsertUser, type Scan, type InsertScan, type Vulnerability, type InsertVulnerability, type ToolStatus, type InsertToolStatus } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  getScan(id: string): Promise<Scan | undefined>;
  getScans(): Promise<Scan[]>;
  getActiveScans(): Promise<Scan[]>;
  createScan(scan: InsertScan): Promise<Scan>;
  updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined>;
  
  getVulnerabilities(scanId?: string): Promise<Vulnerability[]>;
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  
  getToolStatus(): Promise<ToolStatus[]>;
  getToolByName(name: string): Promise<ToolStatus | undefined>;
  createOrUpdateToolStatus(tool: InsertToolStatus): Promise<ToolStatus>;
  updateToolStatus(name: string, updates: Partial<ToolStatus>): Promise<ToolStatus | undefined>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private scans: Map<string, Scan>;
  private vulnerabilities: Map<string, Vulnerability>;
  private tools: Map<string, ToolStatus>;

  constructor() {
    this.users = new Map();
    this.scans = new Map();
    this.vulnerabilities = new Map();
    this.tools = new Map();
    this.initializeTools();
  }

  private initializeTools() {
    const defaultTools = [
      { name: "Sublist3r", status: "ready", successRate: 98, version: "1.0", isActive: true },
      { name: "Subfinder", status: "ready", successRate: 97, version: "2.6.3", isActive: true },
      { name: "Sudomy", status: "ready", successRate: 95, version: "1.1.9", isActive: true },
      { name: "Dome", status: "ready", successRate: 94, version: "1.0", isActive: true },
      { name: "XSStrike", status: "ready", successRate: 97, version: "3.1.5", isActive: true },
      { name: "Dalfox", status: "ready", successRate: 97, version: "2.9.1", isActive: true },
      { name: "XSS-Checker", status: "ready", successRate: 96, version: "1.0", isActive: true },
      { name: "xssFuzz", status: "ready", successRate: 95, version: "1.0", isActive: true },
      { name: "SQLMap", status: "ready", successRate: 99, version: "1.7.11", isActive: true },
      { name: "Ghauri", status: "ready", successRate: 96, version: "1.3.4", isActive: true },
      { name: "GraphQLmap", status: "ready", successRate: 94, version: "1.0", isActive: true },
      { name: "SQLiDetector", status: "ready", successRate: 93, version: "1.0", isActive: true },
      { name: "Nmap", status: "ready", successRate: 100, version: "7.94", isActive: true },
      { name: "Masscan", status: "ready", successRate: 100, version: "1.3.2", isActive: true },
      { name: "Metasploit", status: "ready", successRate: 94, version: "6.3.42", isActive: true },
      { name: "Advanced Web Scanner", status: "ready", successRate: 98, version: "3.0.0", isActive: true },
      { name: "AI Vulnerability Analyzer", status: "ready", successRate: 95, version: "3.0.0", isActive: true },
      { name: "Directory Fuzzer", status: "ready", successRate: 97, version: "3.0.0", isActive: true },
      { name: "Business Logic Analyzer", status: "ready", successRate: 92, version: "3.0.0", isActive: true },
      { name: "Template Injection Scanner", status: "ready", successRate: 94, version: "3.0.0", isActive: true },
      { name: "Prototype Pollution Scanner", status: "ready", successRate: 93, version: "3.0.0", isActive: true },
      { name: "Nuclei", status: "ready", successRate: 99, version: "3.1.0", isActive: true },
    ];

    defaultTools.forEach(tool => {
      const id = randomUUID();
      const toolStatus: ToolStatus = {
        ...tool,
        id,
        lastUsed: null,
        category: "general",
        reliability: 85,
        averageExecutionTime: 0,
        vulnerabilitiesFound: 0,
        totalScans: 0,
        configuration: {},
      };
      this.tools.set(tool.name, toolStatus);
    });
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.username === username);
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async getScan(id: string): Promise<Scan | undefined> {
    return this.scans.get(id);
  }

  async getScans(): Promise<Scan[]> {
    return Array.from(this.scans.values()).sort((a, b) => 
      new Date(b.startedAt!).getTime() - new Date(a.startedAt!).getTime()
    );
  }

  async getActiveScans(): Promise<Scan[]> {
    return Array.from(this.scans.values()).filter(scan => 
      scan.status === "running" || scan.status === "pending"
    );
  }

  async createScan(insertScan: InsertScan): Promise<Scan> {
    const id = randomUUID();
    const scan: Scan = {
      ...insertScan,
      id,
      status: "pending",
      progress: 0,
      startedAt: new Date(),
      completedAt: null,
      results: {},
      vulnerabilities: [],
      toolsUsed: [],
      successRate: 0,
      logs: [],
      riskScore: 0,
      riskLevel: "unknown",
      aiAnalysis: {},
      wordlistsUsed: [],
      executionTime: 0,
      criticalVulns: 0,
      highVulns: 0,
      mediumVulns: 0,
      lowVulns: 0,
    };
    this.scans.set(id, scan);
    return scan;
  }

  async updateScan(id: string, updates: Partial<Scan>): Promise<Scan | undefined> {
    const scan = this.scans.get(id);
    if (!scan) return undefined;
    
    const updatedScan = { ...scan, ...updates };
    this.scans.set(id, updatedScan);
    return updatedScan;
  }

  async getVulnerabilities(scanId?: string): Promise<Vulnerability[]> {
    const vulns = Array.from(this.vulnerabilities.values());
    return scanId ? vulns.filter(v => v.scanId === scanId) : vulns;
  }

  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const id = randomUUID();
    const vulnerability: Vulnerability = {
      ...insertVulnerability,
      id,
      discoveredAt: new Date(),
      evidence: insertVulnerability.evidence || {},
      recommendation: insertVulnerability.recommendation || null,
      cveId: insertVulnerability.cveId || null,
      exploitability: insertVulnerability.exploitability ?? 0,
      impact: insertVulnerability.impact ?? 0,
      remediation: insertVulnerability.remediation || null,
      references: insertVulnerability.references || [],
      toolUsed: insertVulnerability.toolUsed || "unknown",
      confidenceLevel: insertVulnerability.confidenceLevel ?? 50,
      verified: insertVulnerability.verified ?? false,
      falsePositive: insertVulnerability.falsePositive ?? false,
      tags: insertVulnerability.tags || [],
    };
    this.vulnerabilities.set(id, vulnerability);
    return vulnerability;
  }

  async getToolStatus(): Promise<ToolStatus[]> {
    return Array.from(this.tools.values());
  }

  async getToolByName(name: string): Promise<ToolStatus | undefined> {
    return this.tools.get(name);
  }

  async createOrUpdateToolStatus(toolData: InsertToolStatus): Promise<ToolStatus> {
    const existing = this.tools.get(toolData.name);
    if (existing) {
      const updated = { ...existing, ...toolData };
      this.tools.set(toolData.name, updated);
      return updated;
    } else {
      const id = randomUUID();
      const tool: ToolStatus = { 
        id,
        name: toolData.name,
        status: toolData.status || "ready",
        successRate: toolData.successRate ?? 100,
        version: toolData.version || null,
        lastUsed: toolData.lastUsed || null,
        category: toolData.category || "general",
        reliability: toolData.reliability ?? 85,
        averageExecutionTime: toolData.averageExecutionTime ?? 0,
        vulnerabilitiesFound: toolData.vulnerabilitiesFound ?? 0,
        totalScans: toolData.totalScans ?? 0,
        configuration: toolData.configuration || {},
        isActive: toolData.isActive ?? true
      };
      this.tools.set(toolData.name, tool);
      return tool;
    }
  }

  async updateToolStatus(name: string, updates: Partial<ToolStatus>): Promise<ToolStatus | undefined> {
    const tool = this.tools.get(name);
    if (!tool) return undefined;
    
    const updatedTool = { ...tool, ...updates };
    this.tools.set(name, updatedTool);
    return updatedTool;
  }
}

export const storage = new MemStorage();
