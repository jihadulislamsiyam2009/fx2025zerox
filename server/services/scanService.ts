import { storage } from "../storage";
import { toolService } from "./toolService";
import { WebSocket } from "ws";
import type { InsertScan, Scan } from "@shared/schema";

export interface ScanProgress {
  scanId: string;
  progress: number;
  status: string;
  currentTool: string;
  logs: string[];
  vulnerabilities: any[];
}

class ScanService {
  private activeScans: Map<string, NodeJS.Timeout> = new Map();
  private wsClients: Set<WebSocket> = new Set();

  addWebSocketClient(ws: WebSocket) {
    this.wsClients.add(ws);
    ws.on('close', () => {
      this.wsClients.delete(ws);
    });
  }

  broadcast(message: any) {
    const data = JSON.stringify(message);
    this.wsClients.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });
  }

  async startScan(scanData: InsertScan): Promise<Scan> {
    const scan = await storage.createScan(scanData);
    
    // Start the scanning process
    this.executeScan(scan);
    
    return scan;
  }

  private async executeScan(scan: Scan) {
    try {
      await storage.updateScan(scan.id, { status: "running" });
      this.broadcast({ type: "scan_started", scanId: scan.id, scan });

      const tools = this.getToolsForScanType(scan.scanType);
      const totalSteps = tools.length;
      let currentStep = 0;
      const logs: string[] = [];
      const vulnerabilities: any[] = [];
      let successfulTools = 0;

      for (const toolName of tools) {
        await storage.updateToolStatus(toolName, { 
          status: "running", 
          lastUsed: new Date() 
        });

        this.broadcast({
          type: "scan_progress",
          scanId: scan.id,
          progress: Math.round((currentStep / totalSteps) * 100),
          currentTool: toolName,
          logs: logs.slice(-10) // Send last 10 logs
        });

        const logEntry = `[${new Date().toISOString()}] INFO: Starting ${toolName} scan for ${scan.target}`;
        logs.push(logEntry);

        try {
          const result = await toolService.runTool(toolName, scan.target, scan.scanType);
          
          if (result.success) {
            successfulTools++;
            vulnerabilities.push(...result.vulnerabilities);
            
            const successLog = `[${new Date().toISOString()}] SUCCESS: ${toolName} completed successfully`;
            logs.push(successLog);

            // Store vulnerabilities in database
            for (const vuln of result.vulnerabilities) {
              await storage.createVulnerability({
                scanId: scan.id,
                ...vuln
              });
            }
          } else {
            const errorLog = `[${new Date().toISOString()}] ERROR: ${toolName} failed - ${result.error}`;
            logs.push(errorLog);
          }

          await storage.updateToolStatus(toolName, { 
            status: "ready",
            successRate: result.success ? 
              Math.min(100, (await storage.getToolByName(toolName))?.successRate || 0 + 1) :
              Math.max(0, (await storage.getToolByName(toolName))?.successRate || 0 - 1)
          });

        } catch (error) {
          const errorLog = `[${new Date().toISOString()}] CRITICAL: ${toolName} crashed - ${error}`;
          logs.push(errorLog);
          
          await storage.updateToolStatus(toolName, { status: "error" });
        }

        currentStep++;
        
        // Simulate realistic scanning delays
        await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 3000));
      }

      const successRate = Math.round((successfulTools / totalSteps) * 100);
      const finalScan = await storage.updateScan(scan.id, {
        status: "completed",
        progress: 100,
        completedAt: new Date(),
        results: { totalVulnerabilities: vulnerabilities.length },
        vulnerabilities,
        toolsUsed: tools,
        successRate,
        logs
      });

      this.broadcast({
        type: "scan_completed",
        scanId: scan.id,
        scan: finalScan
      });

    } catch (error) {
      const errorLog = `[${new Date().toISOString()}] CRITICAL: Scan failed - ${error}`;
      await storage.updateScan(scan.id, {
        status: "failed",
        logs: [...(scan.logs as string[] || []), errorLog]
      });

      this.broadcast({
        type: "scan_failed",
        scanId: scan.id,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  private getToolsForScanType(scanType: string): string[] {
    const toolMap: { [key: string]: string[] } = {
      "subdomain": ["Sublist3r", "Subfinder", "Sudomy", "Dome"],
      "xss": ["XSStrike", "Dalfox", "XSS-Checker", "xssFuzz"],
      "sql_injection": ["SQLMap", "Ghauri", "GraphQLmap", "SQLiDetector"],
      "network": ["Nmap", "Masscan", "Port Scanner"],
      "directory": ["Directory Scanner", "Dirb", "Gobuster", "Dirsearch"],
      "parameters": ["Parameter Fuzzer", "Ffuf", "Wfuzz", "Param-miner"],
      "web_vuln": ["Web Vulnerability Scanner", "Nikto", "Nuclei", "Wapiti"],
      "full_audit": [
        "Sublist3r", "XSStrike", "SQLMap", "Nmap", "OSINT Gatherer",
        "Directory Scanner", "Parameter Fuzzer", "Port Scanner", "Web Vulnerability Scanner"
      ],
      "osint": ["Sublist3r", "Subfinder", "Sudomy", "OSINT Gatherer"]
    };

    return toolMap[scanType] || toolMap["full_audit"];
  }

  async stopScan(scanId: string): Promise<boolean> {
    const timeout = this.activeScans.get(scanId);
    if (timeout) {
      clearTimeout(timeout);
      this.activeScans.delete(scanId);
      
      await storage.updateScan(scanId, { 
        status: "stopped",
        completedAt: new Date()
      });
      
      this.broadcast({
        type: "scan_stopped",
        scanId
      });
      
      return true;
    }
    return false;
  }

  async getActiveScanProgress(): Promise<ScanProgress[]> {
    const activeScans = await storage.getActiveScans();
    return activeScans.map(scan => ({
      scanId: scan.id,
      progress: scan.progress || 0,
      status: scan.status,
      currentTool: "Scanning...",
      logs: scan.logs as string[] || [],
      vulnerabilities: scan.vulnerabilities as any[] || []
    }));
  }
}

export const scanService = new ScanService();
