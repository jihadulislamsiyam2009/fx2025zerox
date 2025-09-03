import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { writeFile, readFile } from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const toolsDir = path.join(__dirname, "../../tools");

export interface ToolResult {
  success: boolean;
  vulnerabilities: Array<{
    type: string;
    severity: "critical" | "high" | "medium" | "low";
    title: string;
    description: string;
    target: string;
    evidence: any;
    recommendation?: string;
  }>;
  rawOutput: string;
  error?: string;
  metadata?: {
    toolName: string;
    executionTime: number;
    targetUrl: string;
    scanType: string;
  };
}

export class ToolRunner {
  private static instance: ToolRunner;
  private activeProcesses: Map<string, any> = new Map();

  static getInstance(): ToolRunner {
    if (!ToolRunner.instance) {
      ToolRunner.instance = new ToolRunner();
    }
    return ToolRunner.instance;
  }

  async runTool(
    toolName: string,
    target: string,
    scanType: string,
    options: { timeout?: number; args?: string[] } = {}
  ): Promise<ToolResult> {
    const startTime = Date.now();
    const { timeout = 300000, args = [] } = options; // 5 minute default timeout

    const toolMap: { [key: string]: string } = {
      "Sublist3r": "subdomain_enum.py",
      "Subfinder": "subdomain_enum.py",
      "Sudomy": "subdomain_enum.py",
      "Dome": "subdomain_enum.py",
      "XSStrike": "xss_scanner.py",
      "Dalfox": "xss_scanner.py",
      "XSS-Checker": "xss_scanner.py",
      "xssFuzz": "xss_scanner.py",
      "SQLMap": "sql_injection.py",
      "Ghauri": "sql_injection.py",
      "GraphQLmap": "sql_injection.py",
      "SQLiDetector": "sql_injection.py",
      "Nmap": "network_scan.py",
      "Masscan": "network_scan.py",
      "Metasploit": "network_scan.py"
    };

    const scriptName = toolMap[toolName];
    if (!scriptName) {
      return {
        success: false,
        vulnerabilities: [],
        rawOutput: "",
        error: `Unknown tool: ${toolName}`,
        metadata: {
          toolName,
          executionTime: Date.now() - startTime,
          targetUrl: target,
          scanType
        }
      };
    }

    const scriptPath = path.join(toolsDir, scriptName);
    const processId = `${toolName}-${target}-${Date.now()}`;

    return new Promise((resolve) => {
      const pythonProcess = spawn("python3", [
        scriptPath,
        "--tool", toolName.toLowerCase(),
        "--target", target,
        "--scan-type", scanType,
        ...args
      ], {
        env: { 
          ...process.env,
          PYTHONPATH: toolsDir,
          TOOL_TIMEOUT: timeout.toString()
        }
      });

      this.activeProcesses.set(processId, pythonProcess);

      let stdout = "";
      let stderr = "";

      pythonProcess.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      pythonProcess.on("close", (code) => {
        this.activeProcesses.delete(processId);
        const executionTime = Date.now() - startTime;

        if (code === 0) {
          try {
            const result = JSON.parse(stdout);
            resolve({
              success: true,
              vulnerabilities: result.vulnerabilities || [],
              rawOutput: stdout,
              metadata: {
                toolName,
                executionTime,
                targetUrl: target,
                scanType
              }
            });
          } catch (error) {
            resolve({
              success: false,
              vulnerabilities: [],
              rawOutput: stdout,
              error: `Failed to parse tool output: ${error}`,
              metadata: {
                toolName,
                executionTime,
                targetUrl: target,
                scanType
              }
            });
          }
        } else {
          resolve({
            success: false,
            vulnerabilities: [],
            rawOutput: stdout,
            error: stderr || `Tool exited with code ${code}`,
            metadata: {
              toolName,
              executionTime,
              targetUrl: target,
              scanType
            }
          });
        }
      });

      pythonProcess.on("error", (error) => {
        this.activeProcesses.delete(processId);
        resolve({
          success: false,
          vulnerabilities: [],
          rawOutput: stdout,
          error: `Process error: ${error.message}`,
          metadata: {
            toolName,
            executionTime: Date.now() - startTime,
            targetUrl: target,
            scanType
          }
        });
      });

      // Timeout handling
      const timeoutId = setTimeout(() => {
        if (this.activeProcesses.has(processId)) {
          pythonProcess.kill("SIGTERM");
          setTimeout(() => {
            if (this.activeProcesses.has(processId)) {
              pythonProcess.kill("SIGKILL");
            }
          }, 5000);
        }
      }, timeout);

      pythonProcess.on("close", () => {
        clearTimeout(timeoutId);
      });
    });
  }

  async killProcess(processId: string): Promise<boolean> {
    const process = this.activeProcesses.get(processId);
    if (process) {
      process.kill("SIGTERM");
      this.activeProcesses.delete(processId);
      return true;
    }
    return false;
  }

  getActiveProcesses(): string[] {
    return Array.from(this.activeProcesses.keys());
  }
}

export const toolRunner = ToolRunner.getInstance();
