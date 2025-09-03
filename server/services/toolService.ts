import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

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
}

class ToolService {
  async runTool(toolName: string, target: string, scanType: string): Promise<ToolResult> {
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
      "Metasploit": "network_scan.py",
      "Directory Scanner": "directory_scan.py",
      "Dirb": "directory_scan.py",
      "Gobuster": "directory_scan.py",
      "Dirsearch": "directory_scan.py",
      "Parameter Fuzzer": "parameter_fuzzer.py",
      "Ffuf": "parameter_fuzzer.py",
      "Wfuzz": "parameter_fuzzer.py",
      "Param-miner": "parameter_fuzzer.py",
      "Port Scanner": "port_scanner.py",
      "Rustscan": "port_scanner.py",
      "Web Vulnerability Scanner": "web_vulnerability_scanner.py",
      "Nikto": "web_vulnerability_scanner.py",
      "Nuclei": "web_vulnerability_scanner.py",
      "Wapiti": "web_vulnerability_scanner.py"
    };

    const scriptName = toolMap[toolName];
    if (!scriptName) {
      return {
        success: false,
        vulnerabilities: [],
        rawOutput: "",
        error: `Unknown tool: ${toolName}`
      };
    }

    const scriptPath = path.join(toolsDir, scriptName);
    
    return new Promise((resolve) => {
      const pythonProcess = spawn("python3", [
        scriptPath,
        target
      ]);

      let stdout = "";
      let stderr = "";

      pythonProcess.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      pythonProcess.on("close", (code) => {
        if (code === 0) {
          try {
            const result = JSON.parse(stdout);
            resolve({
              success: true,
              vulnerabilities: result.vulnerabilities || [],
              rawOutput: stdout,
              error: undefined
            });
          } catch (error) {
            resolve({
              success: false,
              vulnerabilities: [],
              rawOutput: stdout,
              error: `Failed to parse tool output: ${error}`
            });
          }
        } else {
          resolve({
            success: false,
            vulnerabilities: [],
            rawOutput: stdout,
            error: stderr || `Tool exited with code ${code}`
          });
        }
      });

      // Timeout after 5 minutes
      setTimeout(() => {
        pythonProcess.kill("SIGTERM");
        resolve({
          success: false,
          vulnerabilities: [],
          rawOutput: stdout,
          error: "Tool execution timeout"
        });
      }, 300000);
    });
  }

  async testToolAvailability(toolName: string): Promise<boolean> {
    try {
      const result = await this.runTool(toolName, "example.com", "test");
      return result.success || result.error !== `Unknown tool: ${toolName}`;
    } catch {
      return false;
    }
  }
}

export const toolService = new ToolService();
