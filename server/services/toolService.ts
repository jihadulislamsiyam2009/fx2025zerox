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
      "Nuclei": "advanced_web_scanner.py",
      "Wapiti": "web_vulnerability_scanner.py",
      "Advanced Web Scanner": "advanced_web_scanner.py",
      "AI Vulnerability Analyzer": "ai_vulnerability_analyzer.py",
      "Directory Fuzzer": "advanced_web_scanner.py",
      "Business Logic Analyzer": "ai_vulnerability_analyzer.py",
      "Template Injection Scanner": "ai_vulnerability_analyzer.py",
      "Prototype Pollution Scanner": "ai_vulnerability_analyzer.py"
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
      // Determine tool arguments based on tool name
      const toolArgs = this.getToolArguments(toolName, target, scanType);
      
      const pythonProcess = spawn("python3", [
        scriptPath,
        ...toolArgs
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

  private getToolArguments(toolName: string, target: string, scanType: string): string[] {
    const baseArgs = ["--target", target, "--scan-type", scanType];
    
    // Map tool names to their specific arguments
    const toolArgMap: { [key: string]: string[] } = {
      "Sublist3r": ["--tool", "sublist3r"],
      "Subfinder": ["--tool", "subfinder"],
      "Sudomy": ["--tool", "sudomy"],
      "Dome": ["--tool", "dome"],
      "XSStrike": ["--tool", "xsstrike"],
      "Dalfox": ["--tool", "dalfox"],
      "XSS-Checker": ["--tool", "xss-checker"],
      "xssFuzz": ["--tool", "xssfuzz"],
      "SQLMap": ["--tool", "sqlmap"],
      "Ghauri": ["--tool", "ghauri"],
      "GraphQLmap": ["--tool", "graphqlmap"],
      "SQLiDetector": ["--tool", "sqlidetector"],
      "Advanced Web Scanner": ["--tool", "comprehensive"],
      "AI Vulnerability Analyzer": ["--tool", "comprehensive"],
      "Directory Fuzzer": ["--tool", "directory"],
      "Business Logic Analyzer": ["--tool", "business_logic"],
      "Template Injection Scanner": ["--tool", "advanced_injection"],
      "Prototype Pollution Scanner": ["--tool", "advanced_injection"],
      "Nuclei": ["--tool", "nuclei"]
    };
    
    const specificArgs = toolArgMap[toolName] || ["--tool", toolName.toLowerCase()];
    return [...baseArgs, ...specificArgs];
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
