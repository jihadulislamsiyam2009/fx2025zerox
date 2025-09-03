import { useEffect, useRef, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Terminal } from "lucide-react";
import { useWebSocket } from "@/hooks/use-websocket";

interface LogEntry {
  timestamp: string;
  level: "INFO" | "DEBUG" | "SUCCESS" | "WARNING" | "ERROR" | "CRITICAL";
  message: string;
}

export default function TerminalOutput() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const { lastMessage } = useWebSocket();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (lastMessage) {
      try {
        const data = JSON.parse(lastMessage.data);
        if (data.type === "scan_progress" && data.logs) {
          // Convert logs to proper format
          const newLogs = data.logs.map((log: string) => {
            const match = log.match(/\[([^\]]+)\] (\w+): (.+)/);
            if (match) {
              return {
                timestamp: match[1],
                level: match[2] as LogEntry["level"],
                message: match[3]
              };
            }
            return {
              timestamp: new Date().toISOString(),
              level: "INFO" as const,
              message: log
            };
          });
          setLogs(newLogs);
        }
      } catch (error) {
        console.error("Failed to parse WebSocket message:", error);
      }
    }
  }, [lastMessage]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogColor = (level: LogEntry["level"]) => {
    switch (level) {
      case "SUCCESS": return "text-primary";
      case "ERROR": case "CRITICAL": return "text-destructive";
      case "WARNING": return "text-chart-2";
      case "INFO": return "text-accent";
      case "DEBUG": return "text-muted-foreground";
      default: return "text-foreground";
    }
  };

  const sampleLogs: LogEntry[] = [
    {
      timestamp: "2024-01-15 14:32:15",
      level: "INFO",
      message: "Starting subdomain enumeration for example.com"
    },
    {
      timestamp: "2024-01-15 14:32:16",
      level: "DEBUG",
      message: "Loading Sublist3r module..."
    },
    {
      timestamp: "2024-01-15 14:32:17",
      level: "SUCCESS",
      message: "Found subdomain: api.example.com"
    },
    {
      timestamp: "2024-01-15 14:32:18",
      level: "SUCCESS",
      message: "Found subdomain: mail.example.com"
    },
    {
      timestamp: "2024-01-15 14:32:19",
      level: "SUCCESS",
      message: "Found subdomain: dev.example.com"
    },
    {
      timestamp: "2024-01-15 14:32:20",
      level: "INFO",
      message: "Switching to Subfinder module..."
    },
    {
      timestamp: "2024-01-15 14:32:21",
      level: "WARNING",
      message: "Rate limit detected, implementing delay..."
    },
    {
      timestamp: "2024-01-15 14:32:25",
      level: "SUCCESS",
      message: "Found subdomain: staging.example.com"
    },
    {
      timestamp: "2024-01-15 14:32:26",
      level: "INFO",
      message: "Starting XSS testing on discovered subdomains..."
    },
    {
      timestamp: "2024-01-15 14:32:27",
      level: "DEBUG",
      message: "Loading XSStrike payload database..."
    },
    {
      timestamp: "2024-01-15 14:32:30",
      level: "CRITICAL",
      message: "XSS vulnerability detected on dev.example.com/search?q="
    },
    {
      timestamp: "2024-01-15 14:32:31",
      level: "INFO",
      message: "Beginning SQL injection testing..."
    },
    {
      timestamp: "2024-01-15 14:32:33",
      level: "SUCCESS",
      message: "SQLMap initialized for api.example.com"
    },
    {
      timestamp: "2024-01-15 14:32:35",
      level: "CRITICAL",
      message: "SQL injection vulnerability found in login form"
    },
  ];

  const displayLogs = logs.length > 0 ? logs : sampleLogs;

  return (
    <Card data-testid="terminal-output-card">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <Terminal className="w-5 h-5 text-primary" />
          Live Terminal Output
        </h3>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-primary rounded-full pulse-slow" />
          <span className="text-xs text-muted-foreground">Real-time</span>
        </div>
      </div>
      <CardContent className="p-4">
        <div 
          ref={scrollRef}
          className="bg-muted rounded-lg p-4 h-80 overflow-y-auto terminal-output"
          data-testid="terminal-logs"
        >
          <div className="space-y-1 text-sm">
            {displayLogs.map((log, index) => (
              <div key={index} className={getLogColor(log.level)}>
                [{log.timestamp}] {log.level}: {log.message}
              </div>
            ))}
            <div className="scanning-animation h-1 w-full bg-primary/20 rounded mt-2" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
