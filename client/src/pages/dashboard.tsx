import { useQuery } from "@tanstack/react-query";
import { Play, Clock, Activity, AlertTriangle, CheckCircle, Target, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import ScanCard from "@/components/scan-card";
import TerminalOutput from "@/components/terminal-output";
import VulnerabilitySummary from "@/components/vulnerability-summary";
import ToolStatusGrid from "@/components/tool-status-grid";
import { useWebSocket } from "@/hooks/use-websocket";
import { useLocation } from "wouter";

export default function Dashboard() {
  const [, setLocation] = useLocation();
  const { lastMessage } = useWebSocket();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["/api/stats"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: activeScans, isLoading: scansLoading } = useQuery({
    queryKey: ["/api/scans/active"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  const quickActions = [
    {
      title: "Subdomain Scan",
      description: "Enumerate subdomains",
      icon: Shield,
      color: "primary",
      scanType: "subdomain"
    },
    {
      title: "XSS Hunter",
      description: "Cross-site scripting test",
      icon: Activity,
      color: "chart-2",
      scanType: "xss"
    },
    {
      title: "SQL Injection",
      description: "Database vulnerability test",
      icon: AlertTriangle,
      color: "destructive",
      scanType: "sql_injection"
    },
    {
      title: "Port Scan",
      description: "Network port discovery",
      icon: Target,
      color: "accent",
      scanType: "network"
    },
  ];

  const handleQuickScan = (scanType: string) => {
    setLocation(`/new-scan?type=${scanType}`);
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-card border-b border-border px-6 py-4" data-testid="dashboard-header">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Security Scanner Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Automated penetration testing and vulnerability assessment
            </p>
          </div>
          <div className="flex items-center gap-4">
            <Button 
              onClick={() => setLocation("/new-scan")}
              className="flex items-center gap-2"
              data-testid="button-start-new-scan"
            >
              <Play className="w-4 h-4" />
              Start New Scan
            </Button>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="w-4 h-4" />
              <span data-testid="text-last-scan-time">Last scan: 2h ago</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="p-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" data-testid="stats-overview">
          <Card className="glow-green">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Active Scans</p>
                  <p className="text-3xl font-bold text-primary" data-testid="stat-active-scans">
                    {statsLoading ? "..." : (stats as any)?.activeScans || 0}
                  </p>
                </div>
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                  <Activity className="w-6 h-6 text-primary" />
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-2">Real-time monitoring</p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Vulnerabilities Found</p>
                  <p className="text-3xl font-bold text-destructive" data-testid="stat-vulnerabilities">
                    {statsLoading ? "..." : (stats as any)?.totalVulnerabilities || 0}
                  </p>
                </div>
                <div className="w-12 h-12 bg-destructive/10 rounded-lg flex items-center justify-center">
                  <AlertTriangle className="w-6 h-6 text-destructive" />
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-2">Across all scans</p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Success Rate</p>
                  <p className="text-3xl font-bold text-primary" data-testid="stat-success-rate">
                    {statsLoading ? "..." : `${(stats as any)?.successRate || 100}%`}
                  </p>
                </div>
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-primary" />
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-2">All tools operational</p>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Targets Scanned</p>
                  <p className="text-3xl font-bold text-foreground" data-testid="stat-targets-scanned">
                    {statsLoading ? "..." : (stats as any)?.targetsScanned || 0}
                  </p>
                </div>
                <div className="w-12 h-12 bg-accent/10 rounded-lg flex items-center justify-center">
                  <Target className="w-6 h-6 text-accent" />
                </div>
              </div>
              <p className="text-xs text-muted-foreground mt-2">This month</p>
            </CardContent>
          </Card>
        </div>

        {/* Active Scans and Quick Actions */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Active Scans */}
          <div className="lg:col-span-2">
            <ScanCard scans={(activeScans as any) || []} isLoading={scansLoading} />
          </div>

          {/* Quick Actions */}
          <Card data-testid="quick-actions-card">
            <div className="p-6 border-b border-border">
              <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Target className="w-5 h-5 text-chart-2" />
                Quick Actions
              </h3>
            </div>
            <CardContent className="p-6">
              <div className="space-y-3">
                {quickActions.map((action) => {
                  const Icon = action.icon;
                  return (
                    <Button
                      key={action.scanType}
                      variant="ghost"
                      className={`w-full p-3 bg-${action.color}/10 border border-${action.color}/20 hover:bg-${action.color}/20 justify-start h-auto`}
                      onClick={() => handleQuickScan(action.scanType)}
                      data-testid={`quick-action-${action.scanType}`}
                    >
                      <div className="flex items-center gap-3">
                        <Icon className={`w-5 h-5 text-${action.color}`} />
                        <div className="text-left">
                          <p className="font-medium text-foreground">{action.title}</p>
                          <p className="text-xs text-muted-foreground">{action.description}</p>
                        </div>
                      </div>
                    </Button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Terminal Output and Vulnerability Summary */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <TerminalOutput />
          <VulnerabilitySummary vulnerabilities={(stats as any)?.vulnerabilityCounts} />
        </div>

        {/* Tool Status Grid */}
        <ToolStatusGrid />
      </main>
    </div>
  );
}
