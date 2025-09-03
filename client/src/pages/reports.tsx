import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileText, Download, Eye, Calendar, AlertTriangle } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { Scan, Vulnerability } from "@shared/schema";

export default function Reports() {
  const { data: scans, isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
  });

  const { data: vulnerabilities, isLoading: vulnLoading } = useQuery<Vulnerability[]>({
    queryKey: ["/api/vulnerabilities"],
  });

  const completedScans = scans?.filter(scan => scan.status === "completed") || [];

  const formatDate = (date: Date | null) => {
    if (!date) return "N/A";
    return new Date(date).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  };

  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: "destructive",
      high: "destructive",
      medium: "secondary",
      low: "secondary"
    };
    return (
      <Badge variant={colors[severity as keyof typeof colors] as any}>
        {severity.toUpperCase()}
      </Badge>
    );
  };

  const getVulnerabilityCount = (scanId: string) => {
    return vulnerabilities?.filter(v => v.scanId === scanId).length || 0;
  };

  const getCriticalCount = (scanId: string) => {
    return vulnerabilities?.filter(v => v.scanId === scanId && v.severity === "critical").length || 0;
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-card border-b border-border px-6 py-4" data-testid="reports-header">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Security Reports</h1>
            <p className="text-sm text-muted-foreground">
              View and download comprehensive security assessment reports
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="flex items-center gap-2" data-testid="button-export-all">
              <Download className="w-4 h-4" />
              Export All
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="p-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card data-testid="stat-total-reports">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Reports</p>
                  <p className="text-3xl font-bold text-foreground">
                    {scansLoading ? "..." : completedScans.length}
                  </p>
                </div>
                <FileText className="w-8 h-8 text-primary" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-critical-findings">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Critical Findings</p>
                  <p className="text-3xl font-bold text-destructive">
                    {vulnLoading ? "..." : vulnerabilities?.filter(v => v.severity === "critical").length || 0}
                  </p>
                </div>
                <AlertTriangle className="w-8 h-8 text-destructive" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-this-month">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">This Month</p>
                  <p className="text-3xl font-bold text-foreground">
                    {scansLoading ? "..." : completedScans.filter(scan => {
                      const scanDate = new Date(scan.startedAt!);
                      const now = new Date();
                      return scanDate.getMonth() === now.getMonth() && scanDate.getFullYear() === now.getFullYear();
                    }).length}
                  </p>
                </div>
                <Calendar className="w-8 h-8 text-accent" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-avg-success-rate">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Avg Success Rate</p>
                  <p className="text-3xl font-bold text-primary">
                    {scansLoading ? "..." : `${Math.round(
                      completedScans.reduce((acc, scan) => acc + (scan.successRate || 0), 0) / 
                      (completedScans.length || 1)
                    )}%`}
                  </p>
                </div>
                <Eye className="w-8 h-8 text-primary" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Reports Table */}
        <Card data-testid="reports-table-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              Scan Reports
            </CardTitle>
          </CardHeader>
          <CardContent>
            {scansLoading ? (
              <div className="space-y-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-4">
                      <Skeleton className="w-8 h-8" />
                      <div className="space-y-2">
                        <Skeleton className="h-4 w-48" />
                        <Skeleton className="h-3 w-32" />
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Skeleton className="h-6 w-16" />
                      <Skeleton className="h-8 w-20" />
                    </div>
                  </div>
                ))}
              </div>
            ) : completedScans.length === 0 ? (
              <div className="text-center py-8" data-testid="no-reports">
                <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-sm text-muted-foreground">No completed scans available</p>
              </div>
            ) : (
              <div className="space-y-2">
                {completedScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                    data-testid={`report-item-${scan.id}`}
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-8 h-8 bg-primary/10 rounded-lg flex items-center justify-center">
                        <FileText className="w-4 h-4 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-medium text-foreground" data-testid={`report-target-${scan.id}`}>
                          {scan.target}
                        </h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span data-testid={`report-type-${scan.id}`}>
                            {scan.scanType.replace('_', ' ').toUpperCase()}
                          </span>
                          <span data-testid={`report-date-${scan.id}`}>
                            {formatDate(scan.completedAt)}
                          </span>
                          <span data-testid={`report-vuln-count-${scan.id}`}>
                            {getVulnerabilityCount(scan.id)} vulnerabilities
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {getCriticalCount(scan.id) > 0 && (
                        <div className="flex items-center gap-1">
                          <AlertTriangle className="w-4 h-4 text-destructive" />
                          <span className="text-sm font-medium text-destructive">
                            {getCriticalCount(scan.id)} Critical
                          </span>
                        </div>
                      )}
                      <Badge 
                        variant={scan.successRate && scan.successRate >= 90 ? "default" : "secondary"}
                        data-testid={`report-success-rate-${scan.id}`}
                      >
                        {scan.successRate}% Success
                      </Badge>
                      <div className="flex gap-2">
                        <Button 
                          size="sm" 
                          variant="outline"
                          className="flex items-center gap-1"
                          data-testid={`button-view-${scan.id}`}
                        >
                          <Eye className="w-3 h-3" />
                          View
                        </Button>
                        <Button 
                          size="sm"
                          className="flex items-center gap-1"
                          data-testid={`button-download-${scan.id}`}
                        >
                          <Download className="w-3 h-3" />
                          Download
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
