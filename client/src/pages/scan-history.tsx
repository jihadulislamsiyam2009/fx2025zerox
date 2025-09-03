import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Database, Play, StopCircle, RotateCcw, Eye, Trash2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { Scan } from "@shared/schema";

export default function ScanHistory() {
  const { data: scans, isLoading } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
  });

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

  const formatDuration = (start: Date | null, end: Date | null) => {
    if (!start) return "N/A";
    if (!end) return "Running...";
    
    const diff = new Date(end).getTime() - new Date(start).getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    }
    return `${seconds}s`;
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      running: "default",
      completed: "secondary", 
      failed: "destructive",
      stopped: "outline",
      pending: "secondary"
    };
    
    const colors = {
      running: "text-primary",
      completed: "text-green-500",
      failed: "text-destructive", 
      stopped: "text-muted-foreground",
      pending: "text-chart-2"
    };

    return (
      <Badge variant={variants[status as keyof typeof variants] as any}>
        <div className={`w-2 h-2 rounded-full mr-1 ${colors[status as keyof typeof colors]}`} />
        {status.toUpperCase()}
      </Badge>
    );
  };

  const getStatusActions = (scan: Scan) => {
    if (scan.status === "running" || scan.status === "pending") {
      return (
        <Button size="sm" variant="destructive" data-testid={`button-stop-${scan.id}`}>
          <StopCircle className="w-3 h-3 mr-1" />
          Stop
        </Button>
      );
    }
    
    return (
      <div className="flex gap-2">
        <Button size="sm" variant="outline" data-testid={`button-view-${scan.id}`}>
          <Eye className="w-3 h-3 mr-1" />
          View
        </Button>
        <Button size="sm" variant="outline" data-testid={`button-retry-${scan.id}`}>
          <RotateCcw className="w-3 h-3 mr-1" />
          Retry
        </Button>
      </div>
    );
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-card border-b border-border px-6 py-4" data-testid="scan-history-header">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Scan History</h1>
            <p className="text-sm text-muted-foreground">
              View all previous and active security scans
            </p>
          </div>
          <Button className="flex items-center gap-2" data-testid="button-new-scan">
            <Play className="w-4 h-4" />
            New Scan
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <main className="p-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card data-testid="stat-total-scans">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Total Scans</p>
                  <p className="text-3xl font-bold text-foreground">
                    {isLoading ? "..." : scans?.length || 0}
                  </p>
                </div>
                <Database className="w-8 h-8 text-primary" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-active-scans">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Active Scans</p>
                  <p className="text-3xl font-bold text-chart-2">
                    {isLoading ? "..." : scans?.filter(s => s.status === "running" || s.status === "pending").length || 0}
                  </p>
                </div>
                <Play className="w-8 h-8 text-chart-2" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-completed-scans">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Completed</p>
                  <p className="text-3xl font-bold text-green-500">
                    {isLoading ? "..." : scans?.filter(s => s.status === "completed").length || 0}
                  </p>
                </div>
                <Database className="w-8 h-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card data-testid="stat-failed-scans">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Failed</p>
                  <p className="text-3xl font-bold text-destructive">
                    {isLoading ? "..." : scans?.filter(s => s.status === "failed").length || 0}
                  </p>
                </div>
                <StopCircle className="w-8 h-8 text-destructive" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Scan History Table */}
        <Card data-testid="scan-history-table-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" />
              All Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-4">
                      <Skeleton className="w-8 h-8 rounded" />
                      <div className="space-y-2">
                        <Skeleton className="h-4 w-48" />
                        <Skeleton className="h-3 w-32" />
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <Skeleton className="h-6 w-20" />
                      <Skeleton className="h-4 w-16" />
                      <Skeleton className="h-8 w-24" />
                    </div>
                  </div>
                ))}
              </div>
            ) : !scans || scans.length === 0 ? (
              <div className="text-center py-8" data-testid="no-scans">
                <Database className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-sm text-muted-foreground">No scans found</p>
              </div>
            ) : (
              <div className="space-y-2">
                {scans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                    data-testid={`scan-history-item-${scan.id}`}
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-8 h-8 bg-primary/10 rounded-lg flex items-center justify-center">
                        <Database className="w-4 h-4 text-primary" />
                      </div>
                      <div>
                        <h3 className="font-medium text-foreground" data-testid={`scan-target-${scan.id}`}>
                          {scan.target}
                        </h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span data-testid={`scan-type-${scan.id}`}>
                            {scan.scanType.replace('_', ' ').toUpperCase()}
                          </span>
                          <span data-testid={`scan-started-${scan.id}`}>
                            Started: {formatDate(scan.startedAt)}
                          </span>
                          <span data-testid={`scan-duration-${scan.id}`}>
                            Duration: {formatDuration(scan.startedAt, scan.completedAt)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className="text-sm font-medium" data-testid={`scan-progress-${scan.id}`}>
                          {scan.progress || 0}%
                        </div>
                        {scan.successRate !== null && (
                          <div className="text-xs text-muted-foreground" data-testid={`scan-success-rate-${scan.id}`}>
                            {scan.successRate}% success
                          </div>
                        )}
                      </div>
                      <div data-testid={`scan-status-${scan.id}`}>
                        {getStatusBadge(scan.status)}
                      </div>
                      <div data-testid={`scan-actions-${scan.id}`}>
                        {getStatusActions(scan)}
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
