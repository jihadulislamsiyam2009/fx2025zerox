import { Card, CardContent } from "@/components/ui/card";
import { Activity } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { Scan } from "@shared/schema";

interface ScanCardProps {
  scans: Scan[];
  isLoading: boolean;
}

export default function ScanCard({ scans, isLoading }: ScanCardProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case "running": return "bg-primary";
      case "completed": return "bg-chart-2";
      case "failed": return "bg-destructive";
      case "pending": return "bg-accent";
      default: return "bg-muted";
    }
  };

  const formatTimeRemaining = (progress: number) => {
    if (progress >= 100) return "Completed";
    if (progress === 0) return "Starting...";
    
    // Estimate remaining time based on progress
    const estimatedTotal = 30; // minutes
    const remaining = Math.round(estimatedTotal * (1 - progress / 100));
    return `~${remaining}m remaining`;
  };

  return (
    <Card data-testid="active-scans-card">
      <div className="p-6 border-b border-border">
        <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" />
          Active Scans
        </h3>
      </div>
      <CardContent className="p-6">
        {isLoading ? (
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center justify-between p-4 bg-secondary rounded-lg">
                <div className="flex items-center gap-4">
                  <Skeleton className="w-3 h-3 rounded-full" />
                  <div className="space-y-2">
                    <Skeleton className="h-4 w-32" />
                    <Skeleton className="h-3 w-24" />
                  </div>
                </div>
                <div className="space-y-2">
                  <Skeleton className="h-4 w-12" />
                  <Skeleton className="h-3 w-20" />
                </div>
              </div>
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="text-center py-8" data-testid="no-active-scans">
            <Activity className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-sm text-muted-foreground">No active scans running</p>
          </div>
        ) : (
          <div className="space-y-4">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-4 bg-secondary rounded-lg border border-border"
                data-testid={`scan-item-${scan.id}`}
              >
                <div className="flex items-center gap-4">
                  <div className={`w-3 h-3 rounded-full pulse-slow ${getStatusColor(scan.status)}`} />
                  <div>
                    <p className="font-medium text-foreground" data-testid={`scan-target-${scan.id}`}>
                      {scan.target}
                    </p>
                    <p className="text-sm text-muted-foreground" data-testid={`scan-type-${scan.id}`}>
                      {scan.scanType.replace('_', ' ').toUpperCase()}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-foreground" data-testid={`scan-progress-${scan.id}`}>
                    {scan.progress || 0}%
                  </p>
                  <p className="text-xs text-muted-foreground" data-testid={`scan-eta-${scan.id}`}>
                    {formatTimeRemaining(scan.progress || 0)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
