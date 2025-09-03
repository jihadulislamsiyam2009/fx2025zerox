import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Wrench } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { ToolStatus } from "@shared/schema";

export default function ToolStatusGrid() {
  const { data: tools, isLoading } = useQuery<ToolStatus[]>({
    queryKey: ["/api/tools"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "running": return "bg-chart-2";
      case "ready": return "bg-primary";
      case "error": return "bg-destructive";
      case "disabled": return "bg-muted";
      default: return "bg-primary";
    }
  };

  const formatLastUsed = (lastUsed: Date | null) => {
    if (!lastUsed) return "Never";
    
    const now = new Date();
    const diff = now.getTime() - new Date(lastUsed).getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    
    if (minutes < 1) return "Active";
    if (minutes < 60) return `${minutes}m ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  return (
    <div className="mt-8">
      <h3 className="text-xl font-semibold text-foreground mb-4 flex items-center gap-2">
        <Wrench className="w-5 h-5 text-primary" />
        Security Tool Status
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4" data-testid="tool-status-grid">
        {isLoading ? (
          // Skeleton loader
          Array.from({ length: 8 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <Skeleton className="h-4 w-20" />
                  <Skeleton className="w-2 h-2 rounded-full" />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <Skeleton className="h-3 w-12" />
                    <Skeleton className="h-3 w-16" />
                  </div>
                  <div className="flex justify-between">
                    <Skeleton className="h-3 w-20" />
                    <Skeleton className="h-3 w-12" />
                  </div>
                  <div className="flex justify-between">
                    <Skeleton className="h-3 w-16" />
                    <Skeleton className="h-3 w-14" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : tools ? (
          tools.map((tool) => (
            <Card key={tool.id} data-testid={`tool-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-medium text-foreground" data-testid={`tool-name-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}>
                    {tool.name}
                  </h4>
                  <div className={`w-2 h-2 rounded-full ${getStatusColor(tool.status)} ${
                    tool.status === "running" ? "pulse-slow" : ""
                  }`} />
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Status:</span>
                    <span 
                      className={`font-medium ${
                        tool.status === "running" ? "text-chart-2" :
                        tool.status === "ready" ? "text-primary" :
                        tool.status === "error" ? "text-destructive" :
                        "text-muted-foreground"
                      }`}
                      data-testid={`tool-status-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}
                    >
                      {tool.status.charAt(0).toUpperCase() + tool.status.slice(1)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Success Rate:</span>
                    <span className="text-foreground" data-testid={`tool-success-rate-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}>
                      {tool.successRate}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Last Used:</span>
                    <span className="text-foreground" data-testid={`tool-last-used-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}>
                      {formatLastUsed(tool.lastUsed)}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          <div className="col-span-full text-center py-8">
            <p className="text-muted-foreground">Failed to load tool status</p>
          </div>
        )}
      </div>
    </div>
  );
}
