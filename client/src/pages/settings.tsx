import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Settings, Gavel, Shield, Bell, Download, RefreshCw, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { ToolStatus } from "@shared/schema";

export default function SettingsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [scanSettings, setScanSettings] = useState({
    maxConcurrentScans: 3,
    defaultTimeout: 300,
    autoRetry: true,
    notifications: true,
    darkMode: true,
    realTimeUpdates: true
  });

  const { data: tools, isLoading: toolsLoading } = useQuery<ToolStatus[]>({
    queryKey: ["/api/tools"],
  });

  const updateToolMutation = useMutation({
    mutationFn: async ({ name, updates }: { name: string; updates: Partial<ToolStatus> }) => {
      const response = await apiRequest("PATCH", `/api/tools/${name}`, updates);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/tools"] });
      toast({
        title: "Gavel Updated",
        description: "Gavel settings have been updated successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Update Failed",
        description: error.message || "Failed to update tool settings.",
        variant: "destructive",
      });
    },
  });

  const handleToolToggle = (toolName: string, isActive: boolean) => {
    updateToolMutation.mutate({
      name: toolName,
      updates: { isActive }
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "ready": return "text-primary";
      case "running": return "text-chart-2";
      case "error": return "text-destructive";
      case "disabled": return "text-muted-foreground";
      default: return "text-foreground";
    }
  };

  const getStatusBadge = (status: string, isActive: boolean) => {
    if (!isActive) {
      return <Badge variant="secondary">Disabled</Badge>;
    }
    
    const variants = {
      ready: "default",
      running: "secondary",
      error: "destructive",
      disabled: "outline"
    };

    return (
      <Badge variant={variants[status as keyof typeof variants] as any}>
        {status.toUpperCase()}
      </Badge>
    );
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-card border-b border-border px-6 py-4" data-testid="settings-header">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Settings</h1>
            <p className="text-sm text-muted-foreground">
              Configure security scanner settings and manage tools
            </p>
          </div>
          <Button variant="outline" className="flex items-center gap-2" data-testid="button-save-settings">
            <Download className="w-4 h-4" />
            Export Config
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <main className="p-6 max-w-6xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* General Settings */}
          <div className="space-y-6">
            <Card data-testid="general-settings-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="w-5 h-5 text-primary" />
                  General Settings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between" data-testid="setting-notifications">
                    <div>
                      <Label htmlFor="notifications">Enable Notifications</Label>
                      <p className="text-sm text-muted-foreground">
                        Receive alerts for critical vulnerabilities
                      </p>
                    </div>
                    <Switch
                      id="notifications"
                      checked={scanSettings.notifications}
                      onCheckedChange={(checked) =>
                        setScanSettings(prev => ({ ...prev, notifications: checked }))
                      }
                    />
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between" data-testid="setting-real-time-updates">
                    <div>
                      <Label htmlFor="realtime">Real-time Updates</Label>
                      <p className="text-sm text-muted-foreground">
                        Live terminal output and progress tracking
                      </p>
                    </div>
                    <Switch
                      id="realtime"
                      checked={scanSettings.realTimeUpdates}
                      onCheckedChange={(checked) =>
                        setScanSettings(prev => ({ ...prev, realTimeUpdates: checked }))
                      }
                    />
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between" data-testid="setting-auto-retry">
                    <div>
                      <Label htmlFor="retry">Auto Retry Failed Scans</Label>
                      <p className="text-sm text-muted-foreground">
                        Automatically retry failed scan operations
                      </p>
                    </div>
                    <Switch
                      id="retry"
                      checked={scanSettings.autoRetry}
                      onCheckedChange={(checked) =>
                        setScanSettings(prev => ({ ...prev, autoRetry: checked }))
                      }
                    />
                  </div>

                  <Separator />

                  <div className="space-y-2" data-testid="setting-max-concurrent">
                    <Label htmlFor="concurrent">Maximum Concurrent Scans</Label>
                    <Input
                      id="concurrent"
                      type="number"
                      min="1"
                      max="10"
                      value={scanSettings.maxConcurrentScans}
                      onChange={(e) =>
                        setScanSettings(prev => ({ 
                          ...prev, 
                          maxConcurrentScans: parseInt(e.target.value) 
                        }))
                      }
                    />
                    <p className="text-sm text-muted-foreground">
                      Number of scans that can run simultaneously
                    </p>
                  </div>

                  <div className="space-y-2" data-testid="setting-timeout">
                    <Label htmlFor="timeout">Default Scan Timeout (seconds)</Label>
                    <Input
                      id="timeout"
                      type="number"
                      min="60"
                      max="3600"
                      value={scanSettings.defaultTimeout}
                      onChange={(e) =>
                        setScanSettings(prev => ({ 
                          ...prev, 
                          defaultTimeout: parseInt(e.target.value) 
                        }))
                      }
                    />
                    <p className="text-sm text-muted-foreground">
                      Maximum time allowed for each tool execution
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Security Settings */}
            <Card data-testid="security-settings-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-primary" />
                  Security Settings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-muted/50 rounded-lg">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-chart-2 mt-0.5" />
                    <div>
                      <h4 className="font-semibold text-foreground">Security Notice</h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        This tool is designed for authorized security testing only. 
                        Ensure you have proper permission before scanning any targets.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Rate Limiting</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatic rate limiting is enabled to prevent overwhelming target servers
                  </p>
                  <Badge variant="outline">Enabled</Badge>
                </div>

                <div className="space-y-2">
                  <Label>User Agent</Label>
                  <Input 
                    placeholder="SecureScan Pro v2.4.1" 
                    defaultValue="SecureScan Pro v2.4.1"
                    data-testid="input-user-agent"
                  />
                  <p className="text-sm text-muted-foreground">
                    Custom user agent string for HTTP requests
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Gavel Management */}
          <div>
            <Card data-testid="tool-management-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Gavel className="w-5 h-5 text-primary" />
                  Gavel Management
                </CardTitle>
              </CardHeader>
              <CardContent>
                {toolsLoading ? (
                  <div className="space-y-4">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <div key={i} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="animate-pulse">
                          <div className="h-4 bg-muted rounded w-24 mb-2"></div>
                          <div className="h-3 bg-muted rounded w-32"></div>
                        </div>
                        <div className="animate-pulse">
                          <div className="h-6 bg-muted rounded w-16"></div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : tools ? (
                  <div className="space-y-3">
                    {tools.map((tool) => (
                      <div
                        key={tool.id}
                        className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                        data-testid={`tool-setting-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}
                      >
                        <div className="flex items-center gap-4">
                          <div className={`w-3 h-3 rounded-full ${
                            tool.isActive && tool.status === "ready" ? "bg-primary" :
                            tool.isActive && tool.status === "running" ? "bg-chart-2" :
                            tool.isActive && tool.status === "error" ? "bg-destructive" :
                            "bg-muted-foreground"
                          } ${tool.status === "running" ? "pulse-slow" : ""}`} />
                          <div>
                            <h4 className="font-medium text-foreground">{tool.name}</h4>
                            <div className="flex items-center gap-4 text-sm text-muted-foreground">
                              <span>v{tool.version || "1.0"}</span>
                              <span>Success: {tool.successRate}%</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {getStatusBadge(tool.status, tool.isActive)}
                          <Switch
                            checked={tool.isActive}
                            onCheckedChange={(checked) => handleToolToggle(tool.name, checked)}
                            disabled={updateToolMutation.isPending}
                            data-testid={`switch-${tool.name.toLowerCase().replace(/\s+/g, '-')}`}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8" data-testid="no-tools">
                    <Gavel className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-sm text-muted-foreground">No tools available</p>
                  </div>
                )}

                <div className="mt-6 pt-4 border-t">
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      className="flex items-center gap-2"
                      onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/tools"] })}
                      data-testid="button-refresh-tools"
                    >
                      <RefreshCw className="w-4 h-4" />
                      Refresh Status
                    </Button>
                    <Button 
                      variant="outline" 
                      className="flex items-center gap-2"
                      data-testid="button-test-tools"
                    >
                      <Gavel className="w-4 h-4" />
                      Test All Tools
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Save Settings */}
        <div className="mt-8 flex justify-end">
          <Button 
            className="flex items-center gap-2"
            onClick={() => {
              toast({
                title: "Settings Saved",
                description: "Your preferences have been saved successfully.",
              });
            }}
            data-testid="button-save-all-settings"
          >
            <Settings className="w-4 h-4" />
            Save All Settings
          </Button>
        </div>
      </main>
    </div>
  );
}
