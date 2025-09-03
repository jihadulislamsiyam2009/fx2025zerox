import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { ArrowLeft, Target, Play } from "lucide-react";
import { useLocation, useRoute } from "wouter";
import { insertScanSchema } from "@shared/schema";

const formSchema = insertScanSchema.extend({
  target: z.string().min(1, "Target is required").url("Must be a valid URL or domain")
});

export default function NewScan() {
  const [, setLocation] = useLocation();
  const [, params] = useRoute("/new-scan");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      target: "",
      scanType: (params as any)?.type || "full_audit",
    },
  });

  const startScanMutation = useMutation({
    mutationFn: async (data: z.infer<typeof formSchema>) => {
      const response = await apiRequest("POST", "/api/scans", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      toast({
        title: "Scan Started",
        description: "Your security scan has been initiated successfully.",
      });
      setLocation("/");
    },
    onError: (error) => {
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to start the scan. Please try again.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: z.infer<typeof formSchema>) => {
    startScanMutation.mutate(data);
  };

  const scanTypes = [
    { value: "subdomain", label: "Subdomain Enumeration", description: "Discover subdomains and expand attack surface" },
    { value: "xss", label: "XSS Vulnerability Scan", description: "Detect cross-site scripting vulnerabilities" },
    { value: "sql_injection", label: "SQL Injection Test", description: "Test for database injection flaws" },
    { value: "network", label: "Network Reconnaissance", description: "Port scanning and service discovery" },
    { value: "osint", label: "OSINT Gathering", description: "Open source intelligence collection" },
    { value: "full_audit", label: "Full Security Audit", description: "Comprehensive security assessment" },
  ];

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-card border-b border-border px-6 py-4" data-testid="new-scan-header">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            onClick={() => setLocation("/")}
            className="flex items-center gap-2"
            data-testid="button-back"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Start New Security Scan</h1>
            <p className="text-sm text-muted-foreground">
              Configure and launch automated penetration testing
            </p>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="p-6 max-w-4xl mx-auto">
        <Card data-testid="new-scan-form-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="w-5 h-5 text-primary" />
              Scan Configuration
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                  control={form.control}
                  name="target"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Target URL/Domain</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="https://example.com or example.com"
                          {...field}
                          data-testid="input-target"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="scanType"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Scan Type</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value} data-testid="select-scan-type">
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select scan type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {scanTypes.map((type) => (
                            <SelectItem key={type.value} value={type.value}>
                              <div>
                                <div className="font-medium">{type.label}</div>
                                <div className="text-xs text-muted-foreground">{type.description}</div>
                              </div>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Scan Type Details */}
                <Card className="bg-muted/50">
                  <CardContent className="p-4">
                    <h3 className="font-semibold mb-2">Selected Scan Details</h3>
                    {(() => {
                      const selectedType = scanTypes.find(type => type.value === form.watch("scanType"));
                      return selectedType ? (
                        <div>
                          <p className="text-sm text-muted-foreground mb-2">{selectedType.description}</p>
                          <div className="text-xs text-muted-foreground">
                            <p><strong>Tools used:</strong> {getToolsForScanType(selectedType.value).join(", ")}</p>
                            <p><strong>Estimated time:</strong> {getEstimatedTime(selectedType.value)}</p>
                          </div>
                        </div>
                      ) : null;
                    })()}
                  </CardContent>
                </Card>

                <div className="flex gap-4 pt-4">
                  <Button
                    type="submit"
                    disabled={startScanMutation.isPending}
                    className="flex items-center gap-2"
                    data-testid="button-start-scan"
                  >
                    <Play className="w-4 h-4" />
                    {startScanMutation.isPending ? "Starting Scan..." : "Start Scan"}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setLocation("/")}
                    data-testid="button-cancel"
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            </Form>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

function getToolsForScanType(scanType: string): string[] {
  const toolMap: { [key: string]: string[] } = {
    "subdomain": ["Sublist3r", "Subfinder", "Sudomy", "Dome"],
    "xss": ["XSStrike", "Dalfox", "XSS-Checker", "xssFuzz"],
    "sql_injection": ["SQLMap", "Ghauri", "GraphQLmap", "SQLiDetector"],
    "network": ["Nmap", "Masscan"],
    "osint": ["Sublist3r", "Subfinder", "Sudomy"],
    "full_audit": ["All available tools"],
  };
  return toolMap[scanType] || [];
}

function getEstimatedTime(scanType: string): string {
  const timeMap: { [key: string]: string } = {
    "subdomain": "5-15 minutes",
    "xss": "10-30 minutes",
    "sql_injection": "15-45 minutes",
    "network": "5-20 minutes",
    "osint": "10-25 minutes",
    "full_audit": "30-90 minutes",
  };
  return timeMap[scanType] || "Unknown";
}
