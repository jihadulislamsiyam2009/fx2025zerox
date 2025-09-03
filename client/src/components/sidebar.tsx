import { Link, useLocation } from "wouter";
import { Shield, Activity, Target, FileText, Database, Settings, Globe, Code, Database as DB, Wifi, Search } from "lucide-react";
import { cn } from "@/lib/utils";

export default function Sidebar() {
  const [location] = useLocation();

  const navItems = [
    { href: "/", icon: Activity, label: "Dashboard", active: location === "/" },
    { href: "/new-scan", icon: Target, label: "New Scan", active: location === "/new-scan" },
    { href: "/reports", icon: FileText, label: "Reports", active: location === "/reports" },
    { href: "/history", icon: Database, label: "Scan History", active: location === "/history" },
    { href: "/settings", icon: Settings, label: "Settings", active: location === "/settings" },
  ];

  const scanModules = [
    { icon: Globe, label: "Subdomain Enum", color: "bg-primary", status: "pulse-slow" },
    { icon: Code, label: "XSS Detection", color: "bg-chart-2" },
    { icon: DB, label: "SQL Injection", color: "bg-destructive" },
    { icon: Wifi, label: "Network Scan", color: "bg-accent" },
    { icon: Search, label: "OSINT Gathering", color: "bg-chart-5" },
  ];

  return (
    <div className="fixed inset-y-0 left-0 z-50 w-64 bg-card border-r border-border">
      <div className="flex flex-col h-full">
        {/* Logo Section */}
        <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
          <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-foreground">SecureScan Pro</h1>
            <p className="text-xs text-muted-foreground">v2.4.1</p>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="flex-1 px-4 py-6">
          <div className="space-y-2" data-testid="main-navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link key={item.href} href={item.href}>
                  <a
                    className={cn(
                      "flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                      item.active
                        ? "text-primary bg-primary/10 border border-primary/20"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                    )}
                    data-testid={`nav-${item.label.toLowerCase().replace(' ', '-')}`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </a>
                </Link>
              );
            })}
          </div>

          {/* Tool Categories */}
          <div className="mt-8">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">
              Scan Modules
            </h3>
            <div className="space-y-1" data-testid="scan-modules">
              {scanModules.map((module) => {
                const Icon = module.icon;
                return (
                  <div key={module.label} className="flex items-center gap-3 px-3 py-2 text-sm">
                    <div className={cn("w-2 h-2 rounded-full", module.color, module.status)} />
                    <span className="text-muted-foreground">{module.label}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </nav>

        {/* Status Footer */}
        <div className="px-4 py-3 border-t border-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground" data-testid="system-status">
            <div className="w-2 h-2 bg-primary rounded-full pulse-slow" />
            <span>System Online</span>
          </div>
        </div>
      </div>
    </div>
  );
}
