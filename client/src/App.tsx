import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Dashboard from "@/pages/dashboard";
import NewScan from "@/pages/new-scan";
import Reports from "@/pages/reports";
import ScanHistory from "@/pages/scan-history";
import Settings from "@/pages/settings";
import Sidebar from "@/components/sidebar";

function Router() {
  return (
    <div className="min-h-screen bg-background cyber-grid">
      <Sidebar />
      <div className="ml-0 md:ml-64">
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/new-scan" component={NewScan} />
          <Route path="/reports" component={Reports} />
          <Route path="/history" component={ScanHistory} />
          <Route path="/settings" component={Settings} />
          <Route component={Dashboard} />
        </Switch>
      </div>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
