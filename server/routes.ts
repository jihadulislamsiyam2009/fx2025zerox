import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { scanService } from "./services/scanService";
import { insertScanSchema } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  
  // WebSocket server for real-time updates
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });
  
  wss.on('connection', (ws: WebSocket) => {
    console.log('WebSocket client connected');
    scanService.addWebSocketClient(ws);
    
    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message.toString());
        
        if (data.type === 'get_active_scans') {
          const progress = await scanService.getActiveScanProgress();
          ws.send(JSON.stringify({
            type: 'active_scans_update',
            data: progress
          }));
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });
  });

  // Get dashboard stats
  app.get("/api/stats", async (req, res) => {
    try {
      const activeScans = await storage.getActiveScans();
      const allVulnerabilities = await storage.getVulnerabilities();
      const allScans = await storage.getScans();
      
      const vulnerabilityCounts = {
        critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
        high: allVulnerabilities.filter(v => v.severity === 'high').length,
        medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
        low: allVulnerabilities.filter(v => v.severity === 'low').length,
      };

      const successRate = allScans.length > 0 
        ? Math.round(allScans.reduce((acc, scan) => acc + (scan.successRate || 0), 0) / allScans.length)
        : 100;

      res.json({
        activeScans: activeScans.length,
        totalVulnerabilities: allVulnerabilities.length,
        successRate,
        targetsScanned: allScans.length,
        vulnerabilityCounts
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  // Get all scans
  app.get("/api/scans", async (req, res) => {
    try {
      const scans = await storage.getScans();
      res.json(scans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scans" });
    }
  });

  // Get active scans
  app.get("/api/scans/active", async (req, res) => {
    try {
      const activeScans = await storage.getActiveScans();
      res.json(activeScans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch active scans" });
    }
  });

  // Create new scan
  app.post("/api/scans", async (req, res) => {
    try {
      const scanData = insertScanSchema.parse(req.body);
      const scan = await scanService.startScan(scanData);
      res.json(scan);
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({ error: "Invalid scan data", details: error.errors });
      } else {
        res.status(500).json({ error: "Failed to create scan" });
      }
    }
  });

  // Get scan by ID
  app.get("/api/scans/:id", async (req, res) => {
    try {
      const scan = await storage.getScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }
      res.json(scan);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scan" });
    }
  });

  // Stop scan
  app.post("/api/scans/:id/stop", async (req, res) => {
    try {
      const success = await scanService.stopScan(req.params.id);
      if (!success) {
        return res.status(404).json({ error: "Scan not found or already stopped" });
      }
      res.json({ message: "Scan stopped successfully" });
    } catch (error) {
      res.status(500).json({ error: "Failed to stop scan" });
    }
  });

  // Get vulnerabilities
  app.get("/api/vulnerabilities", async (req, res) => {
    try {
      const scanId = req.query.scanId as string;
      const vulnerabilities = await storage.getVulnerabilities(scanId);
      res.json(vulnerabilities);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch vulnerabilities" });
    }
  });

  // Get tool status
  app.get("/api/tools", async (req, res) => {
    try {
      const tools = await storage.getToolStatus();
      res.json(tools);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch tool status" });
    }
  });

  // Update tool status
  app.patch("/api/tools/:name", async (req, res) => {
    try {
      const updates = req.body;
      const tool = await storage.updateToolStatus(req.params.name, updates);
      if (!tool) {
        return res.status(404).json({ error: "Tool not found" });
      }
      res.json(tool);
    } catch (error) {
      res.status(500).json({ error: "Failed to update tool status" });
    }
  });

  return httpServer;
}
