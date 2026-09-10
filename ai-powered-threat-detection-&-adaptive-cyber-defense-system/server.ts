import express from 'express';
import path from 'path';
import fs from 'fs';
import { createServer as createViteServer } from 'vite';
import { dbStore } from './src/database/store';
import { MODEL_BENCHMARKS, DISSERTATION_EXPERIMENTS } from './src/lib/mlEngine';
import { SAMPLE_CSV_CONTENT } from './src/lib/sampleDatasets';
import { NetworkTelemetry, AlertStatus, RiskLevel, ThreatClass } from './src/types';

async function startServer() {
  const app = express();
  const PORT = 3000;

  // JSON and URL-encoded body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logger
  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
      console.log(`[API ${req.method}] ${req.path}`);
    }
    next();
  });

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'online',
      system: 'AI-Powered Threat Detection & Adaptive Cyber Defense System',
      version: '1.4.0-hons',
      engine: 'Random Forest Multi-Tree Bagging + Risk Scorer',
      timestamp: new Date().toISOString(),
    });
  });

  // 1. Dashboard telemetry metrics
  app.get('/api/dashboard', (req, res) => {
    try {
      const metrics = dbStore.getDashboardMetrics();
      res.json(metrics);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 2. Single event manual analysis
  app.post('/api/analyze', (req, res) => {
    try {
      const telemetry: NetworkTelemetry = req.body.telemetry || req.body;

      // Basic input validation
      if (!telemetry.sourceIp || !telemetry.destinationIp) {
        return res.status(400).json({ error: 'Missing required fields: sourceIp and destinationIp' });
      }

      const analyzedBy = req.body.analyzedBy || 'Analyst (Manual Entry)';
      const analyzedEvent = dbStore.analyzeAndStoreEvent(telemetry, analyzedBy);
      res.status(201).json(analyzedEvent);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 3. Batch CSV upload analysis
  app.post('/api/analyze/csv', (req, res) => {
    try {
      const csvText = req.body.csv;
      if (!csvText || typeof csvText !== 'string') {
        return res.status(400).json({ error: 'Expected raw CSV string in { csv: "..." } body' });
      }

      const lines = csvText.trim().split('\n');
      if (lines.length < 2) {
        return res.status(400).json({ error: 'CSV must contain a header row and at least one data row' });
      }

      const headers = lines[0].split(',').map((h) => h.trim());
      const analyzedResults = [];

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        const values = line.split(',').map((v) => v.trim());
        const row: Record<string, string> = {};
        headers.forEach((h, idx) => {
          row[h] = values[idx] || '';
        });

        // Map CSV fields to NetworkTelemetry
        const telemetry: NetworkTelemetry = {
          timestamp: row.timestamp || new Date().toISOString(),
          sourceIp: row.sourceIp || `192.168.1.${10 + i}`,
          destinationIp: row.destinationIp || '10.0.2.15',
          sourcePort: Number(row.sourcePort) || 45000 + i,
          destinationPort: Number(row.destinationPort) || 80,
          protocol: (row.protocol as any) || 'TCP',
          duration: Number(row.duration) || 1.0,
          srcBytes: Number(row.srcBytes) || 500,
          dstBytes: Number(row.dstBytes) || 1000,
          packetCount: Number(row.packetCount) || 30,
          failedLoginAttempts: Number(row.failedLoginAttempts) || 0,
          requestFrequency: Number(row.requestFrequency) || 10,
          connectionState: (row.connectionState as any) || 'SF',
          service: (row.service as any) || 'http',
          sameSrvRate: Number(row.sameSrvRate) || 1.0,
          diffSrvRate: Number(row.diffSrvRate) || 0.0,
          dstHostCount: Number(row.dstHostCount) || 50,
          dstHostSrvCount: Number(row.dstHostSrvCount) || 50,
        };

        const result = dbStore.analyzeAndStoreEvent(telemetry, 'Batch CSV Ingestion');
        analyzedResults.push(result);
      }

      res.json({
        totalProcessed: analyzedResults.length,
        events: analyzedResults,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 4. Query security events with filters & pagination
  app.get('/api/events', (req, res) => {
    try {
      const {
        page,
        limit,
        severity,
        threatType,
        sourceIp,
        riskMin,
        riskMax,
        hasAlertOnly,
      } = req.query;

      const data = dbStore.getEvents({
        page: page ? parseInt(page as string, 10) : 1,
        limit: limit ? parseInt(limit as string, 10) : 15,
        severity: severity as RiskLevel,
        threatType: threatType as ThreatClass,
        sourceIp: sourceIp as string,
        riskMin: riskMin ? parseInt(riskMin as string, 10) : undefined,
        riskMax: riskMax ? parseInt(riskMax as string, 10) : undefined,
        hasAlertOnly: hasAlertOnly === 'true',
      });

      res.json(data);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 5. Get single event by ID
  app.get('/api/events/:id', (req, res) => {
    const event = dbStore.getEventById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  });

  // 6. Query alerts
  app.get('/api/alerts', (req, res) => {
    try {
      const { status, severity } = req.query;
      const alerts = dbStore.getAlerts({
        status: status as AlertStatus,
        severity: severity as RiskLevel,
      });
      res.json(alerts);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 7. Get single alert
  app.get('/api/alerts/:id', (req, res) => {
    const alert = dbStore.getAlertById(req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    res.json(alert);
  });

  // 8. Update alert status (PATCH)
  app.patch('/api/alerts/:id', (req, res) => {
    try {
      const { status, analystNotes, assignedTo } = req.body;
      if (!status) return res.status(400).json({ error: 'status field is required' });

      const updated = dbStore.updateAlertStatus(req.params.id, status as AlertStatus, analystNotes, assignedTo);
      if (!updated) return res.status(404).json({ error: 'Alert not found' });
      res.json(updated);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 9. Model benchmark evaluation metrics
  app.get('/api/model/metrics', (req, res) => {
    res.json({
      primaryModel: 'Random Forest Ensemble (100 Trees)',
      dataset: 'NSL-KDD (Full Benchmark & Test21)',
      benchmarks: MODEL_BENCHMARKS,
    });
  });

  // 10. Research dissertation experiments 1 - 7
  app.get('/api/experiments', (req, res) => {
    res.json({
      title: 'Hons CS Dissertation Experiments & Comparative Benchmarks',
      researchQuestion: 'Can machine-learning-based risk scoring improve cybersecurity threat detection and adaptive response compared with conventional rule-based detection?',
      experiments: DISSERTATION_EXPERIMENTS,
    });
  });

  // 11. Simulated active defense responses
  app.get('/api/responses', (req, res) => {
    res.json(dbStore.getAdaptiveResponses());
  });

  // 12. Revoke simulated defense action
  app.post('/api/responses/:id/revoke', (req, res) => {
    const success = dbStore.revokeResponse(req.params.id);
    if (!success) return res.status(404).json({ error: 'Response not found' });
    res.json({ success: true, message: 'Simulated defense action revoked.' });
  });

  // 13. Download sample test CSV
  app.get('/api/sample-csv', (req, res) => {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="nsl_kdd_sample_telemetry.csv"');
    res.send(SAMPLE_CSV_CONTENT);
  });

  // 14. Authentication endpoints (Analyst / Admin)
  app.post('/api/auth/login', (req, res) => {
    const { username } = req.body;
    const users = dbStore.getUsers();
    const user = users.find((u) => u.username === username) || users[0];
    res.json({
      token: `jwt-simulated-token-${user.id}-${Date.now()}`,
      user,
    });
  });

  app.get('/api/auth/me', (req, res) => {
    const users = dbStore.getUsers();
    res.json(users[0]);
  });

  // 15. Serve academic dissertation docs statically & API
  const docsDir = path.join(process.cwd(), 'docs');
  app.use('/docs', express.static(docsDir));

  app.get('/api/docs/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(docsDir, filename);
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'text/markdown; charset=UTF-8');
      res.sendFile(filePath);
    } else {
      res.status(404).json({ error: 'Documentation file not found' });
    }
  });

  // Vite development or production static files setup
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Cyber Defense SOC Server] Running on http://localhost:${PORT}`);
  });
}

startServer();
