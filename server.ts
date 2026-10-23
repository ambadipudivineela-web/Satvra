import express from 'express';
import http from 'http';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import JSZip from 'jszip';
import { createServer as createViteServer } from 'vite';
import { ThreatEvaluationService } from './src/core/threatIntel/threatService.ts';
import { searchOfficialSources } from './src/core/officialSources/matcher.ts';
import { OFFICIAL_SOURCES_DIRECTORY } from './src/core/officialSources/directory.ts';
import { runAllTests } from './src/core/testSuite.ts';

import { WebSearchService } from './src/core/search/searchService.ts';

dotenv.config();

const PORT = 3000;
const app = express();

app.use(express.json());

// Initialize core threat evaluation service & search service
const threatService = new ThreatEvaluationService(process.env.WEB_RISK_API_KEY);
const searchService = new WebSearchService(threatService);

// 0. Web Search Endpoint (Handles natural language queries, returns verified real results)
app.get('/api/search', async (req, res) => {
  try {
    const query = typeof req.query.q === 'string' ? req.query.q : '';
    if (!query.trim()) {
      res.json({
        query: '',
        provider: 'DuckDuckGo Web Index',
        totalResults: 0,
        officialCount: 0,
        threatCount: 0,
        results: [],
        latencyMs: 0,
      });
      return;
    }

    const searchResults = await searchService.search(query);
    res.json(searchResults);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error)?.message || 'Web search failed' });
  }
});

// 1. Threat Intel Check Endpoint
app.post('/api/threat-intel/check', async (req, res) => {
  try {
    const { url, forceRefresh } = req.body;
    if (!url) {
      res.status(400).json({ error: 'Missing required field: url' });
      return;
    }

    if (forceRefresh) {
      threatService.clearCache();
    }

    const evaluation = await threatService.evaluateUrl(url);
    res.json(evaluation);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error)?.message || 'Internal evaluation error' });
  }
});

// 2. Clear Cache Endpoint
app.post('/api/threat-intel/clear-cache', (_req, res) => {
  threatService.clearCache();
  res.json({ success: true, message: 'Local cache cleared' });
});

// 3. Provider Status Endpoint
app.get('/api/threat-intel/status', (_req, res) => {
  res.json({
    activeProvider: threatService.getSettings().activeProvider,
    cacheEntriesCount: threatService.getCacheSize(),
    hasWebRiskKey: threatService.hasValidWebRiskKey(),
    settings: threatService.getSettings(),
  });
});

// 4. Update Settings Endpoint
app.post('/api/threat-intel/settings', (req, res) => {
  threatService.updateSettings(req.body);
  res.json({ success: true, settings: threatService.getSettings() });
});

// 5. Official Sources Search & Directory Endpoint
app.get('/api/official-sources', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q : '';
  if (!query.trim()) {
    res.json({
      query: '',
      totalResults: OFFICIAL_SOURCES_DIRECTORY.length,
      matches: OFFICIAL_SOURCES_DIRECTORY.map((record) => ({
        record,
        score: 100,
        matchReason: 'Audited directory listing',
      })),
    });
    return;
  }

  const searchResults = searchOfficialSources(query);
  res.json(searchResults);
});

// 6. Download Chrome Extension Package (.zip)
app.get('/api/extension/download', async (_req, res) => {
  try {
    const zip = new JSZip();
    const extDir = path.resolve('extension');

    const files = fs.readdirSync(extDir);
    for (const file of files) {
      const filePath = path.join(extDir, file);
      const stat = fs.statSync(filePath);
      if (stat.isFile()) {
        const content = fs.readFileSync(filePath);
        zip.file(file, content);
      }
    }

    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="satvra-extension-mv3.zip"');
    res.send(zipBuffer);
  } catch (err: unknown) {
    res.status(500).json({ error: `Failed to create ZIP package: ${(err as Error)?.message}` });
  }
});

// 7. Run Test Suite In-Process
app.post('/api/tests/run', async (_req, res) => {
  try {
    const results = await runAllTests();
    res.json(results);
  } catch (err: unknown) {
    res.status(500).json({ error: (err as Error)?.message });
  }
});

// Mount Vite in development mode
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';
  const httpServer = http.createServer(app);

  if (!isProduction) {
    const isBehindHttps = Boolean(process.env.APP_URL?.startsWith('https'));

    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: {
          server: httpServer,
          ...(isBehindHttps ? { clientPort: 443 } : {}),
        },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve('dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve('dist/index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[SATVRA] Server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();
