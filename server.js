// server.js — single App Service host for the AXA Cloud Budget Estimator.
//
// Serves the built SPA (app/dist) AND every existing Azure Functions handler
// under /api/*, using an adapter so the handler code is reused UNCHANGED.
// One process, one hostname, one private endpoint, no CORS.

const path = require("path");
const fs = require("fs");
const express = require("express");

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json({ limit: "2mb" }));

// ---------------------------------------------------------------------------
// Functions -> Express adapter
// Your handlers are `module.exports = async (context, req[, user]) => {}` and
// respond by setting `context.res = { status, headers, body }`. This wraps an
// Express (req,res) pair into that contract so no handler needs rewriting.
// ---------------------------------------------------------------------------
function adaptFunction(handler) {
  return async (req, res) => {
    const context = {
      log: Object.assign((...a) => console.log(...a), {
        error: (...a) => console.error(...a),
        warn: (...a) => console.warn(...a),
        info: (...a) => console.info(...a),
      }),
      res: undefined,
    };

    // Functions `req` shape: query/body/headers/params + method/url.
    const fnReq = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      query: req.query,
      params: req.params,
      body: req.body,
      rawBody: req.body ? JSON.stringify(req.body) : "",
      get: (h) => req.headers[String(h).toLowerCase()],
    };

    try {
      const returned = await handler(context, fnReq);
      // Handlers set context.res; some also return a response object.
      const r = context.res || returned || { status: 204 };
      const status = r.status || 200;
      if (r.headers) {
        for (const [k, v] of Object.entries(r.headers)) res.set(k, v);
      }
      if (r.body === undefined || r.body === null) return res.status(status).end();
      if (typeof r.body === "object" && !Buffer.isBuffer(r.body)) {
        return res.status(status).json(r.body);
      }
      return res.status(status).send(r.body);
    } catch (err) {
      console.error(`Handler error on ${req.method} ${req.originalUrl}:`, err);
      const status = err.status || 500;
      return res.status(status).json({ error: err.message || "Internal error" });
    }
  };
}

// ---------------------------------------------------------------------------
// Auto-discover and mount every function in ./api.
// Reads each function.json for its route + methods; falls back to the folder
// name and GET+POST if metadata is missing. Adding a new function later needs
// no change here.
// ---------------------------------------------------------------------------
const apiDir = path.join(__dirname, "api");
const mounted = [];

if (fs.existsSync(apiDir)) {
  for (const name of fs.readdirSync(apiDir)) {
    const dir = path.join(apiDir, name);
    const indexPath = path.join(dir, "index.js");
    if (!fs.statSync(dir).isDirectory() || !fs.existsSync(indexPath)) continue;

    let route = name;
    let methods = ["get", "post"];
    const fnJsonPath = path.join(dir, "function.json");
    if (fs.existsSync(fnJsonPath)) {
      try {
        const b = JSON.parse(fs.readFileSync(fnJsonPath, "utf8")).bindings || [];
        const trigger = b.find((x) => x.type === "httpTrigger") || {};
        if (trigger.route) route = trigger.route;
        if (Array.isArray(trigger.methods) && trigger.methods.length) methods = trigger.methods;
      } catch { /* fall back to defaults */ }
    }

    let handler;
    try {
      handler = require(indexPath);
    } catch (e) {
      console.error(`Failed to load api/${name}:`, e.message);
      continue;
    }

    const wrapped = adaptFunction(handler);
    for (const m of methods) {
      app[m.toLowerCase()](`/api/${route}`, wrapped);
    }
    mounted.push(`${methods.map((m) => m.toUpperCase()).join("/")} /api/${route}`);
  }
}

console.log(`Mounted ${mounted.length} API routes:\n  ` + mounted.join("\n  "));

// Health probe endpoint for App Service.
app.get("/healthz", (_req, res) => res.status(200).json({ ok: true, routes: mounted.length }));

// ---------------------------------------------------------------------------
// Static SPA + client-side routing fallback.
// ---------------------------------------------------------------------------
const distDir = path.join(__dirname, "dist");
app.use(express.static(distDir, { index: false, maxAge: "1h" }));

// Anything not /api and not a real file -> index.html (SPA routes).
app.get(/^(?!\/api\/).*/, (_req, res) => {
  res.sendFile(path.join(distDir, "index.html"));
});

app.listen(PORT, () => console.log(`Server listening on :${PORT}`));
