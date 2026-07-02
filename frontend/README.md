# SecureOrch Dashboard

React + Vite frontend for SecureOrch — uploads a security log, streams live
per-agent pipeline progress over SSE, and renders incidents, a risk chart, and
one-click PDF/HTML/JSON report downloads.

## Develop

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # production build → dist/
npm run lint     # oxlint
```

The API base URL defaults to `http://localhost:8000` and can be overridden with
the `VITE_API_BASE` environment variable. Start the backend first (see the
[project README](../README.md)).

## Layout

- `src/App.jsx` — upload flow + dashboard composition
- `src/api/client.js` — upload, SSE pipeline stream, report download
- `src/components/` — `PipelineStatus`, `IncidentsTable`, `RiskChart`
