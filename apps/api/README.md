# SiteShield API

Express server that runs scans for the website and handles domain ownership verification.
The scanning itself lives in `packages/core`; this app queues jobs, stores results in
SQLite and streams progress.

```bash
npm run dev:api          # from the repo root, http://127.0.0.1:4000
npm test -w @siteshield/api
```

Needs Node 22.13 or newer (it uses the built in `node:sqlite`). Settings are in `.env.example`.

## Endpoints

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/health` | Liveness check. |
| POST | `/api/scans` | Body `{ "url": "example.com", "active": false }`. Queues a scan, returns `202` with its `id`. |
| GET | `/api/scans/:id` | Status, grade and the full report once done. |
| GET | `/api/scans/:id/events` | Server sent events: `status`, `check:start`, `check:done`, then `done` or `failed`. |
| POST | `/api/verifications` | Body `{ "domain": "example.com" }`. Returns the token to publish and a private `key`, shown once. |
| GET | `/api/verifications/:id` | Needs the `X-Ownership-Key` header. |
| POST | `/api/verifications/:id/check` | Needs the key. Looks for the token in DNS or at `/.well-known/siteshield.txt`. |

Active scans (`"active": true`) are refused with `403` unless the request carries the
`X-Ownership-Key` of a verified, unexpired claim on that domain.

## Safety decisions

- **SSRF.** Targets are validated in `packages/core/src/target.ts`, and every outgoing
  connection re-checks the resolved IP, so redirects and DNS rebinding cannot reach
  localhost, private ranges or cloud metadata (169.254.169.254).
- **Ownership key.** The DNS token is public, so it cannot be what grants access. The
  separate key is returned once and only its SHA-256 hash is stored.
- **No listing.** There is no endpoint that lists scans. A scan id is a random UUID, so you
  can only read reports you started.
- **Rate limits.** 10 scans per client per 10 minutes, 30 verification calls, 300 requests
  overall per 15 minutes. Set `TRUST_PROXY` correctly when deployed behind a proxy.
- **Its own headers.** helmet is on, so the API passes the HDR001 check it runs on others.
