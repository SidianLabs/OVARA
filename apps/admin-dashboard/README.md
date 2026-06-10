# Ovara Admin Dashboard

Next.js admin dashboard for the Ovara Runtime Trust Infrastructure control plane.

## Pages
- **Dashboard** — Overview metrics, trust score charts, recent decisions
- **Gateways** — Register and manage runtime gateway instances
- **Policies** — Create, edit, simulate, and manage policy rules
- **Audit Log** — Search and export cryptographic decision receipts
- **Organizations** — Manage federated organizations and trust relationships
- **Settings** — Configure API, security, and alerting preferences

## Setup

```bash
cd apps/admin-dashboard
npm install
npm run dev
```

## Build

```bash
npm run build
npm run start
```

## Tech Stack
- Next.js 14 (App Router)
- React 18
- TypeScript
- Tailwind CSS (dark theme)
- Lucide React icons
- Recharts (charts)
