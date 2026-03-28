# Security Platform Dashboard

Minimal React dashboard for the security platform.

## Setup

1. Copy env template:
   - `cp .env.example .env`
2. Fill values in `.env`:
   - `VITE_API_BASE_URL`
   - `VITE_COGNITO_USER_POOL_ID`
   - `VITE_COGNITO_CLIENT_ID`
3. Install and run:
   - `npm install`
   - `npm run dev`

## Features

- Cognito login (username/password)
- View scans with filters
- Open report via pre-signed S3 URL
- View registered pentest targets
- Add new pentest target
- Trigger manual pentest scan
