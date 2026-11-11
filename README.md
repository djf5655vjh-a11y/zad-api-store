# ZAD OSINT - API Selling Platform
Credit: POKA BROTHER

## Run locally
    pip install -r requirements.txt
    ADMIN_USER=admin ADMIN_PASS=YourStrongPass python app.py

## Deploy on Render FREE plan
Free Render has no disk (files vanish on restart), so keep data in a free Postgres (Neon):
1. neon.tech -> create project -> copy the connection string (postgresql://...).
2. Upload all these files (flat, no folders) to GitHub -> Render -> New -> Blueprint (render.yaml, plan: free).
3. In Render > Environment set: ADMIN_PASS (your admin password) and DATABASE_URL (Neon string).
   ADMIN_USER is MAFIA. Admin login is re-applied from these variables on every boot.
4. Keep it awake: free UptimeRobot monitor on https://YOUR-SITE.onrender.com/health every 5 min
   (also ping https://famsytem.onrender.com/ if the gateway is on Render free too).
Without DATABASE_URL the app falls back to SQLite (fine locally, NOT persistent on free Render).

## Payment flow
Buy -> UPI QR (exact price, valid 15 min) -> page polls /order-status every 4s -> server asks your verify API
-> paid => key activated, saved in My APIs + order history. UTR box is only a fallback.
Unpaid users see all APIs as Locked; the gateway rejects keys that do not exist.

## Payment verify
Edit `verify_payment_remote()` in app.py if your verify-payment API uses
different request / response field names. Default: POST JSON {utr, amount, upi_id}.

## How buyers use an API
GET https://YOUR-SITE/g/<slug>?key=<api_key>&<your params>
The real API URL stays hidden; expired keys are blocked automatically.
