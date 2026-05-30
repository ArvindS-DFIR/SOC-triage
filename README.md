# SOC Triage AI

AI-powered security alert triage tool. Paste any alert — EDR, SIEM, cloud, logs — and get instant severity scoring, MITRE mapping, IOC extraction, and recommended actions.

---

## Run Locally (First Time Setup)

### Step 1 — Install Node.js
Download from https://nodejs.org and install. Choose the LTS version.

### Step 2 — Get your Anthropic API key
1. Go to https://console.anthropic.com
2. Sign up / log in
3. Click "API Keys" → "Create Key"
4. Copy the key

### Step 3 — Set up the backend
```bash
cd backend
cp .env.example .env
# Open .env and paste your API key where it says: your_api_key_here
npm install
npm start
```
You should see: `SOC Triage backend running on port 3001`

### Step 4 — Set up the frontend (new terminal window)
```bash
cd frontend
npm install
npm run dev
```
You should see: `Local: http://localhost:5173`

Open that URL in your browser. Done — it's running locally.

---

## Deploy to Vercel (Make it Live Online)

### Step 1 — Push to GitHub
1. Create a free account at https://github.com
2. Create a new repository called `soc-triage`
3. Upload this entire folder to it

### Step 2 — Deploy backend to Render (free)
1. Go to https://render.com — sign up free
2. Click "New Web Service" → connect your GitHub repo
3. Set root directory to `backend`
4. Build command: `npm install`
5. Start command: `npm start`
6. Add environment variable: `ANTHROPIC_API_KEY` = your key
7. Click Deploy — you'll get a URL like `https://soc-triage-api.onrender.com`

### Step 3 — Deploy frontend to Vercel
1. Go to https://vercel.com — sign up with GitHub
2. Click "New Project" → import your repo
3. Set root directory to `frontend`
4. Add environment variable: `VITE_API_URL` = your Render backend URL
5. Click Deploy — you'll get a live URL like `https://soc-triage.vercel.app`

---

## Project Structure

```
soc-triage/
├── frontend/        ← React app (Vite)
│   ├── src/
│   │   ├── main.jsx
│   │   └── App.jsx  ← Main UI
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
│
└── backend/         ← Node.js API server
    ├── server.js    ← Express server + Anthropic API call
    ├── .env.example ← Copy this to .env and add your key
    └── package.json
```

---

## Cost Estimate
- Vercel hosting: **Free**
- Render backend: **Free tier**
- Anthropic API: ~$0.003 per analysis (less than half a cent)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Free to use, modify, and distribute. Commercial use permitted.
Built and maintained by [Arvind S](https://www.linkedin.com/in/aravind-s-733494205).
