# 🚀 Hosting & Deployment Guide — SIH Diode Defense

This guide covers 4 ways to host and deploy the **SIH 26145 AI-Based Diode Defense Prototype**:

---

## 1. Cloud PaaS Deployment (Recommended Free / Low-Cost Setup)

### **A. Database: MongoDB Atlas (Free Cloud Database)**
1. Create a free cluster at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2. Go to **Network Access** → Add IP `0.0.0.0/0` (allow all connections for demo).
3. Create a Database User and copy your connection string:
   `mongodb+srv://<username>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority`

### **B. Backend: Render / Railway / DigitalOcean**
1. Push your repository to GitHub.
2. Sign up on [Render.com](https://render.com) or [Railway.app](https://railway.app).
3. Create a **New Web Service** pointing to the `backend/` directory:
   * **Environment**: Python 3.11
   * **Build Command**: `pip install -r requirements.txt scapy`
   * **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Set Environment Variables:
   * `MONGODB_URI`: `mongodb+srv://<user>:<password>@cluster0.mongodb.net/...`
   * `MONGODB_DB_NAME`: `sih_diode_defense`
   * `CORS_ORIGINS`: `https://your-frontend.vercel.app`

### **C. Frontend: Vercel (Free Next.js Hosting)**
1. Sign up on [Vercel](https://vercel.com).
2. Import your GitHub repository.
3. Set Root Directory to `frontend`.
4. Add Environment Variable:
   * `NEXT_PUBLIC_API_URL`: `https://your-backend.onrender.com`
5. Click **Deploy**.

---

## 2. One-Command Docker Deployment (VPS / Self-Hosted Server)

If you have an AWS EC2, DigitalOcean Droplet, Linode, or local Linux server:

1. Clone the repository onto the server:
   ```bash
   git clone <your-repo-url>
   cd sih-diode-defense-main
   ```

2. Run Docker Compose:
   ```bash
   docker-compose up -d --build
   ```

3. Services will start automatically:
   * **Frontend**: `http://<YOUR_SERVER_IP>:3000`
   * **Backend API**: `http://<YOUR_SERVER_IP>:8000`
   * **MongoDB**: `localhost:27017`

---

## 3. Instant Public URL for Demo Evaluation (Ngrok / Cloudflare Tunnel)

If you want to host locally on your machine and give judges or external users immediate access:

### **Using Cloudflare Tunnel (Free & Unlimited)**
```bash
# Install cloudflared
cloudflared tunnel --url http://localhost:3000
```
* You will get a public HTTPS URL like `https://random-name.trycloudflare.com` pointing to your dashboard.

### **Using Ngrok**
```bash
ngrok http 3000
```

---

## 4. Local Area Network (LAN) Presentation (Offline Hackathon Venue)

To share the app with judges on the same Wi-Fi / Ethernet router:

1. Find your machine's IP address:
   * Windows: `ipconfig` (look for IPv4 Address, e.g. `192.168.1.100`)
   * Linux/Mac: `ip a` or `ifconfig`

2. Start Backend:
   ```bash
   cd backend
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

3. Update Frontend `NEXT_PUBLIC_API_URL` to your LAN IP (`http://192.168.1.100:8000`), then start frontend:
   ```bash
   cd frontend
   npm run dev
   ```

4. Anyone on the same Wi-Fi can open `http://192.168.1.100:3000`.
