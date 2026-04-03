# 🛡️ SentinelX – AI SOC Co-Pilot

> AI-powered Security Operations Center (SOC) Co-Pilot built for hackathon demo.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-LLaMA%203.3%2070B-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Natural Language Query** | Ask questions about security logs in plain English — AI cites specific log IDs |
| ⚔️ **Multi-Agent SOC Debate** | Agent Alpha (aggressive) vs Agent Beta (cautious) with SOC Manager verdict |
| 🔴 **Attacker / Defender Mode** | Toggle red team vs blue team perspectives on any threat |
| 🛡️ **Prompt Injection Scanner** | Detects prompt injection attempts hidden inside log data |
| 📝 **Investigation Memory** | Save and retrieve investigation notes by case ID |
| ⚡ **Attack Simulation Engine** | Stream live fake attack events (brute force, exfil, lateral movement) |
| 🎯 **Threat Actor Profile Card** | AI-generated attacker personality profile after red team analysis |
| 🎤 **Voice Query** | Ask questions using your microphone via browser Speech API |

---

## 🛠️ Tech Stack

- **Backend:** FastAPI + Uvicorn
- **Frontend:** HTML / CSS / JavaScript (single file, no frameworks)
- **AI:** Groq API with LLaMA 3.3 70B Versatile
- **Data:** 60 mock security logs (in-memory)

---

## 📁 Project Structure

```
AI-Soc/
├── main.py             # FastAPI backend — all routes and logic
├── index.html          # Single-page frontend — dark theme dashboard
├── mock_logs.py        # 60 fake security log entries
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
└── README.md
```

---

## 🚀 Run Locally

**1. Clone the repo**

```bash
git clone https://github.com/rohitrawat2005/sentinelx-soc-copilot.git
cd sentinelx-soc-copilot
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Set your API key**

```bash
# PowerShell
$env:GROQ_API_KEY="your_key"

# Bash / macOS
export GROQ_API_KEY="your_key"
```

**4. Start the server**

```bash
python -m uvicorn main:app --reload --port 8000
```

**5. Open the dashboard**

```
http://localhost:8000
```

---

## 📸 Dashboard Preview

The dashboard features a 3-panel layout:

- **Left:** Scrollable security log viewer with severity badges
- **Center:** AI chat interface with voice input and attacker/defender toggle
- **Right:** Multi-agent debate, injection scanner, attack simulation, and notes

---

## 👤 Author

**Rohit Rawat** — [@rohitrawat2005](https://github.com/rohitrawat2005)

---

## 📄 License

This project is for hackathon / educational purposes.
