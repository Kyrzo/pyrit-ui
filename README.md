# PyRIT UI

**The missing visual interface for Microsoft's Python Risk Identification Toolkit.**

PyRIT UI is an open-source web platform for AI red teaming built on top of Azure AI Evaluation SDK. It provides a dashboard to launch adversarial scans, visualize results, manage users with RBAC, and generate PDF reports.

> Built by [@Kyrzo](https://github.com/Kyrzo) · [cibersecblog.com](https://cibersecblog.com)

## Quick Start

### 1. Install backend
\`\`\`bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install "azure-ai-evaluation[redteam]" azure-identity
\`\`\`

### 2. Configure
\`\`\`bash
cp .env.example .env
nano .env
\`\`\`

### 3. Create admin user
\`\`\`bash
python3 create_user.py create --username admin --password yourpassword --role admin
\`\`\`

### 4. Start
\`\`\`bash
uvicorn main:app --host 127.0.0.1 --port 8000
\`\`\`

### 5. Open UI
Open \`frontend/index.html\` in your browser or serve it with any static server.

## Documentation
- [Azure Setup](docs/setup-azure.md)
- [VPS Deployment](docs/setup-vps.md)

## License
MIT
