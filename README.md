<div align="center">

# 🛡️ PyRIT UI

### La interfaz visual que Microsoft no construyó para el red teaming con IA

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com)
[![Azure AI](https://img.shields.io/badge/Azure%20AI-Foundry-0078D4.svg)](https://ai.azure.com)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

**[Demo](https://lab.cibersecblog.com)** · **[Blog](https://cibersecblog.com)** · **[Documentación](#-documentación)**

</div>

---

PyRIT UI es una plataforma web open-source para el **red teaming de sistemas de IA**, construida sobre el [SDK de Azure AI Evaluation](https://learn.microsoft.com/es-es/azure/ai-studio/how-to/develop/evaluate-sdk) y [PyRIT de Microsoft](https://github.com/Azure/PyRIT). Proporciona todo lo que PyRIT no tiene por defecto: interfaz gráfica, gestión de usuarios, reportes PDF profesionales y persistencia de resultados.

> Desarrollado por [@Kyrzo](https://github.com/Kyrzo) · [cibersecblog.com](https://cibersecblog.com)
> Parte de la [serie AI Red Teaming Lab](https://cibersecblog.com)

---

## ✨ Funcionalidades

### 🎯 Motor de ataques
- **Scans PyRIT reales** via Azure AI Foundry — Violence, HateUnfairness, Sexual, SelfHarm
- **Prompt Injection directo** — 8 seeds de inyección enviados directamente al modelo
- **Prompts custom** — tus propios ataques evaluados con score 0-7
- **10 estrategias de ataque** — Baseline, Jailbreak, Base64, ROT13, Morse, Flip, Leetspeak, Crescendo, UnicodeConfusable, IndirectJailbreak
- **Ataques multilingüe** — genera prompts en Español, Francés, Alemán, Portugués
- **Application scenario** — ataques contextualizados para tu aplicación específica

### 📊 Análisis y resultados
- **Dashboard** con métricas en tiempo real, cobertura OWASP Top 10, trend ASR
- **GPT-4o como juez** — evalúa cada respuesta con score 0-7 y reasoning detallado
- **Mapeo automático** a OWASP LLM Top 10 (LLM01-LLM09) y MITRE ATLAS
- **Reportes PDF** profesionales con gráficas, grid OWASP y recomendaciones automáticas
- **Export** en PDF, JSON, CSV y Markdown

### 👥 Plataforma
- **RBAC completo** — roles Admin, Analyst y Viewer con autenticación JWT
- **Persistencia SQLite** — los scans sobreviven reinicios del servidor
- **Catálogo de ataques** — biblioteca de referencia con 50+ prompts por categoría
- **Prompt libraries** — guarda y reutiliza conjuntos de prompts custom
- **Modo simulación** — demo completo sin necesidad de credenciales Azure
- **Gestión de usuarios CLI** — menú interactivo para crear/gestionar usuarios

---

## 🏗️ Arquitectura
<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/1067ec81-7660-4a58-8ca4-db5e5d6f1baa" />


### Modos de ejecución

| Modo | Cuándo se activa | Qué hace |
|------|-----------------|----------|
| **PyRIT real** | Credenciales Azure configuradas + categorías nativas | Foundry genera objetivos adversariales, ataca el target |
| **Prompts directos** | Siempre para injection/custom | Envía prompts vía HTTP, evalúa con GPT-4o como juez |
| **Simulación** | Sin credenciales Azure | Genera findings realistas para demo/testing |

---

## 🚀 Inicio rápido

### Requisitos previos

- Python 3.10+
- Linux / macOS / WSL2
- (Opcional) Suscripción Azure para scans reales — [Azure for Students](https://azure.microsoft.com/free/students/) funciona

### 1. Clonar el repositorio

```bash
git clone https://github.com/Kyrzo/pyrit-ui
cd pyrit-ui
```

### 2. Instalar el backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Para scans PyRIT reales con Azure (opcional)
pip install "azure-ai-evaluation[redteam]" azure-identity
```

### 3. Configurar

```bash
cp .env.example .env
nano .env
```

Variables mínimas para **modo simulación** (sin Azure):

```env
API_TOKEN=genera-un-token-aleatorio
JWT_SECRET=genera-otro-token-aleatorio
```

Para **scans reales** añade también las credenciales Azure — ver [Configuración Azure](#️-configuración-azure).

Genera tokens seguros:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 4. Crear el primer usuario administrador

```bash
# Modo interactivo (recomendado)
python3 create_user.py

# O directamente
python3 create_user.py create --username admin --password tu-contraseña --role admin
```

### 5. Arrancar el backend

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

### 6. Abrir la interfaz

Abre `frontend/index.html` en el navegador, o sírvela con cualquier servidor estático:

```bash
cd ../frontend
python3 -m http.server 3000
# Abre http://localhost:3000
```

En la UI → **Settings**:
- **Backend URL**: `http://localhost:8000`
- **Bearer token**: tu `API_TOKEN`

---

## ☁️ Configuración Azure

### ⚠️ Paso crítico: filtro de contenido para red teaming

El filtro predeterminado de Azure bloquea los prompts adversariales antes de llegar al modelo. Sin configurar esto, todos los scans darán error 400 y ASR 0% incorrecto.
NOTA: Esto lo hicimos para comprobar que funcionaban ataques sin entrar mucho detalle,  este paso es salvable

Ve a **ai.azure.com → Safety + Security → Content filters → + Crear**:

| Categoría | Acción en entrada | Motivo |
|-----------|------------------|--------|
| **Jailbreak** | **Anotar** ← imprescindible | Sin esto nada funciona |
| Violence | Anotar | Para evaluar comportamiento real |
| Hate/Unfairness | Anotar | Para evaluar comportamiento real |
| Sexual | Anotar | Para evaluar comportamiento real |
| Self-harm | Anotar | Para evaluar comportamiento real |

Asigna este filtro a tu deployment de GPT-4o.

### Variables de entorno completas

```env
# Azure AI Foundry
AZURE_AI_PROJECT=https://tu-recurso.services.ai.azure.com/api/projects/tu-proyecto
AZURE_OPENAI_ENDPOINT=https://tu-recurso.services.ai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_KEY=tu-clave-api

# Para el evaluador GPT-4o como juez
AZURE_SUBSCRIPTION_ID=tu-subscription-id
AZURE_RESOURCE_GROUP=tu-resource-group
```

Obtén los IDs con:

```bash
az account show --query id -o tsv        # subscription ID
az group list --query "[].name" -o tsv   # resource groups
```

Guía completa: [docs/setup-azure.md](docs/setup-azure.md)

---

## 🖥️ Despliegue en producción

Para un despliegue completo en VPS con HTTPS, Apache como reverse proxy y systemd, ver [docs/setup-vps.md](docs/setup-vps.md).

```bash
# Instalar como servicio systemd
cp backend/pyrit-ui.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable pyrit-ui
systemctl start pyrit-ui
```

---

## 👥 Gestión de usuarios (RBAC)

| Permiso | Admin | Analyst | Viewer |
|---------|-------|---------|--------|
| Lanzar scans | ✅ | ✅ | ❌ |
| Ver todos los scans | ✅ | solo propios | solo propios |
| Exportar reportes | ✅ | ✅ | ❌ |
| Eliminar scans | ✅ | solo propios | ❌ |
| Gestionar usuarios | ✅ | ❌ | ❌ |

```bash
# Menú interactivo
python3 create_user.py

# Comandos directos
python3 create_user.py create     --username analyst1 --password pass --role analyst
python3 create_user.py list
python3 create_user.py update     --username analyst1 --role admin
python3 create_user.py deactivate --username analyst1
python3 create_user.py passwd     --username analyst1 --password nuevapass
python3 create_user.py delete     --username analyst1
```

---

## 🔐 Seguridad del backend

| Medida | Detalle |
|--------|---------|
| Bearer token | Todas las rutas API protegidas |
| JWT | Sesiones con expiración configurable (8h por defecto) |
| Rate limiting | Límite por IP configurable (100 req/min) |
| CORS | Restringido a orígenes configurados |
| Headers de seguridad | HSTS, X-Frame-Options DENY, X-Content-Type-Options |
| Sin fingerprinting | Header Server eliminado |
| Swagger desactivado | No expone /docs en producción |
| PBKDF2 | 310.000 iteraciones para contraseñas |
| Logs sanitizados | API keys reemplazadas por *** |

---

## 📡 API

```
POST   /api/auth/login                          Obtener JWT
GET    /api/auth/me                             Info del usuario actual
POST   /api/auth/change-password                Cambiar contraseña

POST   /api/scans                               Lanzar scan
GET    /api/scans                               Listar scans
GET    /api/scans/{id}                          Detalles
GET    /api/scans/{id}/findings                 Findings (filtrable)
GET    /api/scans/{id}/scorecard                Scorecard OWASP + MITRE
GET    /api/scans/{id}/logs                     Logs de ejecución
GET    /api/scans/{id}/stream                   SSE tiempo real
GET    /api/scans/{id}/export?fmt=pdf|json|csv  Exportar reporte
DELETE /api/scans/{id}                          Eliminar scan

GET    /api/stats                               Estadísticas globales
GET    /api/prompt-libraries                    Listar librerías
POST   /api/prompt-libraries                    Crear librería
DELETE /api/prompt-libraries/{id}              Eliminar librería

GET    /api/users                               Listar usuarios (admin)
PUT    /api/users/{username}                    Actualizar usuario (admin)
DELETE /api/users/{username}                    Eliminar usuario (admin)
```

---

## 📁 Estructura del repositorio

```
pyrit-ui/
├── README.md
├── .gitignore
├── backend/
│   ├── main.py           # FastAPI — rutas, middleware, ejecución de scans
│   ├── auth.py           # Usuarios — SQLite + PBKDF2
│   ├── db.py             # Persistencia — scans, findings, librerías
│   ├── evaluator.py      # GPT-4o como juez — score 0-7
│   ├── pdf_report.py     # Generador PDF con reportlab
│   ├── create_user.py    # CLI de gestión de usuarios
│   ├── requirements.txt
│   ├── .env.example
│   └── pyrit-ui.service  # Servicio systemd
├── frontend/
│   └── index.html        # UI completa — HTML + CSS + JS
└── docs/
    ├── setup-azure.md    # Guía Azure AI Foundry
    └── setup-vps.md      # Guía despliegue producción
```

---

## 🗺️ Frameworks de referencia

| Framework | Cobertura |
|-----------|----------|
| [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | LLM01–LLM09 |
| [MITRE ATLAS](https://atlas.mitre.org/) | AML.T0051, AML.T0054, AML.T0025 |
| [Microsoft PyRIT](https://github.com/Azure/PyRIT) | Motor de red teaming |
| [Azure AI Evaluation SDK](https://learn.microsoft.com/es-es/azure/ai-studio/how-to/develop/evaluate-sdk) | Evaluadores de seguridad |
| [NIST AI RMF](https://airc.nist.gov/) | Govern, Map, Measure, Manage |

---

## 📄 Licencia

MIT — úsalo, fórkalo, adáptalo.

---

<div align="center">

*PyRIT UI es un proyecto open-source independiente y no está afiliado a Microsoft.*

**[⬆️ Volver arriba](#️-pyrit-ui)**

</div>
