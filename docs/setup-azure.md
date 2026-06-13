# Azure AI Foundry Setup Guide

This guide walks you through setting up Azure AI Foundry for real PyRIT scans.

---

## Prerequisites

- Azure subscription (Azure for Students works)
- Azure CLI installed: `curl -sL https://aka.ms/InstallAzureCLIDeb | bash`

---

## Step 1 — Create an Azure AI Foundry project

1. Go to [ai.azure.com](https://ai.azure.com)
2. Click **New project**
3. Enter a name (e.g. `lab-redteam-pyrit`)
4. Select or create an Azure OpenAI resource
5. Click **Create project**

---

## Step 2 — Deploy GPT-4o

1. In your project, go to **Models → Deployments**
2. Click **Deploy model**
3. Select `gpt-4o` (GlobalStandard)
4. Set TPM to at least 100k (225k recommended for red teaming)
5. Note the deployment name — you'll need it for `.env`

---

## Step 3 — Configure content filter for red teaming ⚠️

This is the **most important step**. The default content filter blocks attack prompts before they reach the model, which prevents PyRIT from getting valid responses to evaluate.

1. Go to **Safety + Security → Content filters**
2. Click **+ Create content filter**
3. Name it `redteam-lab`
4. Configure as follows:

| Category | Input action | Output action |
|----------|-------------|---------------|
| **Jailbreak** | **Annotate** ← critical | — |
| Violence | Annotate | Block Low |
| Hate/Unfairness | Annotate | Block Low |
| Sexual | Annotate | Block Low |
| Self-harm | Annotate | Block Low |

> **Why Annotate instead of Block?**  
> With Block, the model returns a 400 error. PyRIT/the evaluator receives no response to analyze.  
> With Annotate, the model responds (accepting or refusing), and the safety score reflects the actual model behavior.

5. Click **Create**
6. Go back to your GPT-4o deployment → **Edit**
7. In **Content filter**, select `redteam-lab`
8. Save

---

## Step 4 — Get your API credentials

1. In your Foundry project, go to **Settings** or **Overview**
2. Copy:
   - **Project URL**: `https://your-resource.services.ai.azure.com/api/projects/your-project`
   - **Endpoint**: `https://your-resource.services.ai.azure.com`
   - **API Key**: from Keys section

3. Get your Azure subscription details:

```bash
# Subscription ID
az account show --query id -o tsv

# Resource group
az group list --query "[].name" -o tsv
```

---

## Step 5 — Authenticate on the server

PyRIT uses DefaultAzureCredential which picks up `az login`:

```bash
az login --use-device-code
```

Follow the device code flow. The token persists until it expires.

For production automation, use a Service Principal or Managed Identity instead.

---

## Verifying the setup

After configuring `.env` and starting the backend:

```bash
curl -s http://localhost:8000/api/health
# Should return: {"pyrit_available": true, ...}
```

If `pyrit_available` is `false`, check that `azure-ai-evaluation[redteam]` is installed:

```bash
pip install "azure-ai-evaluation[redteam]" azure-identity
```
