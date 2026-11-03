# Ternline Production Deployment Guide: Frontend on Vercel & Backend on AWS

This guide outlines the production deployment architecture and step-by-step setup for running Ternline with:
- **Frontend UI & Documentation:** Hosted globally on **Vercel** (`index.html`, `console.html`, `docs.html`).
- **Backend API & Detection Engine:** Hosted on **AWS** (ECS Fargate / App Runner / EC2) with AWS RDS PostgreSQL 16, AWS ElastiCache Redis 7, and AWS SES for email verification.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |               Vercel Edge                   |
[ Web Browser / Security Operator ] ->|  - Landing Page (/)                        |
                                      |  - Control Room Console (/console)          |
                                      |  - API Documentation (/docs)                |
                                      |  - Email Verification Link (/verify-email)  |
                                      +---------------------+-----------------------+
                                                            | HTTPS API Calls (Bearer JWT / API Key)
                                                            v
+-----------------------------------------------------------------------------------+
|                                  AWS Cloud VPC                                    |
|                                                                                   |
|  +--------------------------------+       +------------------------------------+  |
|  |     Application Load Balancer  | ----> |     AWS ECS Fargate Task / App     |  |
|  |    (ACM SSL/TLS Termination)   |       |     Ternline Backend (Port 8000)   |  |
|  +--------------------------------+       +-----------------+------------------+  |
|                                                             |                     |
|         +---------------------------------------------------+                     |
|         |                                                   |                     |
|         v                                                   v                     |
|  +------------------------------+            +---------------------------------+  |
|  |     AWS RDS PostgreSQL 16    |            |   AWS ElastiCache Redis 7 (TLS) |  |
|  |   (Findings, Events, Users)  |            |  (Sliding Window, State Locks)  |  |
|  +------------------------------+            +---------------------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |     AWS Simple Email Service (SES)                                          |  |
|  |     Sends cryptographic account activation & email verification links       |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## Part 1: Frontend Deployment on Vercel

The frontend is fully configured via `vercel.json` with clean routing, security headers (HSTS, CSP, X-Frame-Options), and dynamic backend URL discovery.

### Step 1: Deploy to Vercel via CLI or Dashboard
1. Link the repository to your Vercel account:
   ```bash
   vercel
   ```
   Or connect your GitHub repository in the [Vercel Dashboard](https://vercel.com/new).
2. Configuration settings:
   - **Framework Preset:** `Other`
   - **Root Directory:** `./`
   - **Build Command:** *(Leave empty)*
   - **Output Directory:** `./`

### Step 2: Route Mapping (Handled by `vercel.json`)
- `/` &rarr; `index.html` (Landing page & threat overview)
- `/console` &rarr; `console.html` (Full SOC Control Room)
- `/docs` &rarr; `docs.html` (API & Architecture Documentation)
- `/verify-email` &rarr; Automatic verification token capture and session boot

### Step 3: Connect Frontend to Your AWS Backend
When accessing the Control Room on Vercel, navigate to **Backend & Settings** (gear icon) in the bottom-left sidebar:
- Enter your AWS Backend URL (e.g., `https://api.yourdomain.com`).
- The frontend securely retains this in `localStorage.setItem('ternline_backend_url', ...)` while keeping bearer tokens strictly in JS memory.

---

## Part 2: Backend Deployment on AWS

### 1. Provision Infrastructure Dependencies
1. **AWS RDS PostgreSQL 16**:
   - Engine: PostgreSQL 16.x
   - Database name: `cyber_engine`
   - Enforce SSL connection (`sslmode=require`).
2. **AWS ElastiCache Redis 7**:
   - Engine: Redis 7.x
   - Enable In-Transit Encryption (TLS) and configure auth token.
3. **AWS SES (Simple Email Service)**:
   - Verify your sending domain (e.g., `ternline.io`) or email address (e.g., `noreply@ternline.io`).
   - Grant `ses:SendEmail` permissions to your ECS Task Execution Role.

### 2. Build and Push Docker Image to Amazon ECR
```bash
# 1. Authenticate with your AWS ECR Registry
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

# 2. Build production multi-stage image
docker build -t ternline/backend:latest -f Dockerfile .

# 3. Tag and push to ECR
docker tag ternline/backend:latest <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/ternline-backend:latest
docker push <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/ternline-backend:latest
```

### 3. Deploy via ECS Fargate
1. Store production secrets in **AWS Secrets Manager**:
   - `ternline/production/database_url`
   - `ternline/production/redis_url`
   - `ternline/production/secret_key` (Generate via `openssl rand -hex 32`)
   - `ternline/production/investigator_api_key`
2. Register the task definition:
   ```bash
   aws ecs register-task-definition --cli-input-json file://aws-task-definition.json
   ```
3. Create or update the ECS Fargate Service behind your Application Load Balancer (ALB).

---

## Part 3: Self-Securing Auth & Email Verification Verification

1. **User Sign Up (`POST /api/v1/auth/register`)**:
   - Accepts email, password, and optional tenant name.
   - Enforces password complexity (8+ chars, uppercase, lowercase, digit/special).
   - Hashes password using salted PBKDF2-HMAC-SHA256 (600,000 iterations).
   - Generates a 256-bit cryptographic token.
   - Dispatches verification email via AWS SES or SMTP.
2. **Email Verification (`POST /api/v1/auth/verify-email`)**:
   - Validates cryptographic token and 24-hour expiration.
   - Marks operator account as verified and burns the one-time token.
   - Issues an initial operator JWT session token.
3. **Brute-Force Rate Limiting**:
   - Protects `/api/v1/auth/login` by enforcing sliding window limits (maximum 5 failed attempts per 5 minutes per account).
4. **Tenant Isolation**:
   - All findings, rules, actions, and audit logs are strictly scoped by `tenant_id`.

