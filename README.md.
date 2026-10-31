# AIDTM Student Support Agent — Assignment 2

## Overview
This is an Assignment 2 demo that extends a college helpdesk with student identity, authorization, approval gates, safe memory, and audit records.

## Features
- Demo sign-in with fictional accounts.
- Application-code authorization: students can only read their own fee and scholarship status.
- Cross-student access attempts are blocked and audited.
- Sensitive email changes are pending until the student explicitly approves; rejection does not apply the change.
- Passwords, OTPs, API keys and similar secrets are not saved to persistent memory.
- JSONL audit log records actor, action, target, permission decision, approval status, and result.
- Optional Groq/LangChain responses for public helpdesk questions.
- LangSmith tracing decorator retained for helpdesk model calls.
- Token usage displayed when provider metadata supplies it.

## Run locally
1. Install Python 3.10+.
2. Create a virtual environment.
3. Install dependencies: `pip install -r requirements_assignment2.txt`
4. Create a local `.env` file from `.env.example` and add your own rotated keys.
5. Run: `streamlit run AIDTM_Assignment2.py`
6. Demo accounts: `STU001 / demo001`, `STU002 / demo002`.

## Test scenarios
1. Sign in as STU001 and check own fee/scholarship status — allowed.
2. As STU001, try to view STU002's fee status — blocked and audited.
3. Request a contact email change, then reject — no change is applied.
4. Request a contact email change, then approve — demo record is updated and audited.
5. Try saving a memory value containing `password` or `OTP` — it is blocked.
6. Ask a public helpdesk question and inspect token usage and audit log.

## Important limitations
- Demo credentials and student records are fictional and hard-coded for coursework only.
- This is not production authentication. Replace demo sign-in with institution-approved identity provider, secure password hashing, database access controls, and role-based access before real deployment.
- The demo approval is a self-confirmation workflow, not independent staff approval. If the instructor expects a separate human approver, implement a separate authorized admin account and approval queue.
- JSON audit logs are useful demonstration evidence but are not tamper-proof; production needs centralized, access-controlled audit storage.
- Model token usage may be unavailable from provider metadata for some model/API versions.
- Never commit `.env`, real student data, or API credentials.
