"""
AIDTM Student Support Agent — Assignment 2
Extends the Assignment 1 helpdesk with student identity, authorization,
approval gates, persistent audit logs, and sensitive-memory filtering.

Run:
  pip install -r requirements.txt
  streamlit run AIDTM_Assignment2.py

Use fictional demo accounts only:
  STU001 / demo001
  STU002 / demo002

Set GROQ_API_KEY and LANGSMITH_API_KEY in a local .env file.
Never commit .env to GitHub.
"""
import json
import os
import re
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

try:
    from langchain_groq import ChatGroq
    from langchain_core.prompts import ChatPromptTemplate
    from langsmith import traceable
except ImportError:
    ChatGroq = None
    ChatPromptTemplate = None
    traceable = lambda **kwargs: (lambda fn: fn)

load_dotenv()

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
AUDIT_FILE = DATA_DIR / "audit_log.jsonl"
MEMORY_FILE = DATA_DIR / "safe_memory.json"

# Fictional demo data. Replace with an approved database/auth provider for production.
STUDENT_RECORDS = {
    "STU001": {
        "name": "Demo Student One",
        "fee_status": "Paid",
        "scholarship_status": "Approved",
        "contact_email": "student1@example.invalid",
    },
    "STU002": {
        "name": "Demo Student Two",
        "fee_status": "Pending",
        "scholarship_status": "Under Review",
        "contact_email": "student2@example.invalid",
    },
}
DEMO_PASSWORDS = {"STU001": "demo001", "STU002": "demo002"}

SENSITIVE_PATTERN = re.compile(
    r"\b(password|passwd|passcode|otp|one[- ]time password|api key|secret|access token)\b",
    re.IGNORECASE,
)

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def append_audit(actor, action, target, allowed, approval_status, result, details=None):
    """Append-only JSONL audit record. Avoid storing secrets or unnecessary PII."""
    record = {
        "timestamp": utc_now(),
        "actor_student_id": actor or "ANONYMOUS",
        "action": action,
        "target_student_id": target,
        "allowed": bool(allowed),
        "approval_status": approval_status,
        "result": result,
        "details": details or {},
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def load_safe_memory():
    if not MEMORY_FILE.exists():
        return {}
    try:
        data = json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}

def save_safe_memory(student_id, key, value):
    """Store only non-sensitive preferences scoped to the signed-in student."""
    if not student_id or student_id not in STUDENT_RECORDS:
        return False, "Sign in before saving memory."
    if SENSITIVE_PATTERN.search(f"{key} {value}"):
        append_audit(student_id, "save_memory", student_id, False, "not_required",
                     "blocked_sensitive_memory")
        return False, "I did not save that because it appears to contain sensitive information."
    data = load_safe_memory()
    data.setdefault(student_id, {})
    data[student_id][str(key)[:80]] = str(value)[:300]
    MEMORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    append_audit(student_id, "save_memory", student_id, True, "not_required", "saved")
    return True, "Saved a non-sensitive preference."

def get_own_record(actor, target, field):
    """Authorization is enforced in application code, not by an LLM prompt."""
    if actor not in STUDENT_RECORDS:
        append_audit(actor, "read_student_record", target, False, "not_required",
                     "blocked_not_authenticated")
        return None, "Please sign in first."
    if target != actor:
        append_audit(actor, "read_student_record", target, False, "not_required",
                     "blocked_cross_student_access", {"field": field})
        return None, "Access denied: you can only view your own private record."
    if field not in {"fee_status", "scholarship_status"}:
        append_audit(actor, "read_student_record", target, False, "not_required",
                     "blocked_invalid_field")
        return None, "That field is not available."
    value = STUDENT_RECORDS[actor].get(field)
    append_audit(actor, "read_student_record", target, True, "not_required",
                 "success", {"field": field})
    return value, None

def request_sensitive_change(actor, target, field, new_value):
    """Create a pending request; never mutate the record until explicit approval."""
    if actor not in STUDENT_RECORDS:
        append_audit(actor, "request_sensitive_change", target, False, "not_required",
                     "blocked_not_authenticated")
        return "Please sign in first."
    if target != actor:
        append_audit(actor, "request_sensitive_change", target, False, "not_required",
                     "blocked_cross_student_access")
        return "Access denied: you can only request changes to your own record."
    if field not in {"contact_email"}:
        append_audit(actor, "request_sensitive_change", target, False, "not_required",
                     "blocked_invalid_field")
        return "This field cannot be changed through the demo app."
    if SENSITIVE_PATTERN.search(str(new_value)):
        append_audit(actor, "request_sensitive_change", target, False, "not_required",
                     "blocked_sensitive_input")
        return "Please do not enter passwords, OTPs, or secret tokens."
    pending = st.session_state.setdefault("pending_change", None)
    st.session_state.pending_change = {
        "actor": actor, "target": target, "field": field, "new_value": str(new_value)[:200]
    }
    append_audit(actor, "request_sensitive_change", target, True, "pending",
                 "awaiting_explicit_approval", {"field": field})
    return "Change prepared. It has NOT been applied. Review and approve or reject it below."

def resolve_pending_change(approved):
    pending = st.session_state.get("pending_change")
    if not pending:
        return "There is no pending change."
    actor = st.session_state.get("student_id")
    if actor != pending["actor"] or actor != pending["target"]:
        append_audit(actor, "resolve_sensitive_change", pending["target"], False,
                     "rejected", "actor_mismatch")
        st.session_state.pending_change = None
        return "Approval rejected: identity mismatch."
    if approved:
        STUDENT_RECORDS[actor][pending["field"]] = pending["new_value"]
        append_audit(actor, "resolve_sensitive_change", pending["target"], True,
                     "approved", "change_applied", {"field": pending["field"]})
        message = "Approved. The demo record has been updated."
    else:
        append_audit(actor, "resolve_sensitive_change", pending["target"], True,
                     "rejected", "change_not_applied", {"field": pending["field"]})
        message = "Rejected. No change was made."
    st.session_state.pending_change = None
    return message

def safe_policy_answer(question):
    q = question.lower()
    if any(x in q for x in ("fee", "payment", "installment", "tuition", "caution deposit")):
        return (
            "For official fee information, check https://www.aidtm.ac.in/admission. "
            "This demo should not be treated as the authoritative source for current fees."
        )
    if any(x in q for x in ("placement", "package", "ctc", "recruitment", "sip")):
        return (
            "For current placement information, please verify details on https://www.aidtm.ac.in/. "
            "I should not invent placement figures or company names."
        )
    if any(x in q for x in ("admission", "address", "contact", "program", "programme")):
        return (
            "AIDTM official website: https://www.aidtm.ac.in/ . "
            "For current admissions or contact details, verify them on the official site."
        )
    return "I couldn't find a verified answer in this demo knowledge base. Please check the official AIDTM website."

def llm_answer(question):
    """Optional LLM answer for general college helpdesk questions; no private record is sent."""
    if ChatGroq is None or not os.getenv("GROQ_API_KEY"):
        return safe_policy_answer(question), {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                                               "note": "LLM unavailable; fallback response used"}
    model = ChatGroq(
        model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b"),
        groq_api_key=os.getenv("GROQ_API_KEY"),
        temperature=0,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a concise AIDTM college helpdesk. Use only verified public information included in the user question. Do not invent fees, placement numbers, or rules. If unsure, direct the user to https://www.aidtm.ac.in/. Do not request passwords or OTPs."),
        ("human", "{question}"),
    ])
    response = (prompt | model).invoke({"question": question})
    usage = getattr(response, "usage_metadata", None) or {}
    return response.content, {
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "total_tokens": usage.get("total_tokens", 0),
    }

@traceable(name="Assignment 2 Helpdesk Query", project_name=os.getenv("LANGSMITH_PROJECT", "Help_Desk"))
def answer_public_question(question):
    return llm_answer(question)

def login():
    st.title("AIDTM Student Support Agent")
    st.caption("Assignment 2 demo — fictional accounts only")
    with st.form("login_form"):
        sid = st.text_input("Demo student ID (STU001 or STU002)")
        password = st.text_input("Demo password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        sid = sid.strip().upper()
        expected = DEMO_PASSWORDS.get(sid, "")
        if expected and hmac.compare_digest(password, expected):
            st.session_state.student_id = sid
            append_audit(sid, "login", sid, True, "not_required", "success")
            st.rerun()
        append_audit(sid or None, "login", sid or None, False, "not_required", "failed_login")
        st.error("Sign-in failed. Use a fictional demo account listed in the README.")

def main():
    st.set_page_config(page_title="AIDTM Student Support Agent", page_icon="🎓", layout="centered")
    if "student_id" not in st.session_state:
        login()
        return

    sid = st.session_state.student_id
    st.title("🎓 AIDTM Student Support Agent")
    st.caption(f"Signed in as {sid} · Demo data only")
    if st.button("Sign out"):
        append_audit(sid, "logout", sid, True, "not_required", "success")
        del st.session_state["student_id"]
        st.rerun()

    st.subheader("Your private student record")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Check my fee status"):
            value, error = get_own_record(sid, sid, "fee_status")
            st.info(error if error else f"Fee status: {value}")
    with col2:
        if st.button("Check my scholarship status"):
            value, error = get_own_record(sid, sid, "scholarship_status")
            st.info(error if error else f"Scholarship status: {value}")

    st.subheader("Privacy test")
    target = st.selectbox("Select record to request", [sid] + [x for x in STUDENT_RECORDS if x != sid])
    if st.button("Try to view selected student's fee status"):
        value, error = get_own_record(sid, target, "fee_status")
        st.warning(error if error else f"Fee status: {value}")

    st.subheader("Sensitive change with approval")
    new_email = st.text_input("Request a change to your demo contact email")
    if st.button("Request email change"):
        st.info(request_sensitive_change(sid, sid, "contact_email", new_email))
    pending = st.session_state.get("pending_change")
    if pending and pending.get("actor") == sid:
        st.warning(f"Pending request: update {pending['field']} to {pending['new_value']}. Not applied yet.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Approve change"):
                st.success(resolve_pending_change(True))
        with c2:
            if st.button("Reject change"):
                st.info(resolve_pending_change(False))

    st.subheader("College helpdesk")
    question = st.chat_input("Ask about fees, placements, admission or college information")
    if question:
        if SENSITIVE_PATTERN.search(question):
            append_audit(sid, "chat_sensitive_input", sid, False, "not_required",
                         "sensitive_input_not_saved")
            st.warning("Please do not share passwords, OTPs, API keys, or secret tokens. I won't save this message.")
        else:
            with st.spinner("Checking helpdesk information..."):
                try:
                    answer, usage = answer_public_question(question)
                except Exception:
                    answer, usage = safe_policy_answer(question), {
                        "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                        "note": "Fallback used after model error"
                    }
                append_audit(sid, "public_helpdesk_query", sid, True, "not_required",
                             "answered", {"token_usage": usage})
                st.chat_message("user").write(question)
                st.chat_message("assistant").write(answer)
                st.caption(f"Token usage (if supplied by provider): input {usage.get('input_tokens', 0)}, "
                           f"output {usage.get('output_tokens', 0)}, total {usage.get('total_tokens', 0)}")

    with st.expander("Saved non-sensitive memory"):
        key = st.text_input("Memory key (e.g., preferred_language)")
        value = st.text_input("Memory value (non-sensitive only)")
        if st.button("Save preference"):
            ok, message = save_safe_memory(sid, key, value)
            (st.success if ok else st.warning)(message)
        st.json(load_safe_memory().get(sid, {}))

    with st.expander("Audit log (demo evidence)"):
        if AUDIT_FILE.exists():
            lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
            own_records = []
            for line in lines[-300:]:
                try:
                    record = json.loads(line)
                    if record.get("actor_student_id") == sid:
                        own_records.append(record)
                except json.JSONDecodeError:
                    continue
            st.json(own_records)
        else:
            st.write("No audit events yet. Perform a test scenario first.")

if __name__ == "__main__":
    main()
