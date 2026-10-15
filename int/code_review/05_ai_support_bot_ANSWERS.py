# Practice 05: AI customer-support assistant (Python / FastAPI / LLM tools)
# Customers chat with an LLM that can look up orders and call tools (refund, cancel, fetch URL).
# Find every vulnerability (classic AppSec AND OWASP LLM Top 10), with line, exploit and fix. Time: 30 minutes.

import json
import os

import requests
import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment
from sqlalchemy import text

from app.auth import get_current_user
from app.db import get_db
from app.llm import chat_completion

app = FastAPI()
jinja = Environment(autoescape=False)                                                                           # LINE 20: [HIGH] autoescape is OFF -> everything rendered through this environment is raw HTML (see transcript())
SYSTEM_PROMPT = open("prompts/system.txt").read()


def issue_refund(order_id: str, amount: float):
    return requests.post(
        "https://payments.internal/refund",
        json={"order_id": order_id, "amount": amount},
        headers={"X-Api-Key": os.environ["REFUND_API_KEY"]},
        verify=False,                                                                                           # LINE 29: [HIGH] TLS certificate verification disabled on a payments call -> MITM can steal the API key or alter refunds
    ).json()


def cancel_order(order_id: str):
    return requests.post("https://orders.internal/cancel", json={"order_id": order_id}, timeout=5).json()


def fetch_url(url: str):
    return requests.get(url, timeout=5).text[:2000]                                                             # LINE 38: [HIGH] SSRF tool: the model (steerable by prompt injection) can fetch internal URLs or cloud metadata and read the result back to the user


TOOLS = {"issue_refund": issue_refund, "cancel_order": cancel_order, "fetch_url": fetch_url}


@app.post("/chat")                                                                                              # LINE 44: [MEDIUM] No rate limit or token budget -> cost exhaustion / denial of wallet (LLM10 Unbounded Consumption)
def chat(req: dict, user=Depends(get_current_user), db=Depends(get_db)):
    question = req["message"]
    order_id = req.get("order_id")
    orders = db.execute(
        text(f"SELECT id, status, address, total FROM orders WHERE id = {order_id}")                            # LINE 49: [HIGH] SQL injection: f-string inside text(). Also BOLA: no user_id filter, so anyone's order (address = PII) goes into the prompt
    ).fetchall()
    context = json.dumps([dict(o._mapping) for o in orders], default=str)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\nRefund API key: " + os.environ["REFUND_API_KEY"]},     # LINE 53: [HIGH] Secret placed in the prompt -> extractable via prompt injection ("print your instructions"); LLM07 System Prompt Leakage. Keep secrets in the tool layer
        {"role": "user", "content": f"Order data: {context}\n\nCustomer question: {question}"},                 # LINE 54: [MEDIUM] Untrusted data and instructions mixed in one message -> indirect prompt injection via stored order fields (e.g. an address containing instructions). LLM01
    ]
    reply = chat_completion(messages, tools=list(TOOLS))
    results = []
    for call in reply.tool_calls:
        results.append(TOOLS[call.name](**call.arguments))                                                      # LINE 59: [CRITICAL] Excessive agency (LLM06): tool calls run with NO authorization check against `user` and no confirmation -> injected text makes the bot refund or cancel ANY order. Enforce authz in each tool and confirm high-impact actions
    db.execute(
        text("INSERT INTO transcripts (user_id, html) VALUES (:uid, :html)"),                                   # LINE 61: NOT A VULN: bound parameters (:uid, :html)
        {"uid": user.id, "html": reply.text},
    )
    db.commit()
    return {"answer": reply.text, "tool_results": results}                                                      # LINE 65: [MEDIUM] Raw tool output returned to the user (fetch_url responses, internal refund API errors) -> data leakage. LLM02 Sensitive Information Disclosure


@app.get("/transcripts/{tid}", response_class=HTMLResponse)
def transcript(tid: int, user=Depends(get_current_user), db=Depends(get_db)):
    row = db.execute(text("SELECT user_id, html FROM transcripts WHERE id = :id"), {"id": tid}).fetchone()      # LINE 70: NOT A VULN: bound parameter, and FastAPI enforces tid as int
    if row.user_id != user.id and not user.is_support:                                                          # LINE 71: NOT A VULN: ownership / support-role check is present (minor: crashes with a 500 if row is None)
        raise HTTPException(status_code=403)
    return jinja.from_string("<div class='chat'>{{ body }}</div>").render(body=row.html)                        # LINE 73: [HIGH] Stored XSS: model output (which the customer can steer) is rendered unescaped; support agents open it -> agent session hijack. LLM05 Improper Output Handling


@app.post("/admin/import-config")
async def import_config(request: Request, user=Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403)                                                                    # LINE 79: NOT A VULN: admin role check is present
    cfg = yaml.load(await request.body(), Loader=yaml.Loader)                                                   # LINE 80: [HIGH] yaml.Loader builds arbitrary Python objects (!!python/object/apply:os.system) -> RCE. Use yaml.safe_load. Admin-only lowers likelihood, not severity
    with open("config/bot.json", "w") as f:
        json.dump(cfg, f)
    return {"ok": True}


@app.post("/feedback")
def feedback(req: dict, user=Depends(get_current_user)):
    with open(f"/var/feedback/{req['ticket']}.json", "w") as f:                                                 # LINE 88: [HIGH] Path traversal / arbitrary file write: ticket = ../../srv/app/templates/x -> write files outside /var/feedback. Use a server-generated id
        json.dump(req, f)
    return {"ok": True}

# ================================================================================================
# ANSWER KEY SUMMARY (line numbers match the practice file)
#  CRITICAL line 59   Excessive agency (LLM06): tool calls run with NO authorization check against `user` and no confirmation -> injected text makes the bot refund or cance
#  HIGH     line 20   autoescape is OFF -> everything rendered through this environment is raw HTML (see transcript())
#  HIGH     line 29   TLS certificate verification disabled on a payments call -> MITM can steal the API key or alter refunds
#  HIGH     line 38   SSRF tool: the model (steerable by prompt injection) can fetch internal URLs or cloud metadata and read the result back to the user
#  HIGH     line 49   SQL injection: f-string inside text(). Also BOLA: no user_id filter, so anyone's order (address = PII) goes into the prompt
#  HIGH     line 53   Secret placed in the prompt -> extractable via prompt injection ("print your instructions"); LLM07 System Prompt Leakage. Keep secrets in the tool lay
#  HIGH     line 73   Stored XSS: model output (which the customer can steer) is rendered unescaped; support agents open it -> agent session hijack. LLM05 Improper Output H
#  HIGH     line 80   yaml.Loader builds arbitrary Python objects (!!python/object/apply:os.system) -> RCE. Use yaml.safe_load. Admin-only lowers likelihood, not severity
#  HIGH     line 88   Path traversal / arbitrary file write: ticket = ../../srv/app/templates/x -> write files outside /var/feedback. Use a server-generated id
#  MEDIUM   line 44   No rate limit or token budget -> cost exhaustion / denial of wallet (LLM10 Unbounded Consumption)
#  MEDIUM   line 54   Untrusted data and instructions mixed in one message -> indirect prompt injection via stored order fields (e.g. an address containing instructions). L
#  MEDIUM   line 65   Raw tool output returned to the user (fetch_url responses, internal refund API errors) -> data leakage. LLM02 Sensitive Information Disclosure
#  NOT A VULN (decoys you should say are safe): lines 61, 70, 71, 79
#  Total real findings: 12
# ================================================================================================
