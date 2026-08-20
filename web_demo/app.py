import os
import json
import gradio as gr
from huggingface_hub import InferenceClient

MODEL_NAME = "elsiddik/finsec_detector"
client = InferenceClient(model=MODEL_NAME)

SYSTEM_PROMPT = (
    "You are FineSec-AI, an expert Application Security Engineer. "
    "Analyze code snippet or security report for vulnerabilities and output JSON report with fields: "
    "'is_vulnerable', 'cwe', 'vulnerability_type', 'severity', 'vulnerable_lines', 'explanation', 'remediation', 'fixed_code'."
)

def audit_code(code_text):
    if not code_text or not code_text.strip():
        return "Please enter a code snippet to analyze.", {}

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this code for security vulnerabilities:\n```\n{code_text}\n```"}
    ]
    
    try:
        response = client.chat_completion(messages=messages, max_tokens=512)
        raw_response = response.choices[0].message.content.strip()
    except Exception as e:
        try:
            fallback = InferenceClient(model="Qwen/Qwen2.5-Coder-7B-Instruct")
            response = fallback.chat_completion(messages=messages, max_tokens=512)
            raw_response = response.choices[0].message.content.strip()
        except Exception as ex:
            return f"Model is initializing on Hugging Face Serverless API. Please retry in 30 seconds. ({str(ex)})", {}

    # Parse JSON
    try:
        cleaned = raw_response
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()
        report = json.loads(cleaned)
    except Exception:
        report = {"raw_output": raw_response}

    if report.get("is_vulnerable") is True:
        status = f"🔴 VULNERABLE ({report.get('severity', 'HIGH')} - {report.get('cwe', 'CWE')})"
    else:
        status = "🟢 SAFE (No high-risk vulnerabilities detected)"

    summary = f"""### Audit Summary: {status}
**Type**: {report.get('vulnerability_type', 'N/A')}
**CWE**: {report.get('cwe', 'N/A')}
**Severity**: {report.get('severity', 'N/A')}

**Explanation**:
{report.get('explanation', 'N/A')}

**Remediation**:
{report.get('remediation', 'N/A')}
"""
    return summary, json.dumps(report, indent=2)

EXAMPLES = [
    ["def login(username, password):\n    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n    cursor.execute(query)"],
    ["import os\ndef ping(host):\n    os.system('ping -c 1 ' + host)"],
    ["def read_user_file(filename):\n    with open('/var/www/uploads/' + filename, 'r') as f:\n        return f.read()"],
    ["import subprocess\ndef ping_safe(host):\n    subprocess.run(['ping', '-c', '1', host], check=True)"]
]

with gr.Blocks(title="FineSec Security Auditor") as demo:
    gr.Markdown("# 🛡️ FineSec Security Auditor (elsiddik/finsec_detector)")
    gr.Markdown("An AI-powered Application Security Auditor fine-tuned on CVE benchmarks and secure code repair patterns.")

    with gr.Row():
        with gr.Column():
            code_input = gr.Code(label="Input Source Code", language="python", lines=12)
            submit_btn = gr.Button("🔍 Audit Code", variant="primary")
            gr.Examples(examples=EXAMPLES, inputs=[code_input])

        with gr.Column():
            summary_output = gr.Markdown(label="Security Audit Findings")
            json_output = gr.Code(label="Structured JSON Report", language="json", lines=12)

    submit_btn.click(fn=audit_code, inputs=[code_input], outputs=[summary_output, json_output])

if __name__ == "__main__":
    demo.launch()
