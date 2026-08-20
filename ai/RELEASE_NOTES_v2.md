# FineSec-AI v2.0.0: The 1M Security Dataset & 7B Automated AppSec Auditor

**Official Community Release Announcement**

We are excited to announce **FineSec-AI v2.0.0**, an open-source Application Security ecosystem. This release introduces a **1,000,000 sample security dataset**, fine-tuned **Qwen2.5-Coder-7B QLoRA model weights**, **GGUF offline quantization (`Q4_K_M`)**, an interactive **Hugging Face Web Auditor**, and a **1-click GitHub Action for CI/CD pipelines**.

---

## Deliverables in This Release

### 1. FineSec-1M Master Dataset (`elsiddik/zz`)
- **1,000,000 training examples** (1.11 GB) formatted in standard JSON.
- **112,759 NVD CVE advisory records** + 500,000 multi-language code snippets & refactors.
- **Exact 50.0% Vulnerable / 50.0% Safe Control class balance** to eliminate false positives.

### 2. FineSec-Detector-v2 Model Weights (`elsiddik/finsec_detector-v2`)
- 7B parameter specialized cybersecurity Large Language Model fine-tuned on Qwen2.5-Coder-7B-Instruct using Unsloth 4-bit QLoRA.
- Audits source code across 9 languages: Python, C, C++, JavaScript, TypeScript, Go, Java, PHP, Bash, and Solidity.
- Verified **100.0% Precision & 90.9% F1 Score** on multi-language vulnerability benchmarks.

### 3. FineSec GitHub Action (`z0uz/FineSec_detect@main`)
- Automated CI/CD pipeline step for GitHub repositories.
- Audits code pushes and automatically leaves formatted markdown security findings on open Pull Requests.

### 4. GGUF Offline Quantization (`elsiddik/finsec_detector-v2-GGUF`)
- Provides `Q4_K_M` GGUF quantization for 1-line offline execution via Ollama and LM Studio.

### 5. Live Interactive Web Space (`elsiddik/zouz`)
- Gradio 5 web interface hosted on Hugging Face Spaces for real-time security auditing.

---

## Ecosystem Links

- **GitHub Repository**: [https://github.com/z0uz/FineSec_detect](https://github.com/z0uz/FineSec_detect)
- **Hugging Face 1M Dataset**: [https://huggingface.co/datasets/elsiddik/zz](https://huggingface.co/datasets/elsiddik/zz)
- **Hugging Face Model**: [https://huggingface.co/elsiddik/finsec_detector-v2](https://huggingface.co/elsiddik/finsec_detector-v2)
- **Hugging Face GGUF**: [https://huggingface.co/elsiddik/finsec_detector-v2-GGUF](https://huggingface.co/elsiddik/finsec_detector-v2-GGUF)
- **Live Web Auditor**: [https://huggingface.co/spaces/elsiddik/zouz](https://huggingface.co/spaces/elsiddik/zouz)

---

## Quickstart Code

```yaml
# Add to your repository: .github/workflows/security-audit.yml
name: FineSec Security Audit Pipeline
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: z0uz/FineSec_detect@main
        with:
          path: '.'
          fail-on-vulnerability: false
```

```bash
# Run locally via Ollama:
ollama run hf.co/elsiddik/finsec_detector-v2-GGUF
```

---

## License

FineSec-AI is released under the **Apache-2.0 License**.
