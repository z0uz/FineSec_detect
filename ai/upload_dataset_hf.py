#!/usr/bin/env python3
import os
from huggingface_hub import HfApi

token = os.environ.get("HF_TOKEN")
if not token:
    raise ValueError("❌ HF_TOKEN environment variable is missing!")

repo_id = "elsiddik/zz"
api = HfApi()

print(f"1. Creating/Verifying Hugging Face Dataset repository: {repo_id}...")
api.create_repo(repo_id=repo_id, repo_type="dataset", token=token, exist_ok=True)

readme_content = """---
license: apache-2.0
task_categories:
- text-generation
- text2text-generation
language:
- en
- code
tags:
- cybersecurity
- vulnerability-detection
- cve
- code-audit
- code-repair
size_categories:
- 100K<n<1M
---

# FineSec-212k Master Security Dataset

**FineSec-212k** is a high-precision, large-scale cybersecurity dataset containing **212,759 training examples** designed for fine-tuning security LLMs on code auditing, CVE analysis, and secure code refactoring.

## Dataset Structure

1. **112,759 Real-World NVD CVE Advisories**: Complete National Vulnerability Database vulnerability advisory records with primary CWE annotations.
2. **100,000 Multi-Language Code Snippets & Patches**: Vulnerable code vs. secure patch refactor pairs across **Python, C, C++, JavaScript, Go, Java, PHP, Bash, and Solidity**.

## Usage with Hugging Face Datasets

```python
from datasets import load_dataset

dataset = load_dataset('elsiddik/zz', split='train')
print(f'Total records: {len(dataset)}')
```
"""

print("2. Uploading dataset README.md...")
api.upload_file(
    path_or_fileobj=readme_content.encode("utf-8"),
    path_in_repo="README.md",
    repo_id=repo_id,
    repo_type="dataset",
    token=token
)

dataset_file = "data/training_data_200k.jsonl"
print(f"3. Uploading {dataset_file} (286 MB) to {repo_id}...")
api.upload_file(
    path_or_fileobj=dataset_file,
    path_in_repo="training_data_200k.jsonl",
    repo_id=repo_id,
    repo_type="dataset",
    token=token
)

print(f"✅ Successfully uploaded 212,759 sample dataset to https://huggingface.co/datasets/{repo_id}!")
