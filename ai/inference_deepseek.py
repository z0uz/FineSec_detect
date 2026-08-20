#!/usr/bin/env python3
"""
FineSec Vulnerability Analysis Inference Engine
Supports Qwen2.5-Coder-7B, DeepSeek-Coder (1.3B/6.7B), and arbitrary PEFT/LoRA security models.
Auto-detects base model configurations and parses structured JSON security reports.
"""

import os
import json
import torch
import argparse
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

SYSTEM_PROMPT = (
    "You are an expert security engineer and vulnerability researcher. "
    "Analyze the provided code or security report for security vulnerabilities. "
    "Respond strictly with a valid JSON object matching this schema:\n"
    "{\n"
    '  "is_vulnerable": boolean,\n'
    '  "cwe": string,\n'
    '  "vulnerability_type": string,\n'
    '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",\n'
    '  "vulnerable_lines": array of strings,\n'
    '  "explanation": string,\n'
    '  "remediation": string\n'
    "}"
)

class VulnerabilityAnalyzer:
    """Analyze code using trained Security LLM (PEFT/LoRA)"""
    
    def __init__(self, model_path, base_model=None):
        """
        Initialize analyzer with auto-detection of base model path from adapter_config.json
        """
        print(f"🔧 Loading model adapter from {model_path}...")
        
        # Auto-detect base model if not explicitly specified
        if not base_model:
            adapter_config_file = os.path.join(model_path, "adapter_config.json")
            if os.path.exists(adapter_config_file):
                with open(adapter_config_file, "r") as f:
                    config = json.load(f)
                    base_model = config.get("base_model_name_or_path")
                    print(f"🔍 Auto-detected base model: {base_model}")
        
        if not base_model:
            base_model = "Qwen/Qwen2.5-Coder-7B-Instruct"
        
        # Load Tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_path if os.path.exists(os.path.join(model_path, "tokenizer_config.json")) else base_model,
            trust_remote_code=True
        )
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Load Base Model
        print(f"🤖 Loading base model weights for {base_model}...")
        self.base_model = AutoModelForCausalLM.from_pretrained(
            base_model,
            device_map="auto",
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            trust_remote_code=True
        )
        
        # Attach LoRA adapter
        print(f"⚡ Merging LoRA adapter from {model_path}...")
        self.model = PeftModel.from_pretrained(self.base_model, model_path)
        self.model.eval()
        
        print("✅ Vulnerability Analyzer initialized successfully!")

    def analyze(self, code, max_new_tokens=512):
        """Analyze code for vulnerabilities"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this code snippet for security vulnerabilities:\n\n```\n{code}\n```"}
        ]
        
        # Format via tokenizer template
        if hasattr(self.tokenizer, "apply_chat_template"):
            prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt = f"System: {SYSTEM_PROMPT}\n\nUser: {code}\n\nAssistant:"

        inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024).to(self.model.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=0.2,
                do_sample=False,
                repetition_penalty=1.1
            )

        full_response = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()
        
        # Attempt to parse JSON response
        try:
            # Clean markdown formatting if present
            cleaned = full_response
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned:
                cleaned = cleaned.split("```")[1].split("```")[0].strip()
            
            parsed_json = json.loads(cleaned)
            return parsed_json
        except Exception:
            return {"raw_response": full_response}

def main():
    parser = argparse.ArgumentParser(description="Analyze code with trained Security LLM")
    parser.add_argument("--model", required=True, help="Path to trained model adapter directory")
    parser.add_argument("--base_model", default=None, help="Base model override")
    parser.add_argument("--code", help="Code string to analyze")
    parser.add_argument("--file", help="File containing code to analyze")
    
    args = parser.parse_args()
    analyzer = VulnerabilityAnalyzer(args.model, base_model=args.base_model)

    code_to_analyze = args.code
    if args.file and os.path.exists(args.file):
        with open(args.file, "r") as f:
            code_to_analyze = f.read()

    if not code_to_analyze:
        print("Please provide --code or --file argument.")
        return

    result = analyzer.analyze(code_to_analyze)
    print("\n" + "=" * 60)
    print("📊 Security Analysis Result:")
    print("=" * 60)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
