"""
Simple Kaggle Example - Copy This to Test Your Model
No errors, ready to run!
"""

# Install dependencies
import subprocess
subprocess.run(["pip", "install", "-q", "transformers", "peft", "bitsandbytes", "accelerate"], check=True)

# Load model
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

print("🔧 Loading model...")

base_model = AutoModelForCausalLM.from_pretrained(
    "deepseek-ai/deepseek-coder-1.3b-instruct",
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)

tokenizer = AutoTokenizer.from_pretrained(
    "deepseek-ai/deepseek-coder-1.3b-instruct",
    trust_remote_code=True
)

model = PeftModel.from_pretrained(
    base_model,
    "elsiddik/pentest-vulnerability-detector"
)

print("✅ Model loaded!\n")

# Analysis function
def analyze_vulnerability(code_snippet):
    """Analyze code for vulnerabilities"""
    prompt = f"""System: You are a security expert.

User: Analyze this code:

{code_snippet}

Assistant:"""
    
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=300,
            temperature=0.7,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
    
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    if "Assistant:" in response:
        response = response.split("Assistant:")[-1].strip()
    
    return response

# Test examples (NO ERRORS!)
print("="*70)
print("🧪 TESTING VULNERABILITY DETECTION")
print("="*70)

# Example 1: SQL Injection
print("\n" + "="*70)
print("Example 1: SQL Injection")
print("="*70)
code1 = "query = 'SELECT * FROM users WHERE id=' + request.GET['id']"
print(f"Code: {code1}")
print("\nAnalysis:")
print(analyze_vulnerability(code1))

# Example 2: XSS
print("\n" + "="*70)
print("Example 2: Cross-Site Scripting")
print("="*70)
code2 = "output = '<div>' + user_data + '</div>'"
print(f"Code: {code2}")
print("\nAnalysis:")
print(analyze_vulnerability(code2))

# Example 3: Command Injection
print("\n" + "="*70)
print("Example 3: Command Injection")
print("="*70)
code3 = "subprocess.call('ping ' + hostname, shell=True)"
print(f"Code: {code3}")
print("\nAnalysis:")
print(analyze_vulnerability(code3))

print("\n" + "="*70)
print("✅ ALL TESTS COMPLETE!")
print("="*70)
print("\nYou can now use: analyze_vulnerability('your_code_here')")
print("="*70)
