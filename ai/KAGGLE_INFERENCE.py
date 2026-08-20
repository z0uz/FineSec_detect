#!/usr/bin/env python3
"""
Complete Kaggle Notebook Code - Copy & Paste This Entire File
Use your Hugging Face model on Kaggle for vulnerability detection
"""

# ============================================================================
# STEP 1: Install Dependencies
# ============================================================================
print("📦 Installing dependencies...")
import subprocess
subprocess.run(["pip", "install", "-q", "transformers", "peft", "bitsandbytes", "accelerate", "torch"], check=True)
print("✅ Dependencies installed!\n")

# ============================================================================
# STEP 2: Load Model from Hugging Face
# ============================================================================
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

print("🔧 Loading model from Hugging Face...")
print("   This may take 2-3 minutes on first run...\n")

# Load base model
base_model_name = "deepseek-ai/deepseek-coder-1.3b-instruct"
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_name,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

# Load your LoRA adapter from Hugging Face
model = PeftModel.from_pretrained(
    base_model,
    "elsiddik/pentest-vulnerability-detector"
)

print("✅ Model loaded successfully!\n")

# ============================================================================
# STEP 3: Define Analysis Function
# ============================================================================
def analyze_vulnerability(code_snippet, max_length=300):
    """
    Analyze code for security vulnerabilities
    
    Args:
        code_snippet: Code to analyze
        max_length: Maximum response length
        
    Returns:
        Analysis result as string
    """
    prompt = f"""System: You are a security expert analyzing code for vulnerabilities.

User: Analyze this code for security vulnerabilities:

{code_snippet}

Assistant:"""
    
    # Tokenize
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    # Generate
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_length,
            temperature=0.7,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
    
    # Decode
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Extract assistant response
    if "Assistant:" in response:
        response = response.split("Assistant:")[-1].strip()
    
    return response

# ============================================================================
# STEP 4: Test Examples
# ============================================================================
print("="*70)
print("🧪 TESTING MODEL WITH VULNERABILITY EXAMPLES")
print("="*70)

# Test 1: SQL Injection
print("\n" + "="*70)
print("Test 1: SQL Injection")
print("="*70)
sql_code = "SELECT * FROM users WHERE id = '" + "user_input" + "'"
print(f"\nCode: {sql_code}")
print("\nAnalysis:")
print(analyze_vulnerability(sql_code))

# Test 2: XSS
print("\n" + "="*70)
print("Test 2: Cross-Site Scripting (XSS)")
print("="*70)
xss_code = "document.write('<div>' + userInput + '</div>')"
print(f"\nCode: {xss_code}")
print("\nAnalysis:")
print(analyze_vulnerability(xss_code))

# Test 3: Command Injection
print("\n" + "="*70)
print("Test 3: Command Injection")
print("="*70)
cmd_code = "os.system('ping ' + userInput)"
print(f"\nCode: {cmd_code}")
print("\nAnalysis:")
print(analyze_vulnerability(cmd_code))

# Test 4: Path Traversal
print("\n" + "="*70)
print("Test 4: Path Traversal")
print("="*70)
path_code = "file_path = '/uploads/' + filename\nopen(file_path, 'r')"
print(f"\nCode: {path_code}")
print("\nAnalysis:")
print(analyze_vulnerability(path_code))

print("\n" + "="*70)
print("✅ ALL TESTS COMPLETE!")
print("="*70)

# ============================================================================
# STEP 5: Interactive Analysis (Optional)
# ============================================================================
print("\n" + "="*70)
print("💡 INTERACTIVE MODE")
print("="*70)
print("\nYou can now analyze your own code:")
print("\nExample:")
print('  result = analyze_vulnerability("your_code_here")')
print('  print(result)')
print("\nOr use the function in your Kaggle notebook!")
print("\n" + "="*70)
