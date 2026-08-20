#!/usr/bin/env python3
"""
AI-Powered Vulnerability Explainer using Ollama DeepSeek
Provides detailed explanations, impact analysis, and remediation guidance
"""

import requests
import json
from typing import Dict, Optional
from src.core.base import logger


class AIVulnerabilityExplainer:
    """Explains vulnerabilities using Ollama DeepSeek model"""
    
    def __init__(self, model: str = "deepseek-v3.1:671b-cloud", ollama_url: str = "http://localhost:11434"):
        """
        Initialize AI explainer
        
        Args:
            model: Ollama model to use (default: deepseek-v3.1:671b-cloud)
            ollama_url: Ollama API endpoint
        """
        self.model = model
        self.ollama_url = ollama_url
        self.api_endpoint = f"{ollama_url}/api/generate"
        
    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Call Ollama API with the given prompt
        
        Args:
            prompt: The prompt to send to the model
            
        Returns:
            Model response or None if error
        """
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,  # Lower temperature for more focused responses
                    "top_p": 0.9,
                }
            }
            
            response = requests.post(
                self.api_endpoint,
                json=payload,
                timeout=60  # Longer timeout for complex explanations
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return None
                
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama. Make sure Ollama is running (ollama serve)")
            return None
        except requests.exceptions.Timeout:
            logger.error("Ollama request timed out")
            return None
        except Exception as e:
            logger.error(f"Error calling Ollama: {e}")
            return None
    
    def explain_vulnerability(self, vuln_data: Dict) -> Optional[str]:
        """
        Get detailed explanation of a vulnerability
        
        Args:
            vuln_data: Dictionary containing vulnerability details
            
        Returns:
            Detailed explanation or None if error
        """
        vuln_type = vuln_data.get('type', 'Unknown')
        severity = vuln_data.get('severity', 'Unknown')
        
        # Build context-specific prompt
        prompt = self._build_explanation_prompt(vuln_data)
        
        print(f"\n🤖 AI Analysis in progress...")
        response = self._call_ollama(prompt)
        
        if response:
            return self._format_explanation(response, vuln_type, severity)
        return None
    
    def _build_explanation_prompt(self, vuln_data: Dict) -> str:
        """Build a detailed prompt for the AI model"""
        vuln_type = vuln_data.get('type', 'Unknown')
        severity = vuln_data.get('severity', 'Unknown')
        evidence = vuln_data.get('evidence', 'No evidence provided')
        payload = vuln_data.get('payload', 'N/A')
        parameter = vuln_data.get('parameter', 'N/A')
        endpoint = vuln_data.get('endpoint', vuln_data.get('url', 'N/A'))
        
        prompt = f"""You are a cybersecurity expert analyzing a vulnerability found during penetration testing.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Severity: {severity}
- Endpoint: {endpoint}
- Parameter: {parameter}
- Payload Used: {payload}
- Evidence: {evidence}

Please provide a comprehensive security analysis with the following sections:

1. VULNERABILITY EXPLANATION (2-3 sentences)
   - What is this vulnerability?
   - Why is it dangerous?

2. ATTACK SCENARIO (2-3 sentences)
   - How could an attacker exploit this?
   - What could they achieve?

3. EXPLOITATION GUIDE (DETAILED - for verification/testing)
   Provide step-by-step instructions to manually verify this vulnerability:
   - Exact curl commands or browser steps
   - What to look for in the response
   - How to confirm it's a real vulnerability vs false positive
   - Multiple exploitation techniques if applicable
   - Expected output for successful exploitation
   
   Format as:
   Step 1: [Action]
   Command: [Exact command]
   Expected: [What you should see]
   
   Step 2: [Action]
   Command: [Exact command]
   Expected: [What you should see]

4. FALSE POSITIVE CHECK (2-3 sentences)
   - How to determine if this is a false positive
   - What responses indicate it's NOT exploitable
   - Common false positive patterns for this vulnerability type

5. BUSINESS IMPACT (2-3 sentences)
   - What data/systems are at risk?
   - What are the potential consequences?

6. TECHNICAL DETAILS (2-3 sentences)
   - What's happening at the code level?
   - Why did the payload work?

7. REMEDIATION STEPS (3-5 concrete steps)
   - Immediate actions to take
   - Long-term fixes
   - Best practices to implement

8. CODE EXAMPLE (if applicable)
   - Show vulnerable code pattern
   - Show secure code pattern

Keep the response clear, actionable, and focused on practical security guidance.
Format the response with clear section headers and bullet points."""

        return prompt
    
    def _format_explanation(self, response: str, vuln_type: str, severity: str) -> str:
        """Format the AI response for display"""
        separator = "=" * 80
        
        formatted = f"\n{separator}\n"
        formatted += f"🤖 AI SECURITY ANALYSIS - {vuln_type} ({severity})\n"
        formatted += f"{separator}\n\n"
        formatted += response
        formatted += f"\n\n{separator}\n"
        
        return formatted
    
    def explain_scan_summary(self, total_tests: int, vulnerabilities_found: int, vuln_types: list) -> Optional[str]:
        """
        Provide summary analysis of the entire scan
        
        Args:
            total_tests: Number of tests performed
            vulnerabilities_found: Number of vulnerabilities found
            vuln_types: List of vulnerability types found
            
        Returns:
            Summary analysis or None if error
        """
        if vulnerabilities_found == 0:
            prompt = f"""You are a cybersecurity expert reviewing penetration test results.

SCAN RESULTS:
- Total Tests Performed: {total_tests}
- Vulnerabilities Found: 0
- Status: SECURE

Provide a brief (3-4 sentences) positive security assessment explaining:
1. What this means for the application's security posture
2. Why continuous testing is still important
3. Recommended next steps for maintaining security

Keep it encouraging but professional."""
        else:
            prompt = f"""You are a cybersecurity expert reviewing penetration test results.

SCAN RESULTS:
- Total Tests Performed: {total_tests}
- Vulnerabilities Found: {vulnerabilities_found}
- Vulnerability Types: {', '.join(vuln_types)}

Provide a brief (4-5 sentences) security assessment explaining:
1. The overall security risk level
2. Which vulnerabilities should be prioritized
3. The urgency of remediation
4. General recommendations

Keep it clear and actionable."""
        
        print(f"\n🤖 Generating scan summary...")
        response = self._call_ollama(prompt)
        
        if response:
            separator = "=" * 80
            formatted = f"\n{separator}\n"
            formatted += "🤖 AI SCAN SUMMARY\n"
            formatted += f"{separator}\n\n"
            formatted += response
            formatted += f"\n\n{separator}\n"
            return formatted
        return None
    
    def check_connection(self) -> bool:
        """
        Check if Ollama is accessible
        
        Returns:
            True if connected, False otherwise
        """
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                
                # Check if our model is available
                if any(self.model in name for name in model_names):
                    return True
                else:
                    logger.warning(f"Model '{self.model}' not found in Ollama")
                    logger.info(f"Available models: {', '.join(model_names)}")
                    logger.info(f"To pull the model, run: ollama pull {self.model}")
                    return False
            return False
        except:
            return False


def test_ai_explainer():
    """Test the AI explainer with a sample vulnerability"""
    explainer = AIVulnerabilityExplainer()
    
    # Check connection
    if not explainer.check_connection():
        print("❌ Cannot connect to Ollama. Please ensure:")
        print("   1. Ollama is installed: https://ollama.ai")
        print("   2. Ollama is running: ollama serve")
        print(f"   3. Model is pulled: ollama pull deepseek-v3.1:671b-cloud")
        return
    
    print("✅ Connected to Ollama successfully!\n")
    print("Testing with sample SQL injection vulnerability...")
    print("This will show you the NEW exploitation guide format.\n")
    
    # Test with sample vulnerability
    sample_vuln = {
        'type': 'SQLI_PII',
        'severity': 'CRITICAL',
        'endpoint': '/api/users',
        'parameter': 'id',
        'payload': "1' UNION SELECT username,password,email FROM users--",
        'evidence': 'PII data detected in response'
    }
    
    explanation = explainer.explain_vulnerability(sample_vuln)
    if explanation:
        print(explanation)
        print("\n" + "="*80)
        print("✅ The AI now provides:")
        print("   1. Vulnerability explanation")
        print("   2. Attack scenario")
        print("   3. 🆕 EXPLOITATION GUIDE (step-by-step with commands)")
        print("   4. 🆕 FALSE POSITIVE CHECK (how to verify)")
        print("   5. Business impact")
        print("   6. Technical details")
        print("   7. Remediation steps")
        print("   8. Code examples")
        print("="*80)


if __name__ == "__main__":
    test_ai_explainer()
