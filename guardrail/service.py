import asyncio
import os
from transformers import pipeline
import torch
import time
import socket
from dotenv import load_dotenv
import logging

logging.getLogger().setLevel(logging.INFO)

load_dotenv() # Load env vars from .env file

class PromptInjectionDetector:
    def __init__(self, device=None, max_retries=3):
        if device is None:
            device = 0 if torch.cuda.is_available() else -1
        
        model_name = 'protectai/deberta-v3-base-prompt-injection-v2'
        
        for attempt in range(max_retries):
            try:
                logging.info(f"Attempt {attempt + 1}/{max_retries}: Loading model...")
                
                # Set longer timeout
                socket.setdefaulttimeout(120)  # 2 minutes
                
                self.pipe = pipeline(
                    "text-classification",
                    model=model_name,
                    device=device,
                    truncation=True,
                    max_length=512
                )
                logging.info("✓ Model loaded successfully!")
                return
                
            except Exception as e:
                logging.error(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 5
                    logging.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise Exception(f"Failed after {max_retries} attempts: {e}")
    
    def check_prompt(self, text, threshold=0.5):
        """
        Check if a prompt contains injection attempts
        
        Args:
            text: The user input to check
            threshold: Confidence threshold (0-1) for flagging injections
        
        Returns:
            dict: Contains 'is_injection', 'label', 'score', and 'confidence'
        """
        if not text or not text.strip():
            return {
                'is_injection': False,
                'label': 'SAFE',
                'score': 0.0,
                'confidence': 'high'
            }
        
        try:
            result = self.pipe(text)[0]
            
            # ProtectAI model uses 'INJECTION' and 'SAFE' labels
            is_injection = (
                'INJECTION' in result['label'].upper() and 
                result['score'] > threshold
            )
            
            # Determine confidence level
            if result['score'] > 0.9:
                confidence = 'very_high'
            elif result['score'] > 0.7:
                confidence = 'high'
            elif result['score'] > 0.5:
                confidence = 'medium'
            else:
                confidence = 'low'
            
            return {
                'is_injection': is_injection,
                'label': result['label'],
                'score': round(result['score'], 4),
                'confidence': confidence,
                'safe': not is_injection
            }
        except Exception as e:
            logging.error(f"Error checking prompt: {e}")
            return {
                'is_injection': False,
                'label': 'ERROR',
                'score': 0.0,
                'confidence': 'unknown',
                'error': str(e)
            }

try:
    from .policy_engine import PolicyEngine
    from .compliance import ComplianceChecker
except ImportError:
    from policy_engine import PolicyEngine
    from compliance import ComplianceChecker

class Guardrail:
    def __init__(self):
        # Initialize Hugging Face model
        logging.info("Initializing Guardrail Service...")
        try:
            self.detector = PromptInjectionDetector()
            self.policy_engine = PolicyEngine()
            self.compliance_checker = ComplianceChecker()
            logging.info("Guardrail Service Initialized")
        except Exception as e:
            logging.error(f"Failed to initialize Guardrail: {e}")
            self.detector = None
            self.policy_engine = None
            self.compliance_checker = None


    async def check_content_policy(self, prompt: str) -> dict:
        # Simulate LLM/Cloud call
        await asyncio.sleep(1)
        return {"check": "content_policy", "status": "pass", "details": "No policy violation"}

    async def check_pii(self, prompt: str) -> dict:
        # Simulate PII detection
        await asyncio.sleep(1)
        return {"check": "pii", "status": "pass", "details": "No PII detected"}

    async def check_prompt_injection(self, prompt: str) -> dict:
        if self.detector:
            # Run in thread pool to avoid blocking async loop since transformers is CPU bound
            # We wrap the synchronous check_prompt call
            result = await asyncio.to_thread(self.detector.check_prompt, prompt)
            
            status = "pass"
            if result['is_injection']:
                 status = "fail"
            
            return {
                "check": "prompt_injection",
                "status": status,
                "label": result['label'],
                "score": result['score'],
                "details": f"Model classified as {result['label']} (Confidence: {result['confidence']})"
            }
        else:
            return {"check": "prompt_injection", "status": "error", "details": "Model not loaded"}

    async def check_regional_compliance(self, prompt: str) -> dict:
        if self.compliance_checker:
            # Run in thread pool as it involves network calls and possibly heavy processing
            result = await asyncio.to_thread(self.compliance_checker.check_regional_compliance, prompt)
            return result
        else:
             return {"error": "ComplianceChecker not initialized"}

    async def validate(self, prompt: str, region: str = "Others") -> dict:
        # Run all checks concurrently
        content_policy_task = self.check_content_policy(prompt)
        # pii_task = self.check_pii(prompt)
        injection_task = self.check_prompt_injection(prompt)
        compliance_task = self.check_regional_compliance(prompt)
        
        results = await asyncio.gather(
            content_policy_task,
            # pii_task,
            injection_task,
            compliance_task
        )
        logging.info(f"Results: {results}")
        content_res, injection_res, compliance_res = results
        
        # Policy Engine Evaluation
        policy_decision = self.policy_engine.evaluate(
            injection_result=injection_res,
            compliance_results=compliance_res,
            user_region=region
        )
        
        return {
            "checks": {
                "content_policy": content_res,
                # "pii": pii_res,
                "prompt_injection": injection_res,
                "regional_compliance": compliance_res
            },
            "policy_decision": policy_decision,
            "overall_status": "pass" if policy_decision["decision"] == "accept" else "fail"
        }

