import asyncio
import os
from transformers import pipeline
import torch
import time
import socket
import hashlib
import json
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import logging

logging.getLogger().setLevel(logging.INFO)

load_dotenv() # Load env vars from .env file


class MockLLM:
    """A mock LLM that simply echoes the prompt back."""
    async def generate_response(self, prompt: str) -> str:
        # Simulate network latency
        await asyncio.sleep(0.5)
        # Echo the prompt as a simple mock response
        return f"Response to: {prompt}"

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
            # Initialize Presidio
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
            self.llm = MockLLM()
            logging.info("Guardrail Service Initialized")
        except Exception as e:
            logging.error(f"Failed to initialize Guardrail: {e}")
            self.detector = None
            self.policy_engine = None
            self.compliance_checker = None
            self.analyzer = None
            self.anonymizer = None
            self.llm = None

    def _hash_text(self, text):
        """Create a SHA256 hash of the text."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    async def analyze_and_anonymize_pii(self, prompt: str):
        """
        Analyze prompt for PII using Presidio.
        Returns:
            - anonymized_prompt (str)
            - pii_mapping (dict): hash -> original_text
            - entities_found (list)
        """
        if not self.analyzer:
             return prompt, {}, []

        # Run CPU-bound analysis in a thread
        def _analyze_sync():
            results = self.analyzer.analyze(text=prompt, language="en")
            
            if not results:
                return prompt, {}, []

            pii_mapping = {}
            hash_to_original = {}
            
            # Create mappings
            for result in results:
                original_text = prompt[result.start:result.end]
                hash_value = self._hash_text(original_text)
                
                pii_mapping[hash_value] = original_text
                hash_to_original[original_text] = hash_value
            
            # Create operators for anonymization
            operators = {}
            for result in results:
                original_text = prompt[result.start:result.end]
                hash_value = hash_to_original[original_text]
                
                operators[result.entity_type] = OperatorConfig(
                    "replace",
                    {"new_value": hash_value}
                )
            
            anonymized_result = self.anonymizer.anonymize(
                text=prompt,
                analyzer_results=results,
                operators=operators
            )
            
            entities_info = [{
                "type": r.entity_type,
                "text": prompt[r.start:r.end],
                "score": r.score
            } for r in results]

            return anonymized_result.text, pii_mapping, entities_info

        return await asyncio.to_thread(_analyze_sync)

    def _deanonymize_response(self, text: str, mapping: dict) -> str:
        """Replace hash values back with original text."""
        result = text
        logging.info(f"Mapping: {mapping}")
        for hash_val, original in mapping.items():
            result = result.replace(hash_val, original)
        return result


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
        # 1. PII Anonymization
        logging.info("Step 1: PII Analysis")
        anonymized_prompt, pii_mapping, entities = await self.analyze_and_anonymize_pii(prompt)
        
        logging.info(f"Anonymized Prompt: {anonymized_prompt}")
        logging.info(f"PII Entities Found: {len(entities)}")

        # 2. Run Checks on Anonymized Prompt
        content_policy_task = self.check_content_policy(anonymized_prompt)
        injection_task = self.check_prompt_injection(anonymized_prompt)
        compliance_task = self.check_regional_compliance(anonymized_prompt)
        
        results = await asyncio.gather(
            content_policy_task,
            injection_task,
            compliance_task
        )
        
        content_res, injection_res, compliance_res = results
        
        # 3. Policy Engine Evaluation
        policy_decision = self.policy_engine.evaluate(
            injection_result=injection_res,
            compliance_results=compliance_res,
            user_region=region
        )
        
        final_response = None
        
        # 4. Target LLM & Deanonymization (only if accepted)
        if policy_decision["decision"] == "accept":
            # Call Mock LLM with ANONYMIZED prompt
            llm_response = await self.llm.generate_response(anonymized_prompt)
            
            # Deanonymize the response
            logging.info(f"LLM Response: {llm_response}")
            final_response = self._deanonymize_response(llm_response, pii_mapping)
            logging.info(f"Deanonymized Response: {final_response}")

        return {
            "original_prompt": prompt,
            "anonymized_prompt": anonymized_prompt,
            "pii_entities": entities,
            "checks": {
                "content_policy": content_res,
                "prompt_injection": injection_res,
                "regional_compliance": compliance_res
            },
            "policy_decision": policy_decision,
            "overall_status": "pass" if policy_decision["decision"] == "accept" else "fail",
            "llm_response": final_response
        }

