import asyncio
import logging
import socket
import time
from uuid import uuid4
from typing import Dict, Any

import torch
from transformers import pipeline
from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine

from policy_engine import PolicyEngine
from compliance import ComplianceChecker

# --------------------------------------------------
# Setup
# --------------------------------------------------

logging.getLogger().setLevel(logging.INFO)
load_dotenv()
socket.setdefaulttimeout(120)

# --------------------------------------------------
# Mock LLM
# --------------------------------------------------

class MockLLM:
    async def generate_response(self, prompt: str) -> str:
        await asyncio.sleep(0.3)
        return f"Response to: {prompt}"

# --------------------------------------------------
# Prompt Injection Detector (DEEPSET-CORRECT)
# --------------------------------------------------

INJECTION_KEYWORDS = [
    "ignore previous",
    "ignore all rules",
    "forget all rules",
    "forget your rules",
    "do what i say",
    "you must obey",
    "system prompt",
    "developer message",
    "bypass",
    "jailbreak",
    "act as",
]

def has_override_intent(text: str) -> bool:
    text = text.lower()
    return any(k in text for k in INJECTION_KEYWORDS)

class PromptInjectionDetector:
    def __init__(self, device=None, max_retries=3):
        if device is None:
            device = 0 if torch.cuda.is_available() else -1

        self.model_name = "deepset/deberta-v3-base-injection"

        for attempt in range(max_retries):
            try:
                logging.info(
                    f"Attempt {attempt + 1}/{max_retries}: Loading {self.model_name}"
                )

                self.pipe = pipeline(
                    "text-classification",
                    model=self.model_name,
                    device=device,
                    truncation=True,
                    max_length=512,
                )

                logging.info("✓ Injection model loaded")
                return

            except Exception as e:
                logging.error(f"Attempt {attempt + 1} failed: {e}")
                time.sleep((attempt + 1) * 5)

        raise RuntimeError("Failed to load injection model")

    def check_prompt(self, text: str, threshold: float = 0.8) -> Dict[str, Any]:
        if not text.strip():
            return {
                "is_injection": False,
                "label": "LEGIT",
                "score": 0.0,
                "confidence": "high",
                "override_intent": False,
            }

        result = self.pipe(text)[0]

        label = result["label"]     # LEGIT / INJECTION
        score = result["score"]
        override = has_override_intent(text)

        # 🚨 REAL jailbreak
        if label == "INJECTION" and score >= threshold and override:
            return {
                "is_injection": True,
                "label": label,
                "score": round(score, 4),
                "confidence": "very_high",
                "override_intent": True,
            }

        # ⚠️ Suspicious but no control intent
        if label == "INJECTION" and score >= threshold:
            return {
                "is_injection": False,
                "label": label,
                "score": round(score, 4),
                "confidence": "medium",
                "override_intent": False,
            }

        # ✅ Legit
        return {
            "is_injection": False,
            "label": label,
            "score": round(score, 4),
            "confidence": "high",
            "override_intent": False,
        }

# --------------------------------------------------
# Guardrail Core
# --------------------------------------------------

class Guardrail:
    def __init__(self):
        logging.info("Initializing Guardrail Service...")

        self.detector = PromptInjectionDetector()
        self.policy_engine = PolicyEngine()
        self.compliance_checker = ComplianceChecker()

        self.analyzer = AnalyzerEngine()
        self.llm = MockLLM()

        logging.info("✓ Guardrail Service Initialized")

    # --------------------------------------------------
    # PII Anonymization (SPAN-SAFE)
    # --------------------------------------------------

    async def analyze_and_anonymize_pii(self, text: str):
        def _sync():
            results = self.analyzer.analyze(text=text, language="en")
            if not results:
                return text, {}, []

            # RIGHT → LEFT to avoid index shifts
            results = sorted(results, key=lambda r: r.start, reverse=True)

            anonymized = text
            mapping: Dict[str, str] = {}

            for idx, r in enumerate(results):
                original = text[r.start:r.end]
                token = f"<<PII_{r.entity_type}_{idx}_{uuid4().hex[:6]}>>"
                mapping[token] = original
                anonymized = anonymized[:r.start] + token + anonymized[r.end:]

            entities = [
                {"type": r.entity_type, "text": text[r.start:r.end], "score": r.score}
                for r in results
            ]

            return anonymized, mapping, entities

        return await asyncio.to_thread(_sync)

    def deanonymize(self, text: str, mapping: Dict[str, str]) -> str:
        for token, original in mapping.items():
            text = text.replace(token, original)
        return text

    # --------------------------------------------------
    # Checks
    # --------------------------------------------------

    async def check_prompt_injection(self, prompt: str) -> Dict[str, Any]:
        result = await asyncio.to_thread(self.detector.check_prompt, prompt)

        status = "pass"
        if result["is_injection"] and result["override_intent"]:
            status = "fail"

        return {
            "check": "prompt_injection",
            "status": status,
            "label": result["label"],
            "score": result["score"],
            "override_intent": result["override_intent"],
            "details": f"confidence={result['confidence']}",
        }

    async def check_content_policy(self, prompt: str) -> Dict[str, Any]:
        await asyncio.sleep(0.2)
        return {"check": "content_policy", "status": "pass"}

    async def check_regional_compliance(self, prompt: str) -> Dict[str, Any]:
        return await asyncio.to_thread(
            self.compliance_checker.check_regional_compliance, prompt
        )

    # --------------------------------------------------
    # Main Validation
    # --------------------------------------------------

    async def validate(self, prompt: str, region: str = "Others") -> Dict[str, Any]:
        anonymized_prompt, pii_mapping, entities = await self.analyze_and_anonymize_pii(
            prompt
        )

        content_task = self.check_content_policy(anonymized_prompt)
        injection_task = self.check_prompt_injection(anonymized_prompt)
        compliance_task = self.check_regional_compliance(anonymized_prompt)

        content_res, injection_res, compliance_res = await asyncio.gather(
            content_task, injection_task, compliance_task
        )

        policy_decision = self.policy_engine.evaluate(
            injection_result=injection_res,
            compliance_results=compliance_res,
            user_region=region,
        )

        llm_response = None
        if policy_decision["decision"] == "accept":
            raw = await self.llm.generate_response(anonymized_prompt)
            llm_response = self.deanonymize(raw, pii_mapping)

        return {
            "original_prompt": prompt,
            "anonymized_prompt": anonymized_prompt,
            "pii_entities": entities,
            "checks": {
                "content_policy": content_res,
                "prompt_injection": injection_res,
                "regional_compliance": compliance_res,
            },
            "policy_decision": policy_decision,
            "overall_status": policy_decision["decision"],
            "llm_response": llm_response,
        }
