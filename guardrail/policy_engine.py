from enum import Enum
from typing import Dict, Any, List
import logging

class PolicyDecision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"

class PolicyEngine:
    def __init__(self):
        pass

    def evaluate(self, injection_result: Dict[str, Any], compliance_results: Dict[str, str], user_region: str) -> Dict[str, Any]:
        """
        Evaluate the safety of the prompt based on injection score and regional compliance.
        
        Args:
            injection_result: Result from PromptInjectionDetector
            compliance_results: Dictionary of region -> pass/fail/not_checked status
            user_region: The region the user is coming from (e.g. 'USA', 'EU', 'India', 'Internal')
            
        Returns:
            Dict containing decision, reason, and details
        """
        
        # 1. Check Injection Score
        # If it's a high confidence injection, reject immediately
        if injection_result.get('status') in ['fail']:
            return {
                "decision": PolicyDecision.REJECT,
                "reason": "High confidence prompt injection detected",
                "details": f"Injection Status: {injection_result.get('status')}"
            }

        # 2. Check Regional Compliance
        # If the user's region failed the compliance check, reject
        # We normalize keys to ensure matching (assuming region names match keys in compliance_results)
        
        # Mapping user_region to compliance keys if necessary, or assuming direct match
        # compliance_results keys example: 'EU', 'USA', 'India', 'Internal'
        
        # region_key = "EU"
        region_key = user_region
        # Handle 'Others' or unknown regions by mapping them or defaulting
        if region_key not in compliance_results and region_key != "Others":
             # fallback or Strict mode? For now, if region not found in compliance keys, we might treat as 'Internal' or skip?
             # User requirement: "complied if resgion is same as violation we will rjeect rpomt"
             pass
        logging.info(f"Compliance check for region: {region_key}")
        if region_key in compliance_results:
            status = compliance_results[region_key]
            if status == "not-passed":
                 return {
                    "decision": PolicyDecision.REJECT,
                    "reason": f"Compliance check failed for region: {user_region}",
                    "details": f"Region {user_region} status: {status}"
                }
        
        # Default Accept
        return {
            "decision": PolicyDecision.ACCEPT,
            "reason": "Passed all policy checks",
            "details": "Safe"
        }
