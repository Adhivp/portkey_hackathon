import os
import logging
import asyncio
from typing import List, Dict
from compliance import ComplianceChecker
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WeeklyPipeline")

load_dotenv()

def fetch_weekly_failures() -> List[str]:
    """
    Simulates fetching failures from the last week.
    In a real scenario, this would query a database or parse logs 
    for interactions marked as 'unsatisfactory' or 'failed'.
    
    Returns:
        List of strings, where each string is a description of a failure 
        that should be added to the Internal policy.
    """
    logger.info("Fetching weekly failures...")
    
    # Simulated failures
    # These represent "bad" things that happened or new rules we want to enforce internally
    failures = [
        "Employees should not share internal server IP addresses in public chats.",
        "Discussions about 'Project Chimera' are strictly forbidden outside of the secure room.",
        "Do not share customer PII (Personally Identifiable Information) in plain text, even for debugging.",
        "Avoid using authorized credentials in example code snippets."
    ]
    
    return failures

def run_weekly_pipeline():
    """
    Main function to run the weekly pipeline.
    """
    logger.info("Starting Weekly Compliance Update Pipeline")
    
    checker = ComplianceChecker()
    
    # 1. Fetch Failures
    failures = fetch_weekly_failures()
    
    if not failures:
        logger.info("No failures found for this week. Exiting.")
        return

    logger.info(f"Found {len(failures)} failures to process.")

    # 2. Process and Upload to Vector DB
    success_count = 0
    for failure_text in failures:
        # We treat the failure description as a new policy rule
        # Category is 'Internal' by default in add_policy
        logger.info(f"Adding policy: {failure_text[:50]}...")
        success = checker.add_policy(text=failure_text, category="Internal")
        
        if success:
            success_count += 1
        else:
            logger.error(f"Failed to add policy: {failure_text[:30]}...")
            
    logger.info("--------------------------------------------------")
    logger.info(f"Pipeline Complete. Successfully added {success_count}/{len(failures)} policies.")
    logger.info("These policies will now be 'Always Checked' by the guardrail system.")
    logger.info("--------------------------------------------------")

if __name__ == "__main__":
    run_weekly_pipeline()
    
