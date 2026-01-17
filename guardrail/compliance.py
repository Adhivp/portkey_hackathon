import os
import json
import re
import logging
from portkey_ai import Portkey
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import VectorizedQuery

logger = logging.getLogger(__name__)

class ComplianceChecker:
    def __init__(self):
        self.portkey_api_key = os.getenv("PORTKEY_API_KEY")
        self.search_endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
        self.search_key = os.getenv("AZURE_SEARCH_KEY")
        self.index_name = "guardrails-policies-index"

        if not self.portkey_api_key:
            logger.warning("PORTKEY_API_KEY not found. Compliance checks may fail.")
        
        if not self.search_endpoint or not self.search_key:
            logger.warning("Azure Search credentials not found. Compliance checks may fail.")

        try:
            self.portkey = Portkey(api_key=self.portkey_api_key)
        except Exception as e:
            logger.error(f"Failed to initialize Portkey: {e}")
            self.portkey = None

    def assess_risk(self, user_prompt):
        """
        LLM1: Analyze user prompt and return risk assessment and data classification.
        """
        if not self.portkey:
            logger.error("Portkey client not initialized.")
            return None

        logger.info("LLM1: Starting Risk Assessment")
        
        system_prompt = """You are an AI risk assessment expert. Analyze the user's input and determine:
1. Risk Assessment: Identify if the use case involves any of these risks
2. Data Classification: Identify what types of data are involved

Return your response as a valid JSON object with this exact structure:
{
    "risk_assessment": {
        "biometric_processing": false,
        "surveillance": false,
        "real_time_tracking": false,
        "privacy_invasion": false,
        "extortion_or_coercion": false,
        "reidentification": false,
        "children_data": false,
        "sensitive_attribute_inference": false
    },
    "data_classification": {
        "personal_data": false,
        "sensitive_data": false,
        "biometric_data": false
    },
    "evidence": {
        "biometric_processing": [],
        "surveillance": [],
        "privacy_invasion": [],
        "extortion_or_coercion": [],
        "reidentification": []
    }
}

Set each field to true if the risk/data type is present, false otherwise.
Add specific evidence strings to the evidence arrays for identified risks."""
        
        try:
            response = self.portkey.chat.completions.create(
                model="@openai/gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=1024
            )
            
            # Note: Portkey might look like OpenAI client structure
            llm1_output = response.choices[0].message.content
            logger.info("LLM1 Response received")
            
            # Extract JSON from markdown if present
            json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', llm1_output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = llm1_output
            
            # Parse JSON response
            assessment = json.loads(json_str.strip())
            return assessment
        
        except Exception as e:
            logger.error(f"Error calling LLM1: {e}")
            return None

    def generate_search_query(self, assessment):
        """
        Generate search query strings from risk assessment data.
        """
        if not assessment:
            return ""

        logger.info("Generating Search Query")
        
        search_terms = []
        
        # Extract active risks and create policy-focused terms
        risk_assessment = assessment.get("risk_assessment", {})
        for risk_type, is_active in risk_assessment.items():
            if is_active:
                # Convert to policy-relevant search terms
                readable_term = risk_type.replace("_", " ")
                search_terms.append(f"{readable_term} policy")
                search_terms.append(f"{readable_term} regulation")
        
        # Extract data classifications with policy context
        data_classification = assessment.get("data_classification", {})
        for data_type, is_present in data_classification.items():
            if is_present:
                readable_term = data_type.replace("_", " ")
                search_terms.append(f"{readable_term} protection")
                search_terms.append(f"{readable_term} compliance")
        
        # Add general compliance terms
        policy_terms = [
            "prohibited activities",
            "restricted use",
            "compliance requirements",
            "privacy protection",
            "data protection regulations"
        ]
        
        search_terms.extend(policy_terms)
        
        # Create focused search query (limit to most relevant terms)
        enhanced_query = " ".join(search_terms[:15])  # Limit to avoid overly long queries
        
        logger.info(f"Generated Search Query: {enhanced_query}")
        return enhanced_query

    def create_embedding(self, query_text):
        """
        Create embedding for the search query using Portkey.
        """
        if not self.portkey:
            return None

        try:
            response = self.portkey.embeddings.create(
                input=query_text,
                model="@openai/text-embedding-ada-002",
                encoding_format="float"
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Error creating query embedding: {e}")
            return None

    def search_policies(self, query_embedding, top_k=5):
        """
        Search Azure AI Search index using vector search.
        """
        if not self.search_endpoint or not self.search_key:
            return []

        logger.info("RAG: Searching Azure AI Search Index")
        
        try:
            search_client = SearchClient(
                endpoint=self.search_endpoint,
                index_name=self.index_name,
                credential=AzureKeyCredential(self.search_key)
            )
            
            # Ensure query_embedding is a list
            if not isinstance(query_embedding, list):
                query_embedding = list(query_embedding)
            
            # Create vector query
            vector_query = VectorizedQuery(
                vector=query_embedding,
                k_nearest_neighbors=top_k,
                fields="embedding"
            )
            
            # We are not applying category filter here as per current requirement integration, 
            # or maybe we should passthrough? The user prompt had it. 
            # I will omit 'filter' for now or default to all, as step 1 integration only mentioned check_regional_compliance returning dict.
            # Adding category filtering would require knowing which category to filter for, 
            # but check_regional_compliance needs to return status for ALL regions effectively.
            # Actually, the user's `check_regional_compliance` signature was `(prompt: str) -> dict`.
            # And it returned status for USA, EU, India, Internal.
            # So likely we need to NOT filter by category during search to get policies for ALL regions, 
            # OR we rely on LLM2 to figure it out from context.
            # The original code allowed filtering but default was "all". I'll use no filter (equivalent to all).

            results = search_client.search(
                search_text=None,
                vector_queries=[vector_query],
                top=top_k,
                select=["chunk_id", "content", "chunk_index"],
                include_total_count=True
            )
            
            retrieved_docs = []
            for result in results:
                doc = {
                    "chunk_id": result.get("chunk_id"),
                    "content": result.get("content"),
                    "chunk_index": result.get("chunk_index"),
                    "score": result.get("@search.score")
                }
                retrieved_docs.append(doc)
            
            return retrieved_docs
        
        except Exception as e:
            logger.error(f"Error searching index: {e}")
            return []

    def check_compliance(self, user_prompt, assessment, retrieved_docs):
        """
        LLM2: Determine compliance status based on risk assessment and retrieved policies.
        """
        if not self.portkey:
            return None

        logger.info("LLM2: Compliance Assessment")
        
        # Prepare context from retrieved documents
        context = "\n\n".join([
            f"Policy Excerpt {i+1}:\n{doc['content']}" 
            for i, doc in enumerate(retrieved_docs)
        ])
        
        system_prompt = """You are a legal compliance expert. Based on the user's use case, risk assessment, and relevant policy excerpts, determine compliance status for different jurisdictions.

Return your response as a valid JSON object with this exact structure:
{
    "EU": "passed" | "not-passed" | "unchecked",
    "USA": "passed" | "not-passed" | "unchecked",
    "India": "passed" | "not-passed" | "unchecked",
    "Internal": "passed" | "not-passed" | "unchecked",
    "reasoning": {
        "EU": "explanation",
        "USA": "explanation",
        "India": "explanation",
        "Internal": "explanation"
    }
}

Use:
- "passed" if the use case is compliant with regulations or allowed
- "not-passed" if the use case violates regulations
- "unchecked" if there's insufficient information to determine compliance

Note: The output keys "India" matches the 'IN' requirement from prompt but generalized to full name as per existing service.py output format if needed. 
Wait, the original user code used "IN". The service.py uses "India". I will convert or ask LLM to output "India".
I will use "India" to match service.py expected keys.
"""
        # Adjusted JSON keys to match service.py expected output structure which uses "India" not "IN"
        
        user_message = f"""Use Case: {user_prompt}

Risk Assessment:
{json.dumps(assessment, indent=2)}

Relevant Policy Excerpts:
{context}

Determine compliance status for EU, USA, India, and Internal policies."""
        
        try:
            response = self.portkey.chat.completions.create(
                model="@openai/gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=1024
            )
            
            llm2_output = response.choices[0].message.content
            logger.info("LLM2 Response received")
            
            # Extract JSON from markdown if present
            json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', llm2_output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = llm2_output
            
            # Parse JSON response
            compliance = json.loads(json_str.strip())
            return compliance
        
        except Exception as e:
            logger.error(f"Error calling LLM2: {e}")
            return None

    def check_regional_compliance(self, prompt: str) -> dict:
        """
        Orchestrate the full compliance check flow.
        """
        # Step 1: Assess Risk
        assessment = self.assess_risk(prompt)
        if not assessment:
            return {"error": "Risk assessment failed"}

        # Step 2: Generate Search Query
        search_query = self.generate_search_query(assessment)
        
        # Step 3: Create Embedding
        query_embedding = self.create_embedding(search_query)
        if not query_embedding:
             return {"error": "Embedding creation failed"}

        # Step 4: Search Policies
        retrieved_docs = self.search_policies(query_embedding)
        
        # Step 5: Check Compliance
        compliance_result = self.check_compliance(prompt, assessment, retrieved_docs)
        
        if not compliance_result:
             return {"error": "Compliance check failed"}
             
        return compliance_result