from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests
import ipaddress
from enum import Enum
from typing import Optional, Dict, Any
import os
from portkey_ai import Portkey
import contextlib

try:
    from .service import Guardrail
except ImportError:
    try:
        from service import Guardrail
    except ImportError:
        from guardrail.service import Guardrail

# Global instance
guardrail_service = None

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    global guardrail_service
    guardrail_service = Guardrail()
    yield

app = FastAPI(title="Guardrail22 - AI Security Gateway", lifespan=lifespan)

# Setup templates
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Pydantic models
class Prompt(BaseModel):
    prompt: str

class AIRequest(BaseModel):
    prompt: str
    model: str
    max_tokens: Optional[int] = 512
    system_prompt: Optional[str] = "You are a helpful assistant."

class RegionCategory(str, Enum):
    INDIA = "India"
    USA = "USA"
    EU = "EU"
    OTHERS = "Others"

# List of EU country codes
EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", 
    "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"
}

def get_public_ip():
    """Get the public IP address"""
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        return response.json().get("ip")
    except requests.RequestException:
        return None

def determine_category(country_code: str) -> RegionCategory:
    """Determine region category based on country code"""
    if not country_code:
        return RegionCategory.OTHERS
    
    code = country_code.upper()
    if code == "IN":
        return RegionCategory.INDIA
    elif code == "US":
        return RegionCategory.USA
    elif code in EU_COUNTRIES:
        return RegionCategory.EU
    else:
        return RegionCategory.OTHERS

def get_geo_info(ip_address: str) -> tuple:
    """Get geographical information from IP address"""
    country_code = None
    country_name = "Unknown"
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        response.raise_for_status()
        geoip_data = response.json()
        
        if geoip_data.get("status") == "success":
            country_code = geoip_data.get("countryCode")
            country_name = geoip_data.get("country", "Unknown")
    except requests.RequestException:
        pass
    
    return country_code, country_name

# Initialize Portkey client
portkey_client = None
try:
    api_key = os.getenv("PORTKEY_API_KEY", "0yr**********************JtV")
    portkey_client = Portkey(api_key=api_key)
except Exception as e:
    print(f"Warning: Portkey client initialization failed: {e}")

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the main UI page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze")
async def analyze_prompt(prompt: Prompt, request: Request):
    """Analyze a prompt through the guardrail system"""
    client_host = request.client.host
    
    # Check if IP is private or loopback
    ip_to_check = client_host
    try:
        ip_obj = ipaddress.ip_address(client_host)
        if ip_obj.is_private or ip_obj.is_loopback:
            public_ip = get_public_ip()
            if public_ip:
                ip_to_check = public_ip
    except ValueError:
        pass
    
    country_code, country_name = get_geo_info(ip_to_check)
    category = determine_category(country_code)
    
    # Run Guardrail checks
    if guardrail_service:
        guardrail_results = await guardrail_service.validate(prompt.prompt, region=category.value)
    else:
        guardrail_results = {"error": "Guardrail service not initialized"}
    
    return {
        "received_prompt": prompt.prompt,
        "client_ip": client_host,
        "resolved_ip_for_geo": ip_to_check,
        "country_detected": country_name,
        "region_category": category.value,
        "guardrail_results": guardrail_results
    }

@app.post("/api/ai/chat")
async def ai_chat(ai_request: AIRequest, request: Request):
    """
    Send a chat request to AI model through Portkey with guardrail protection
    """
    if not portkey_client:
        raise HTTPException(status_code=500, detail="Portkey client not initialized. Please set PORTKEY_API_KEY.")
    
    # First, run guardrail check
    client_host = request.client.host
    ip_to_check = client_host
    
    try:
        ip_obj = ipaddress.ip_address(client_host)
        if ip_obj.is_private or ip_obj.is_loopback:
            public_ip = get_public_ip()
            if public_ip:
                ip_to_check = public_ip
    except ValueError:
        pass
    
    country_code, country_name = get_geo_info(ip_to_check)
    category = determine_category(country_code)
    
    # Run Guardrail checks
    if guardrail_service:
        guardrail_results = await guardrail_service.validate(ai_request.prompt, region=category.value)
    else:
        return {
            "error": "Guardrail service not initialized",
            "status": "error"
        }
    
    # Check if guardrail rejected the prompt
    policy_decision = guardrail_results.get("policy_decision", {})
    if policy_decision.get("decision") == "reject":
        return {
            "status": "rejected",
            "reason": policy_decision.get("reason"),
            "details": policy_decision.get("details"),
            "guardrail_results": guardrail_results
        }
    
    # If passed, send to AI model
    try:
        response = portkey_client.chat.completions.create(
            model=ai_request.model,
            messages=[
                {"role": "system", "content": ai_request.system_prompt},
                {"role": "user", "content": guardrail_results.get("anonymized_prompt", ai_request.prompt)}
            ],
            max_tokens=ai_request.max_tokens
        )
        
        return {
            "status": "success",
            "model": ai_request.model,
            "response": response.choices[0].message.content,
            "guardrail_results": guardrail_results,
            "metadata": {
                "country": country_name,
                "region": category.value
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI model error: {str(e)}")

@app.get("/api/models")
async def get_available_models():
    """Get list of available AI models"""
    return {
        "models": [
            {
                "id": "@openai/gpt-4-turbo-2024-04-09",
                "name": "GPT-4 Turbo",
                "provider": "OpenAI"
            },
            {
                "id": "@openai/gpt-3.5-turbo",
                "name": "GPT-3.5 Turbo",
                "provider": "OpenAI"
            },
            {
                "id": "@anthropic/claude-sonnet-4-5",
                "name": "Claude Sonnet 4.5",
                "provider": "Anthropic"
            },
            {
                "id": "@grok/grok-4-latest",
                "name": "Grok 4",
                "provider": "xAI"
            },
            {
                "id": "@vertex-global/gemini-3-pro-preview",
                "name": "Gemini 3 Pro",
                "provider": "Google"
            }
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "guardrail_service": "active" if guardrail_service else "inactive",
        "portkey_client": "active" if portkey_client else "inactive"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
