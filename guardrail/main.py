from fastapi import FastAPI, Request
from pydantic import BaseModel
import requests
import ipaddress
from enum import Enum
try:
    from .service import Guardrail
except ImportError:
    try:
        from service import Guardrail
    except ImportError:
        from guardrail.service import Guardrail
import contextlib

# Global instance
guardrail_service = None

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    global guardrail_service
    guardrail_service = Guardrail()
    yield

app = FastAPI(lifespan=lifespan)

class Prompt(BaseModel):
    prompt: str

class RegionCategory(str, Enum):
    INDIA = "India"
    USA = "USA"
    EU = "EU"
    OTHERS = "Others"

# List of EU country codes (approximate)
EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"
}

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        return response.json().get("ip")
    except requests.RequestException:
        return None

def determine_category(country_code: str) -> RegionCategory:
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

@app.post("/analyze")
async def analyze_prompt(prompt: Prompt, request: Request):
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
        pass # Invalid IP format
    
    country_code = None
    country_name = "Unknown"
    
    try:
        # Request fields: status, country, countryCode, regionName
        response = requests.get(f"http://ip-api.com/json/{ip_to_check}")
        response.raise_for_status()
        geoip_data = response.json()
        
        if geoip_data.get("status") == "success":
             country_code = geoip_data.get("countryCode")
             country_name = geoip_data.get("country", "Unknown")
             
    except requests.RequestException:
        pass # Maintain defaults
    
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
        "region_category": category,
        "guardrail_results": guardrail_results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)