from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from auth import require_role

app = FastAPI(title="CRM API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

CUSTOMERS = {
    1: {"id": 1, "name": "Acme S.p.A.", "city": "Milano", "tier": "gold"},
    2: {"id": 2, "name": "Globex S.r.l.", "city": "Torino", "tier": "silver"},
    3: {"id": 3, "name": "Initech", "city": "Roma", "tier": "bronze"},
}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/customers")
def list_customers(claims: dict = Depends(require_role("crm-user"))):
    return {"requested_by": claims.get("preferred_username"), "customers": list(CUSTOMERS.values())}


@app.delete("/api/customers/{customer_id}")
def delete_customer(customer_id: int, claims: dict = Depends(require_role("crm-user"))):
    if customer_id not in CUSTOMERS:
        raise HTTPException(404, f"Customer {customer_id} not found")
    deleted = CUSTOMERS.pop(customer_id)
    return {"deleted_by": claims.get("preferred_username"), "deleted": deleted}
