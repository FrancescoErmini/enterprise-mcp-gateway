from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth import require_role

app = FastAPI(title="Orders API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ORDERS = [
    {"id": 1001, "customer_id": 1, "total": 1250.00, "status": "shipped"},
    {"id": 1002, "customer_id": 2, "total": 310.50, "status": "pending"},
    {"id": 1003, "customer_id": 1, "total": 99.90, "status": "delivered"},
]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/orders")
def list_orders(claims: dict = Depends(require_role("orders-user"))):
    return {"requested_by": claims.get("preferred_username"), "orders": ORDERS}
