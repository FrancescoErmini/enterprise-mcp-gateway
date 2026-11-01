# 🚀 Enterprise GenAI Gateway (Architettura Micro-MCP)

![Architecture](https://img.shields.io/badge/Architecture-Micro--MCP-blue) ![Security](https://img.shields.io/badge/Security-Zero_Trust-green) ![Protocol](https://img.shields.io/badge/Protocol-MCP_(Model_Context_Protocol)-orange) ![Platform](https://img.shields.io/badge/Platform-Kubernetes-326ce5) ![Auth](https://img.shields.io/badge/Auth-OAuth2_Token_Exchange-purple)

## 📌 Panoramica del Progetto

Questo repository definisce un pattern architetturale enterprise per l'integrazione sicura, scalabile e *Zero-Trust* di Agenti AI (LLMs) all'interno di un ecosistema aziendale Kubernetes (K8s).

Il progetto risolve il problema dell'integrazione N×M tra modelli AI e applicazioni di business frammentate, implementando il **Model Context Protocol (MCP)** in una topologia decentralizzata. Sfruttando **Kong**, **Keycloak** e **Open Policy Agent (OPA)**, il sistema elimina il rischio di *Confused Deputy* (attacchi via Prompt Injection) garantendo che l'Agente AI operi esclusivamente delegando l'identità dell'utente richiedente (On-Behalf-Of Delegation).

---

## 🏗️ Architettura di Sistema

```text
                            L'INGRESSO AI
                                  |
                                  v
+-----------------------------------------------------------------------+
|                              AL AGENTS                                |
|                                                                       |
|  [ User JWT (Subject: User) ]  --IMPERSONIFICA--> [ Chat UI ]         |
|                                                          |            |
|                                                          v            |
|                                                     [ AI Agent ]      |
|                                                          |            |
|  (On-Behalf-Of Delegation: ACTS ON BEHALF OF (RFC 8693)) |            |
+----------------------------------------------------------|------------+
                                                           |
                                 MCP Protocol (JSON-RPC)   |
  Delegated JWT (Subject: User + Actor: AI)                |
  Delegated Request                                        v
+-----------------------------------------------------------------------+
|                        IL GATEWAY DI SICUREZZA                        |
|                          (Central Security)                           |
|                                                                       |
|                   +---------------------------+                       |
|                   |                           |                       |
|                   |      KONG API Gateway     |                       |
|                   |                           |                       |
|                   +-------------+-------------+                       |
|                                 | Validazione Token & Policy          |
|                                 v                                     |
|                   +---------------------------+                       |
|                   |        OPA (Policy)       |                       |
|                   +-------------+-------------+                       |
|                                 | Validazione Token & Policy          |
|                                 v                                     |
|                   +---------------------------+                       |
|                   |       Keycloak (Auth)     |                       |
|                   +---------------------------+                       |
|                                                                       |
+---------------------------------|-------------------------------------+
                                  |
+---------------------------------|-------------------------------------+
|                  I COMPLESSI APPLICATIVI VERTICALI                    |
|                      (Custom Apps & Backends)                         |
|                                 |                                     |
|                                 | CRM DOMAIN                          |
|                                 v                                     |
|  +----------------+      REST API with       +-----------------+      |
|  |                |      Delegated JWT       |                 |      |
|  | CRM MCP Server |------------------------->| CRM Backend API |      |
|  |                |      (Operates as User)  |                 |      |
|  +----------------+                          +--------+--------+      |
|                                                       |               |
|                                Row-Level Security)    |               |
|                                basati sull'identità   v               |
|                                dell'utente delegato +-----------+     |
|                                                     |    CRM    |     |
|                                                     |  Database |     |
|                                                     +-----------+     |
|                                                                       |
|                                 | ORDERS DOMAIN                       |
|                                 v                                     |
|  +-------------------+   REST API with       +--------------------+   |
|  |                   |   Delegated JWT       |                    |   |
|  | Orders MCP Server |---------------------->| Orders Backend API |   |
|  |                   |   (Operates as User)  |                    |   |
|  +-------------------+                       +---------+----------+   |
|                                                        |              |
|                                 Controlli di sicurezza |              |
|                                 (Row-Level Security)   v              |
|                                 basati sull'identità +-----------+    |
|                                 dell'utente delegato |   Orders  |    |
|                                                      |  Database |    |
|                                                      +-----------+    |
+-----------------------------------------------------------------------+
                                  K8S Cluster


# ==========================================
# DEFINIZIONE COMPONENTI ARCHITETTURALI
# ==========================================
shared_infrastructure:
  kong_api_gateway:
    role: "Entry point globale (PEP - Policy Enforcement Point base)"
    features: 
      - "Routing dinamico basato su namespace o header"
      - "Gestione del Tool Registry in-memory (O(1) lookup latency)"
      - "Rate limiting globale per gli agenti AI"
      
  keycloak_idp:
    role: "Identity & Access Management Broker"
    features: 
      - "Supporto nativo OAuth2 Token Exchange (RFC 8693)"
      - "Emissione di token delegati (User come Subject, AI come Actor)"
      
  opa_central:
    role: "PDP (Policy Decision Point) Centralizzato"
    features: 
      - "Host del motore Rego per Policy-as-Code"
      - "Decisioni ABAC (Attribute-Based Access Control) senza stato"

domain_level_architecture:
  opa_guard_sidecar:
    role: "PEP (Policy Enforcement Point) di Dominio"
    action: "Intercetta il payload MCP, estrae il JWT, interroga OPA, blocca richieste malevole"
    
  micro_mcp_server:
    role: "Traduttore di Protocollo Stateless"
    action: "Converte JSON-RPC (MCP) in REST API, propaga l'Authorization Header al target"
    
  target_api_backend:
    role: "Sorgente di Verità e Logica di Business"
    action: "Valida il JWT delegato, applica Row-Level Security nativa (RBAC/ABAC del DB)"



# ==========================================
# PSEUDO-CODICE DEL FLUSSO END-TO-END
# ==========================================
def handle_ai_mcp_request(http_request, delegated_user_jwt):
    
    # 1. Routing Dinamico (Kong Gateway)
    domain_guard = kong.route_to_upstream(http_request.path) # es. routing a crm-opa-guard
    
    try:
        # 2. Deep Payload Inspection (OPA Guard Sidecar)
        mcp_payload = domain_guard.extract_json_rpc(http_request.body)
        
        # 3. Valutazione ABAC (Central OPA)
        is_allowed = opa.evaluate_policy(
            token_claims = delegated_user_jwt.decode(),
            mcp_tool     = mcp_payload.get("name"),       # es. "delete_customer"
            mcp_args     = mcp_payload.get("arguments")   # es. {"id": 123, "region": "EU"}
        )
        
        if not is_allowed:
            raise SecurityException("Accesso negato: policy OPA fallita sui parametri forniti")
            
        # 4. Esecuzione Delegata (Micro-MCP -> Backend)
        rest_api_response = micro_mcp_server.translate_and_execute(
            mcp_payload, 
            auth_header = f"Bearer {delegated_user_jwt}"
        )

        return format_mcp_response(rest_api_response)

    except Exception as e:
        return mcp_error_response(e.message)


# 1. Clona il repository
git clone [https://github.com/tuo-org/enterprise-mcp-gateway.git](https://github.com/tuo-org/enterprise-mcp-gateway.git)
cd enterprise-mcp-gateway

# 2. Avvia l'infrastruttura in background
docker-compose up -d

# 3. Esegui il bootstrap delle migrazioni database per Kong
docker-compose run --rm kong-bootstrap

# 4. Verifica lo stato dei container
docker-compose ps
# MCP demo

1. `docker compose up -d`
2. `DECK_WEATHERAPI_LOCAL_KEY=mcp-test-key-2026 deck gateway sync kong/weather-api-deck.yaml`
3. Configure Keycloak realm `mcp`, client `mcp`, user `testuser01` / password `testuser01` (or reuse your own secrets)
4. `cd mcp-client && python client.py --grant-type password`
