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

```

---

## ▶️ Demo eseguibile

### 1. Come mettere in vita la demo

Prerequisiti: Docker con Compose v2 (su Windows va bene anche Docker dentro WSL) e Python 3 solo per lo script di test.

```bash
# (opzionale, solo per la chat AI) chiave OpenAI: il file è ignorato da git
echo "OPENAI_API_KEY=sk-..." > .env        # opzionale: OPENAI_MODEL=gpt-4o-mini (default)

docker compose up --build -d              # build + avvio di tutti i servizi
docker compose ps                         # verifica che siano tutti "running"
```

Keycloak impiega circa un minuto per importare il realm `mcp-demo`. Per fermare tutto: `docker compose down`; per ripartire da zero (necessario se cambi `keycloak/realm-export.json`, che viene importato solo a database vuoto): `docker compose down -v`.

| Servizio | URL host | Note |
|---|---|---|
| Frontend (login + chiamate dirette alle API) | http://localhost:3000 | |
| **Chat AI** (OpenAI + tool MCP, JWT dell'utente) | http://localhost:3001 | richiede `OPENAI_API_KEY` |
| Keycloak | http://localhost:8080 | admin / admin |
| Kong proxy (`/mcp/crm`, `/mcp/orders`) | http://localhost:8000 | |
| CRM API / Orders API | http://localhost:8001 / :8002 | |
| OPA | http://localhost:8181 | |

Utenti (password `test`):

| Utente | Ruoli | Può fare |
|---|---|---|
| `mario.sales` | `crm-user` | leggere i clienti (`crm_get_customers`); **non** cancellare, **non** vedere Orders |
| `anna.admin` | `crm-user`, `crm-admin` | leggere e cancellare clienti (`crm_delete_customer`) |
| `luigi.finance` | `orders-user` | leggere gli ordini (`orders_get_orders`); nessun accesso al CRM |

Client Keycloak: `frontend-web` (public), `mcp-gateway` (secret `mcp-secret-123`, usato dai guard per l'introspection).

Flusso: Agente -> Kong -> OPA Guard (introspection + policy OPA sul tool JSON-RPC) -> Micro-MCP -> API REST con lo stesso JWT.
#### Tool Registry, namespace e routing

- **Namespace obbligatorio**: ogni tool ha il prefisso della sua app (`crm_get_customers`, `crm_delete_customer`, `orders_get_orders`), così app diverse non possono collidere.
- **Tool Registry** (`opa/policies/data.json`, caricato da OPA come `data.tool_registry`): mappa ogni tool a `app` e `roles_required`. La policy `opa/policies/mcp.rego` non contiene ruoli: cerca il tool nel registry, verifica che appartenga al dominio chiamato e che l'utente abbia almeno uno dei ruoli richiesti. Il file è in `opa/policies/`, già montato su `/policies` nel container OPA, e viene ricaricato a caldo (`--watch`): per esporre un nuovo tool o cambiare i ruoli basta modificare una riga, senza toccare agente o policy.
- **Filtro dinamico di `tools/list`**: il guard chiede a OPA `allowed_tools` e restituisce all'agente solo i tool permessi all'utente (mario vede solo `crm_get_customers`; su Orders non vede nulla). Una `tools/call` verso un tool non permesso resta comunque negata (403).
- **Routing deterministico** (`kong/kong.yml`, niente scatter-gather): il prefisso del tool decide la rotta, quindi `crm_get_customers` -> `POST /mcp/crm` -> `crm-opa-guard:8090`, `orders_get_orders` -> `POST /mcp/orders` -> `orders-opa-guard:8090`. Il client di test e la chat usano la stessa mappa prefisso -> path.

Policy: `opa/policies/mcp.rego`. Test: `docker run --rm -v "$PWD/opa/policies:/p" openpolicyagent/opa:1.4.1 test /p -v`.
Kong gira in DB-less con `kong/kong.yml`; Postgres serve solo a Keycloak.

### 2. Come provarla

**Da UI - Chat AI (http://localhost:3001)**
1. Clicca *Login* e accedi come `mario.sales` / `test`.
2. Scrivi *"Elenca i clienti del CRM"*: l'agente chiama `crm_get_customers`; sotto la risposta trovi il riquadro espandibile con la chiamata MCP e il risultato.
3. Scrivi *"Mostrami gli ordini"* o *"Cancella il cliente 1"*: mario non ha i tool `orders_get_orders` / `crm_delete_customer` (il guard li ha filtrati da `tools/list`), quindi l'agente risponde che non può farlo.
4. Logout, entra come `anna.admin` / `test` e scrivi *"Cancella il cliente 2, confermo"*: ora `crm_delete_customer` è disponibile e il cliente viene cancellato (l'agente chiede conferma prima).
5. Logout, entra come `luigi.finance` / `test`: vede solo gli ordini.
6. Per far vedere un 403 vero, usa lo script da riga di comando (sotto): chiama direttamente i tool negati.

**Da UI - Frontend semplice (http://localhost:3000)**
Login, poi i bottoni *Chiama CRM API* / *Chiama Orders API* chiamano direttamente le API REST con il token (senza passare da MCP): 200 se hai il ruolo, 403 altrimenti.

**Da riga di comando - simulatore di agente AI**
```bash
pip install -r tests/requirements.txt
python tests/test_mcp_client.py          # mario.sales -> crm_get_customers
python tests/test_mcp_client.py --all    # + scenari di autorizzazione: 403 su tool non permessi, 401 senza token, tools/list filtrato per utente
```

### 3. Come analizzare i log

Ogni componente scrive su stdout, quindi si legge con `docker compose logs`.

```bash
docker compose logs -f                              # tutto, in streaming
docker compose logs -f --tail 20 kong crm-opa-guard     # alcuni servizi, ultime 20 righe
docker compose logs --no-log-prefix --since 2m chat # senza prefisso e solo ultimi 2 minuti
docker compose logs crm-opa-guard | grep -E "DENY|ALLOW"
```

Servizi: `kong`, `crm-opa-guard`, `orders-opa-guard`, `opa`, `crm-mcp`, `orders-mcp`, `crm-api`, `orders-api`, `chat`, `keycloak`, `postgres`, `frontend`.

Cosa cercare lungo il percorso di una richiesta (consiglio: `docker compose logs -f chat kong crm-opa-guard opa crm-mcp crm-api` in un terminale mentre usi la chat):

| Servizio | Cosa mostra |
|---|---|
| `chat` | messaggio utente, tool scoperti via Kong, risposta di OpenAI (`tool_calls` / `final answer`), chiamata MCP e risultato |
| `kong` | access log: `POST /mcp/crm 200` o `403`, con `kong_request_id` |
| `crm-opa-guard` / `orders-opa-guard` | `OPA decision user=... roles=... method=tools/call tool=... -> ALLOW/DENY (motivo)`, `401` per token mancante/inattivo, inoltro al micro-MCP |
| `opa` | decision log JSON: `input` completo e `result` di ogni valutazione (`allow`, `reason`) |
| `crm-mcp` / `orders-mcp` | traduzione tool -> REST con conferma che il JWT è propagato (`JWT forwarded: True`) e status del backend |
| `crm-api` / `orders-api` | `ALLOW user=... role=...` oppure `DENY 401/403` con il motivo (validazione firma JWT e ruolo) |
| `keycloak` | eventi: `type="LOGIN"` (login utente) e `type="INTROSPECT_TOKEN"` (verifica token fatta dai guard con `mcp-gateway`) |

Esempio di richiesta negata (`mario.sales` -> `crm_delete_customer`, provocabile con `python tests/test_mcp_client.py --all`), visibile in sequenza:
```text
kong             "POST /mcp/crm HTTP/1.1" 403
crm-opa-guard    OPA decision user=mario.sales roles=['crm-user'] method=tools/call tool=crm_delete_customer -> DENY (user 'mario.sales' lacks any of roles ["crm-admin"] for tool 'crm_delete_customer')
```
La richiesta si ferma al guard: `crm-mcp` e `crm-api` non vedono nulla. Il filtro di `tools/list` è visibile nel log del guard: `tools/list filtered: 2 -> 1 visible=['crm_get_customers']`.

Per filtrare l'output JSON di OPA: `docker compose logs --no-log-prefix opa | grep decision_id`.
