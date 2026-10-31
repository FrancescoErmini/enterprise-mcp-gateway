package mcp

import rego.v1

default allow := false

# ---- Configuration (edit to match your environment) ----
allowed_issuers := {
  "http://localhost:8081/realms/mcp",
}

allowed_clients := {
  "mcp",
}

# Choose one approach for users:
# A) allowlist of usernames
allowed_users := {
  "testuser01",
}

# B) allowlist of emails (optional)
allowed_emails := {
  "fermini@menarini.it",
}

# ---- Helpers ----
now_s := time.now_ns() / 1000000000

client_id := input.token.azp if input.token.azp
client_id := input.token.client_id if input.token.client_id  # some introspection payloads

username := input.token.preferred_username if input.token.preferred_username
email := input.token.email if input.token.email

valid_issuer if allowed_issuers[input.token.iss]

valid_client if allowed_clients[client_id]

valid_user if allowed_users[username]
valid_user if allowed_emails[email]

not_expired if {
  # Only enforce exp if present (JWT has it; introspection sometimes uses "exp" too)
  not input.token.exp
} else if {
  input.token.exp > now_s
}

# Optional: require token active if you're passing introspection response
active if {
  not input.token.active
} else if {
  input.token.active == true
}

# Optional: role check (Keycloak JWT typically has realm_access.roles)
has_role(role) if {
  roles := input.token.realm_access.roles
  roles[_] == role
}

# ---- Main decision ----
allow if {
  valid_issuer
  active
  not_expired
  valid_client
  valid_user

  # Optional: require a role
  # has_role("uma_authorization")

  # Optional: authorize by HTTP request
  # input.request.http.method == "POST"
  # input.request.http.path == "/mcp"
}
