package mcp.authz

import rego.v1

# No roles are hardcoded here: tool -> app / roles_required comes from data.tool_registry
# (opa/policies/data.json, hot-reloaded by OPA --watch).

default allow := false

roles := object.get(input.token, "roles", [])

# Protocol-level calls (initialize, tools/list, ping, notifications) only need a valid token.
allow if {
	input.token.active == true
	input.rpc.method != "tools/call"
}

# Tool invocations: the tool must be registered for the domain being called, and the user
# must hold at least one of the roles required by the registry entry.
allow if {
	input.token.active == true
	input.rpc.method == "tools/call"
	entry := data.tool_registry[input.rpc.tool]
	entry.app == input.domain
	some required in entry.roles_required
	required in roles
}

# Tools the user may see/use on this domain (used by the guard to filter tools/list).
allowed_tools := {name |
	some name, entry in data.tool_registry
	entry.app == input.domain
	some required in entry.roles_required
	required in roles
}

reason := "token inactive" if not input.token.active == true

reason := sprintf("unknown tool '%s'", [input.rpc.tool]) if {
	input.token.active == true
	input.rpc.method == "tools/call"
	not data.tool_registry[input.rpc.tool]
}

reason := sprintf("tool '%s' belongs to app '%s', not '%s'", [input.rpc.tool, entry.app, input.domain]) if {
	input.token.active == true
	input.rpc.method == "tools/call"
	entry := data.tool_registry[input.rpc.tool]
	entry.app != input.domain
}

reason := sprintf("user '%s' lacks any of roles %v for tool '%s'", [input.token.username, entry.roles_required, input.rpc.tool]) if {
	input.token.active == true
	input.rpc.method == "tools/call"
	entry := data.tool_registry[input.rpc.tool]
	entry.app == input.domain
	not user_has_required_role(entry)
}

user_has_required_role(entry) if {
	some required in entry.roles_required
	required in roles
}
