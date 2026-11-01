package mcp.authz

import rego.v1

# Tool -> realm role required to invoke it.
tool_roles := {
	"get_customers": "crm-user",
	"delete_customer": "crm-user",
	"get_orders": "orders-user",
}

default allow := false

roles := object.get(input.token, "roles", [])

# Protocol-level calls (initialize, tools/list, ping, notifications) only need a valid token.
allow if {
	input.token.active == true
	input.rpc.method != "tools/call"
}

# Tool invocations need the role mapped to the tool. Unknown tools are denied.
allow if {
	input.token.active == true
	input.rpc.method == "tools/call"
	required := tool_roles[input.rpc.tool]
	required in roles
}

reason := "token inactive" if not input.token.active == true

reason := sprintf("unknown tool '%s'", [input.rpc.tool]) if {
	input.token.active == true
	input.rpc.method == "tools/call"
	not tool_roles[input.rpc.tool]
}

reason := sprintf("user '%s' lacks role '%s' for tool '%s'", [input.token.username, tool_roles[input.rpc.tool], input.rpc.tool]) if {
	input.token.active == true
	input.rpc.method == "tools/call"
	required := tool_roles[input.rpc.tool]
	not required in roles
}
