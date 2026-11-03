package mcp.authz_test

import rego.v1

import data.mcp.authz

registry := {
	"crm_get_customers": {"app": "crm", "roles_required": ["crm-user"]},
	"crm_delete_customer": {"app": "crm", "roles_required": ["crm-admin"]},
	"orders_get_orders": {"app": "orders", "roles_required": ["orders-user"]},
}

mario := {"active": true, "username": "mario.sales", "roles": ["crm-user"]}

luigi := {"active": true, "username": "luigi.finance", "roles": ["orders-user"]}

anna := {"active": true, "username": "anna.admin", "roles": ["crm-user", "crm-admin"]}

call(token, domain, tool) := {"token": token, "domain": domain, "rpc": {"method": "tools/call", "tool": tool}}

test_mario_reads_crm_but_cannot_delete if {
	authz.allow with input as call(mario, "crm", "crm_get_customers") with data.tool_registry as registry
	not authz.allow with input as call(mario, "crm", "crm_delete_customer") with data.tool_registry as registry
}

test_anna_can_delete if {
	authz.allow with input as call(anna, "crm", "crm_delete_customer") with data.tool_registry as registry
}

test_mario_cannot_use_orders_tools if {
	not authz.allow with input as call(mario, "orders", "orders_get_orders") with data.tool_registry as registry
}

test_luigi_orders_only if {
	authz.allow with input as call(luigi, "orders", "orders_get_orders") with data.tool_registry as registry
	not authz.allow with input as call(luigi, "crm", "crm_get_customers") with data.tool_registry as registry
}

test_unknown_tool_denied if {
	not authz.allow with input as call(mario, "crm", "drop_database") with data.tool_registry as registry
}

test_tool_on_wrong_domain_denied if {
	not authz.allow with input as call(anna, "orders", "crm_get_customers") with data.tool_registry as registry
}

test_inactive_token_denied if {
	not authz.allow with input as call({"active": false}, "crm", "crm_get_customers") with data.tool_registry as registry
}

test_protocol_methods_allowed_with_valid_token if {
	authz.allow with input as {"token": mario, "domain": "crm", "rpc": {"method": "initialize"}}
	authz.allow with input as {"token": luigi, "domain": "orders", "rpc": {"method": "tools/list"}}
}

test_allowed_tools_filtering if {
	authz.allowed_tools == {"crm_get_customers"} with input as {"token": mario, "domain": "crm"} with data.tool_registry as registry
	authz.allowed_tools == {"crm_get_customers", "crm_delete_customer"} with input as {"token": anna, "domain": "crm"} with data.tool_registry as registry
	authz.allowed_tools == set() with input as {"token": mario, "domain": "orders"} with data.tool_registry as registry
}

# The shipped data.json (loaded by `opa test`) must contain the namespaced tools.
test_shipped_registry_is_namespaced if {
	every name, _ in data.tool_registry {
		startswith(name, concat("_", [data.tool_registry[name].app, ""]))
	}
}
