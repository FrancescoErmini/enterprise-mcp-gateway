package mcp.authz_test

import rego.v1

import data.mcp.authz

mario := {"active": true, "username": "mario.sales", "roles": ["crm-user"]}

luigi := {"active": true, "username": "luigi.finance", "roles": ["orders-user"]}

call(token, tool) := {"token": token, "rpc": {"method": "tools/call", "tool": tool}}

test_mario_can_use_crm_tools if {
	authz.allow with input as call(mario, "get_customers")
	authz.allow with input as call(mario, "delete_customer")
}

test_mario_cannot_use_orders_tools if {
	not authz.allow with input as call(mario, "get_orders")
}

test_luigi_can_use_orders_but_not_crm if {
	authz.allow with input as call(luigi, "get_orders")
	not authz.allow with input as call(luigi, "get_customers")
}

test_unknown_tool_denied if {
	not authz.allow with input as call(mario, "drop_database")
}

test_inactive_token_denied if {
	not authz.allow with input as call({"active": false}, "get_customers")
}

test_protocol_methods_allowed_with_valid_token if {
	authz.allow with input as {"token": mario, "rpc": {"method": "initialize"}}
	authz.allow with input as {"token": luigi, "rpc": {"method": "tools/list"}}
}
