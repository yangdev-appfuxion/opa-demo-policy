package system.envoy.authz

import rego.v1

default allow := false

allow if {
    true
}

# 1. Extract Context from Headers (Injected by Python Gateway)
# Headers are usually lowercase in Envoy input
realm_name  := input.attributes.request.http.headers["x-realm"]
client_name := input.attributes.request.http.headers["x-client-id"]
env_name    := input.attributes.request.http.headers["x-env"]

# 2. Dynamic Policy Lookup
allow if {

    # Ensure headers are present
    realm_name != ""
    client_name != ""
    env_name != ""

    # Look up policy: data[realm][client].policies[env]
    policy := data[realm_name][client_name].policies[env_name]
    
    policy.allow
}