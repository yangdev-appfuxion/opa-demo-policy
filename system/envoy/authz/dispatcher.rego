package system.envoy.authz

import rego.v1

default allow := false

# 1. Parse the Path segments
# Assumption: URL is /api/{realm}/{client}/{env}/{resource}/{id}
path_segments := split(trim(input.attributes.request.http.path, "/"), "/")

# 2. Extract Context Variables
realm_name  := path_segments[1]  # index 1 because index 0 is "api"
client_name := path_segments[2]
env_name    := path_segments[3]

# 3. Dynamic Dispatch
# This looks into "data.policies" for a package matching the URL structure
# and invokes the "allow" rule inside it.
allow if {
    # Check if the policy exists in memory
    policy := data.policies[realm_name][client_name][env_name]
    
    # Delegate the decision to that policy
    policy.allow
}