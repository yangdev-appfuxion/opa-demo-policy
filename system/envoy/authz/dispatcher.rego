package system.envoy.authz

import rego.v1

default allow := false

# 1. Parse Path
# Input:  /api/{realm}/{client}/{env}/...
path_segments := split(trim(input.attributes.request.http.path, "/"), "/")

# 2. Extract Dynamic Segments
realm_name  := path_segments[1]
client_name := path_segments[2]
env_name    := path_segments[3]

# 3. Dynamic Policy Lookup
allow if {
    count(path_segments) >= 4
    
    # FIX IS HERE: No dot between 'data' and '[realm_name]'
    policy := data[realm_name][client_name].policies[env_name]
    
    policy.allow
}