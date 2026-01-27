package system.envoy.authz

import rego.v1

default allow := false

# Parse path segments: /api/{realm}/{client}/{env}/...
path_segments := split(trim(input.attributes.request.http.path, "/"), "/")

realm_name  := path_segments[1]
client_name := path_segments[2]
env_name    := path_segments[3]

# Delegate decision to policies
allow if {
    policy := data.policies[realm_name][client_name].policies[env_name]
    policy.allow
}
