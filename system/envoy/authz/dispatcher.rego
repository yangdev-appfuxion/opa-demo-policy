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
    # Verify enough segments to avoid index out of bounds
    count(path_segments) >= 4

    policy := data.[realm_name][client_name].policies[env_name]
    policy.allow
}
