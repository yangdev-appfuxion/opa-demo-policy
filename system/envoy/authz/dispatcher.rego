package system.envoy.authz

import rego.v1

default allow := false

# =======================================================
# 1. INPUT PARSING
# =======================================================

# Extract Bearer Token
bearer_token := token if {
    auth_header := input.attributes.request.http.headers.authorization
    startswith(auth_header, "Bearer ")
    token := substring(auth_header, 7, -1)
}

# Decode JWT (no verification here)
jwt_parts := io.jwt.decode(bearer_token)
payload := jwt_parts[1]

# =======================================================
# 2. CONTEXT EXTRACTION
# =======================================================

# Realm from issuer URL
realm_name := realm if {
    parts := split(payload.iss, "/")
    realm := parts[count(parts) - 1]
}

# Client from azp
client_name := payload.azp

# =======================================================
# 3. ENV EXTRACTION FROM PATH
# =======================================================

# Example path:
# /api/opaDemoRealm/opaDemoClient/dev/v1/project/1
env_name := env if {
    path := input.attributes.request.http.path
    segments := split(path, "/")

    # Ensure path is long enough
    count(segments) >= 5

    # segments[0] = ""
    # segments[1] = "api"
    # segments[2] = realm
    # segments[3] = client
    # segments[4] = env
    env := segments[4]
}

# =======================================================
# 4. DYNAMIC DISPATCH
# =======================================================

allow if {
    realm_name != ""
    client_name != ""
    env_name != ""

    # data.opaDemoRealm.opaDemoClient.policies.dev
    policy := data[realm_name][client_name].policies[env_name]
    policy.allow
}

# =======================================================
# 5. DEBUGGING / DECISION LOGS
# =======================================================

result := {
    "allowed": allow,
    "inferred_realm": realm_name,
    "inferred_client": client_name,
    "inferred_env": env_name,
    "request_path": input.attributes.request.http.path,
    "jwt_iss": object.get(payload, "iss", "missing")
}
