package policies.opaDemoRealm.opaDemoClient.policies.dev

import rego.v1

# ============================================
# IMPORTS
# ============================================
# We point to the data loaded by OPAL from Kafka
import data.opaDemoRealm.opaDemoClient.data.dev as sql

# ============================================
# CONFIGURATION & CONSTANTS
# ============================================
default allow := false

# ============================================
# 1. ENVOY INPUT PARSING (The "Adapter" Layer)
# ============================================

# Extract the HTTP Request object for easier access
http_request := input.attributes.request.http

# 1a. Parse JWT from Header to get User Email
# We trust the token because Envoy/Gateway should have verified the signature
claims := payload if {
    auth_header := http_request.headers.authorization
    startswith(auth_header, "Bearer ")
    bearer_token := substring(auth_header, 7, -1)
    [_, payload, _] := io.jwt.decode(bearer_token)
}

# 1b. Map HTTP Methods to CRUD Actions
action := "read" if http_request.method == "GET"
else := "create" if http_request.method == "POST"
else := "update" if http_request.method in ["PUT", "PATCH"]
else := "delete" if http_request.method == "DELETE"
else := "options" if http_request.method == "OPTIONS"

# 1c. Parse the Path (e.g., "/api/project/1")
# We ignore empty strings caused by leading slashes
path_segments := [x | some x in split(http_request.path, "/"); x != ""]

# Resource Name: Assumes path structure is like ["api", "project", "1", ...]
# We take index 1 (the second element) as the resource name.
resource_name := path_segments[1] if count(path_segments) >= 2

# Resource ID: Assumes index 2 is the ID. We MUST convert to Number.
resource_id := to_number(path_segments[2]) if {
    count(path_segments) >= 3
    # Check if it looks like a number before converting to avoid runtime errors
    regex.match(`^\d+$`, path_segments[2])
}

# ============================================
# 2. SQL DATA HELPERS (The "Lookup" Layer)
# ============================================

# Resolve Current User from SQL based on JWT Email
current_user := user if {
    some user in sql.users
    user.email == claims.email
}

# Resolve User Roles (Join user -> user_role -> role)
user_roles contains role.name if {
    some mapping in sql.user_role
    mapping.user_id == current_user.id
    
    some role in sql.role
    role.id == mapping.role_id
}

# Resolve Target Project
target_project := project if {
    resource_name == "project"
    some project in sql.project
    project.id == resource_id
}

# ============================================
# 3. POLICY RULES (The "Logic" Layer)
# ============================================

# Rule 0: Allow Health Checks (Optional but recommended)
allow if {
    http_request.path == "/health"
    http_request.method == "GET"
}

# Rule 1: Superadmins can do anything
allow if {
    "superadmin" in user_roles
}

# Rule 2: Project Owner can always access their project
allow if {
    action == "read"
    target_project.owner_user_id == current_user.id
}

# Rule 3: Department Match & Seniority Check
allow if {
    action == "read"
    resource_name == "project"
    
    # 3a. Find the Project Owner
    some owner in sql.users
    owner.id == target_project.owner_user_id
    
    # 3b. Department Match: User must be in same department as Owner
    current_user.department_id == owner.department_id
    
    # 3c. Seniority Check: User must be Seniority Level >= 3 (Junior or above)
    some level in sql.seniority_level
    level.id == current_user.seniority_level_id
    level.level_value >= 3
}

# ============================================
# DEBUGGING (Response for Decision Logs)
# ============================================
# When testing with OPA CLI or viewing logs, this object explains the decision
result := {
    "allowed": allow,
    "user_email": object.get(claims, "email", "no-token"),
    "user_id": object.get(current_user, "id", "not-found"),
    "parsed_action": action,
    "parsed_resource": resource_name,
    "parsed_id": resource_id,
    "roles": user_roles
}