package opaDemoRealm.opaDemoClient.policies.dev

import rego.v1

# ============================================
# IMPORTS
# ============================================
import data.opaDemoRealm.opaDemoClient.data.dev as sql

# ============================================
# DEFAULT DENY
# ============================================
default allow := false

# ============================================
# 1. HELPER: Resolve the Current User
# ============================================
current_user := user if {
    some user in sql.users
    user.email == input.user
}

# ============================================
# 2. HELPER: Resolve User's Roles
# ============================================
user_roles contains role.name if {
    uid := current_user.id
    some mapping in sql.user_role
    mapping.user_id == uid
    some role in sql.role
    role.id == mapping.role_id
}

# ============================================
# 3. HELPER: Resolve the Target Resource
# ============================================
# input.resource_name comes from the URL path (e.g., "project")
# input.resource_id comes from the URL path (e.g., "123")
target_project := project if {
    # Match the resource name from Python (likely plural from URL)
    input.resource_name == "project"
    
    some project in sql.project
    
    # Compare IDs. 
    # CAUTION: URL inputs are Strings. If your SQL data has Int IDs,
    # you might need to convert: format_int(project.id, 10) == input.resource_id
    project.id == input.resource_id
}

# ============================================
# POLICY RULES
# ============================================

# Rule 1: Superadmins can do anything
allow if {
    "superadmin" in user_roles
}

# Rule 2: Project Owner can always access their project
allow if {
    input.action == "read"
    target_project.owner_user_id == current_user.id
}

# Rule 3: Department Match
allow if {
    input.action == "read"
    
    some owner in sql.users
    owner.id == target_project.owner_user_id
    
    # Logic: User must be in same department as Project Owner
    current_user.department_id == owner.department_id
    
    # Logic: User must be Seniority Level 3 or higher
    some level in sql.seniority_level
    level.id == current_user.seniority_level_id
    level.level_value >= 3 
}

# ============================================
# DEBUGGING
# ============================================
debug := {
    "input_user": input.user,
    "input_resource": input.resource_name,
    "input_id": input.resource_id,
    "user_found": current_user.name,
    "target_project": target_project
}