package opaDemoRealm.opaDemoClient.policies.dev

import rego.v1

# ============================================
# IMPORTS - Connect to the Data Pump
# ============================================
# We alias the path to 'sql' for easier reading
import data.opaDemoRealm.opaDemoClient.data.dev as sql

# ============================================
# DEFAULT DENY
# ============================================
default allow := false

# ============================================
# 1. HELPER: Resolve the Current User
# ============================================
# Look up the full user object inside sql.users based on input.user (email)
current_user := user if {
    some user in sql.users
    user.email == input.user
}

# ============================================
# 2. HELPER: Resolve User's Roles (The JOIN)
# ============================================
# Returns a Set of role names (e.g., {"superadmin", "developer"})
# Join logic: users.id -> user_role.user_id + user_role.role_id -> role.id
user_roles contains role.name if {
    # 1. We have a valid current user
    uid := current_user.id
    
    # 2. Find the link table entries for this user
    some mapping in sql.user_role
    mapping.user_id == uid
    
    # 3. Find the actual role definition
    some role in sql.role
    role.id == mapping.role_id
}

# ============================================
# 3. HELPER: Resolve the Target Resource
# ============================================
# If input is a project, find it in sql.project
target_project := project if {
    input.resource.type == "project"
    some project in sql.project
    project.id == input.resource.id
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
# Allow if the user belongs to the same department as the project
# AND the user has a seniority level > 3 (Mid-level or above)
allow if {
    input.action == "read"
    
    # Check Department Match (User Dept ID == Project Dept ID??)
    # Note: Your project schema in the log didn't have dept_id, 
    # but let's assume strict separation by inference or if logic existed:
    # Let's try a logic: Users can read projects created by others in their department?
    # (Assuming we map project owner -> owner's department -> matches user department)
    
    # 1. Find Project Owner
    some owner in sql.users
    owner.id == target_project.owner_user_id
    
    # 2. Compare Departments
    current_user.department_id == owner.department_id
    
    # 3. Check Seniority (Join to Seniority Level table)
    some level in sql.seniority_level
    level.id == current_user.seniority_level_id
    level.level_value >= 3 
}

# ============================================
# DEBUGGING (Optional: To see what OPA sees)
# ============================================
debug := {
    "user_found": current_user.name,
    "roles": user_roles,
    "department_id": current_user.department_id,
    "accessing_project": target_project.name
}