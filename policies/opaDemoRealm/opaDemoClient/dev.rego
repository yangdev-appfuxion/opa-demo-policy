package opaDemoRealm.opaDemoClient.policies.dev

# ============================================
# IMPORTS - Connect to the Data Pump
# ============================================

import opaDemoRealm.opaDemoClient.data.dev as sql

# ============================================
# DEFAULT DENY
# ============================================

default allow := false

# ============================================
# HELPER FUNCTIONS (Refactored for Data Pump)
# ============================================

# Get user's roles
user_role contains role if {
    # CHANGED: Use 'sql.user_role' instead of 'data.user_role'
    some user_role in sql.user_role
    user_role.user_id == input.user.id
    some role in sql.roles
    role.id == user_role.role_id
}

# Get user's highest clearance level
user_clearance_level := level if {
    levels := [role.clearance_level | some role in user_role]
    level := max(levels)
}

# Check if user has specific role
has_role(role_name) if {
    some role in user_role
    role.name == role_name
}

# Get user's department
user_department := dept if {
    some user in sql.users
    user.id == input.user.id
    some dept in sql.department
    dept.id == user.department_id
}

# Get user's seniority level
user_seniority := seniority if {
    some user in sql.users
    user.id == input.user.id
    some seniority in sql.seniority_level
    seniority.id == user.seniority_level_id
}

# Check if user is active
is_active_user if {
    some user in sql.users
    user.id == input.user.id
    some status in sql.user_statuse
    status.id == user.status_id
    status.status_code == "active"
}

# Get resource sensitivity level value
resource_sensitivity_value(resource_type, resource_id) := value if {
    resource_type == "project"
    some project in sql.projects
    project.id == resource_id
    some sensitivity in sql.sensitivity_levels
    sensitivity.id == project.sensitivity_level_id
    value := sensitivity.level_value
}

resource_sensitivity_value(resource_type, resource_id) := value if {
    resource_type == "engagement"
    some engagement in sql.engagements
    engagement.id == resource_id
    some sensitivity in sql.sensitivity_levels
    sensitivity.id == engagement.sensitivity_level_id
    value := sensitivity.level_value
}

resource_sensitivity_value(resource_type, resource_id) := value if {
    resource_type == "security_finding"
    some finding in sql.security_findings
    finding.id == resource_id
    some engagement in sql.engagements
    engagement.id == finding.engagement_id
    some sensitivity in sql.sensitivity_levels
    sensitivity.id == engagement.sensitivity_level_id
    value := sensitivity.level_value
}

# Check if user is explicitly denied access
is_denied(resource_type, resource_id) if {
    resource_type == "project"
    some deny in sql.deny_user_to_project
    deny.user_id == input.user.id
    deny.project_id == resource_id
}

is_denied(resource_type, resource_id) if {
    resource_type == "engagement"
    some deny in sql.deny_user_to_engagement
    deny.user_id == input.user.id
    deny.engagement_id == resource_id
}

is_denied(resource_type, resource_id) if {
    resource_type == "security_finding"
    some deny in sql.deny_user_to_security_finding
    deny.user_id == input.user.id
    deny.security_finding_id == resource_id
}

# Check if user is project owner
is_project_owner(project_id) if {
    some project in sql.projects
    project.id == project_id
    project.owner_user_id == input.user.id
}

# Get project for engagement
engagement_project_id(engagement_id) := project_id if {
    some engagement in sql.engagements
    engagement.id == engagement_id
    project_id := engagement.project_id
}

# Get engagement for finding
finding_engagement_id(finding_id) := engagement_id if {
    some finding in sql.security_findings
    finding.id == finding_id
    engagement_id := finding.engagement_id
}

# Check if resource belongs to user's department
is_same_department(resource_type, resource_id) if {
    resource_type == "project"
    some project in sql.projects
    project.id == resource_id
    some owner in sql.users
    owner.id == project.owner_user_id
    owner.department_id == user_department.id
}

# Get risk level value for finding
finding_risk_value(finding_id) := value if {
    some finding in sql.security_findings
    finding.id == finding_id
    some risk in sql.risk_levels
    risk.id == finding.risk_level_id
    value := risk.level_value
}

# ============================================
# RBAC RULES - Role-Based Access Control
# ============================================

# SuperAdmin - Full Access
allow if {
    has_role("superadmin")
    is_active_user
}

# Company Admin - Access to all resources except explicit denies
allow if {
    has_role("company_admin")
    is_active_user
    not is_denied(input.resource.type, input.resource.id)
}

# Head of Department - Access to department resources
allow if {
    has_role("hod")
    is_active_user
    is_same_department(input.resource.type, input.resource.id)
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# PROJECT ACCESS RULES
# ============================================

# Project Manager can access projects they own
allow if {
    input.resource.type == "project"
    has_role("project_manager")
    is_active_user
    is_project_owner(input.resource.id)
    not is_denied(input.resource.type, input.resource.id)
}

# Project Manager can view projects with appropriate clearance
allow if {
    input.resource.type == "project"
    input.action == "view"
    has_role("project_manager")
    is_active_user
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    user_clearance_level >= sensitivity
    not is_denied(input.resource.type, input.resource.id)
}

# Security Lead can access all security-related resources with appropriate clearance
allow if {
    input.resource.type in ["project", "engagement", "security_finding"]
    has_role("security_lead")
    is_active_user
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    user_clearance_level >= sensitivity
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# ENGAGEMENT ACCESS RULES
# ============================================

# Security Analyst can view engagements with appropriate clearance
allow if {
    input.resource.type == "engagement"
    input.action in ["view", "update"]
    has_role("security_analyst")
    is_active_user
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    user_clearance_level >= sensitivity
    not is_denied(input.resource.type, input.resource.id)
}

# Project owner can access engagements in their projects
allow if {
    input.resource.type == "engagement"
    is_active_user
    project_id := engagement_project_id(input.resource.id)
    is_project_owner(project_id)
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# SECURITY FINDING ACCESS RULES
# ============================================

# Security Analyst can create and update findings
allow if {
    input.resource.type == "security_finding"
    input.action in ["view", "create", "update"]
    has_role("security_analyst")
    is_active_user
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    user_clearance_level >= sensitivity
    not is_denied(input.resource.type, input.resource.id)
}

# Developer Lead can view findings in their projects
allow if {
    input.resource.type == "security_finding"
    input.action == "view"
    has_role("developer_lead")
    is_active_user
    engagement_id := finding_engagement_id(input.resource.id)
    project_id := engagement_project_id(engagement_id)
    is_project_owner(project_id)
    risk_value := finding_risk_value(input.resource.id)
    risk_value <= 75
    not is_denied(input.resource.type, input.resource.id)
}

# Developer can view non-critical findings in their department
allow if {
    input.resource.type == "security_finding"
    input.action == "view"
    has_role("developer")
    is_active_user
    engagement_id := finding_engagement_id(input.resource.id)
    project_id := engagement_project_id(engagement_id)
    is_same_department("project", project_id)
    risk_value := finding_risk_value(input.resource.id)
    risk_value <= 50
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# AUDITOR ACCESS RULES
# ============================================

allow if {
    input.resource.type == "engagement"
    input.action == "view"
    has_role("auditor")
    is_active_user
    some engagement in sql.engagements
    engagement.id == input.resource.id
    some status in sql.engagement_statuses
    status.id == engagement.status_id
    status.status_code == "completed"
    not is_denied(input.resource.type, input.resource.id)
}

allow if {
    input.resource.type == "security_finding"
    input.action == "view"
    has_role("auditor")
    is_active_user
    some finding in sql.security_findings
    finding.id == input.resource.id
    some status in sql.finding_statuses
    status.id == finding.status_id
    status.status_code in ["closed", "resolved"]
    not is_denied(input.resource.type, input.resource.id)
}

allow if {
    input.resource.type == "audit_log"
    input.action == "view"
    has_role("auditor")
    is_active_user
}

# ============================================
# ABAC RULES
# ============================================

# High seniority users can access medium sensitivity resources
allow if {
    input.action == "view"
    is_active_user
    user_seniority.level_value >= 7
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    sensitivity <= 50
    not is_denied(input.resource.type, input.resource.id)
}

# Users can access resources during business hours for non-critical items
allow if {
    input.action == "view"
    is_active_user
    time.now_ns() >= input.context.business_hours_start
    time.now_ns() <= input.context.business_hours_end
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    sensitivity <= 25
    not is_denied(input.resource.type, input.resource.id)
}

# Same department access for low sensitivity projects
allow if {
    input.resource.type == "project"
    input.action == "view"
    is_active_user
    is_same_department(input.resource.type, input.resource.id)
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    sensitivity <= 25
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# GUEST USER RULES
# ============================================

allow if {
    has_role("guest")
    input.action == "view"
    some user in sql.users
    user.id == input.user.id
    some status in sql.user_statuse
    status.id == user.status_id
    status.status_code == "guest"
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    sensitivity == 0
    not is_denied(input.resource.type, input.resource.id)
}

# ============================================
# ADMINISTRATIVE ACTIONS
# ============================================

allow if {
    input.action == "delete"
    has_role("superadmin")
    is_active_user
}

allow if {
    input.action == "delete"
    has_role("company_admin")
    is_active_user
    not is_denied(input.resource.type, input.resource.id)
}

allow if {
    input.resource.type == "user_role"
    input.action in ["create", "delete"]
    has_role("superadmin")
    is_active_user
}

allow if {
    input.resource.type in ["deny_user_to_project", "deny_user_to_engagement", "deny_user_to_security_finding"]
    has_role("superadmin")
    is_active_user
}

allow if {
    input.resource.type in ["deny_user_to_project", "deny_user_to_engagement", "deny_user_to_security_finding"]
    has_role("company_admin")
    is_active_user
}

# ============================================
# AUDIT & RESPONSE
# ============================================

deny_reason := reason if {
    not allow
    is_denied(input.resource.type, input.resource.id)
    reason := "explicitly_denied"
} else := reason if {
    not allow
    not is_active_user
    reason := "user_not_active"
} else := reason if {
    not allow
    sensitivity := resource_sensitivity_value(input.resource.type, input.resource.id)
    user_clearance_level < sensitivity
    reason := "insufficient_clearance"
} else := reason if {
    not allow
    reason := "no_matching_policy"
}

audit_log := {
    "timestamp": time.now_ns(),
    "user_id": input.user.id,
    "action": input.action,
    "resource_type": input.resource.type,
    "resource_id": input.resource.id,
    "allowed": allow,
    "roles": [role.name | some role in user_role],
    "deny_reason": deny_reason
}

response := {
    "allowed": allow,
    "reason": deny_reason,
    "audit_log": audit_log
}