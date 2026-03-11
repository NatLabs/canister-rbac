# canister-rbac

A hierarchical Role-Based Access Control (RBAC) library for Motoko on the Internet Computer.

## Installation

```bash
mops add canister-rbac
```

## Core Concepts

There are four building blocks: **permissions**, **roles**, **resources**, and **users**.

- **Permissions** are named actions (e.g. `"read"`, `"write"`, `"delete"`). They are the atomic unit of access.
- **Roles** are named groups of permissions (e.g. `"admin"` = `["read", "write", "delete"]`). A role must exist before it can be granted.
- **Resources** are hierarchical paths expressed as a `ResourceScope` — an ordered list of `(resource_type, resource_id)` segments. The empty scope `[]` means global. A grant at a parent scope automatically grants access to all child scopes.
- **Users** (Principals) are granted roles at a specific resource scope. A user's effective permissions at any scope are determined by all roles granted at that scope or any ancestor scope.

**Rules:**
- A user can hold the same role at multiple different scopes independently.
- Granting the same role+scope twice is idempotent (no duplicates).
- Deleting a role or permission cascades — removed from all users/roles automatically.
- Role and permission names are case-insensitive (auto-lowercased).

### Naming Rules

All role and permission names are validated on input:

- **Role & permission names**: alphanumeric characters, hyphens (`-`), underscores (`_`), and colons (`:`). Examples: `"admin"`, `"read-write"`, `"api:manage"`.
- **Scope segments**: alphanumeric characters, hyphens (`-`), and underscores (`_`). Colons are **not** allowed in scope types or values. 
- **Wildcards**: The wildcard `"*"` is allowed **only** as the value in the **last segment** of a scope. This prevents ambiguous scope patterns.
  - ✅ Valid: `[("database", "*")]`, `[("database", "users"), ("collection", "*")]`
  - ❌ Invalid: `[("database", "*"), ("collection", "profiles")]` (wildcard not at end)
- Names cannot be empty and are automatically lowercased.

## Quick Start

```motoko
import CanisterRBAC "mo:canister-rbac";

// Initialize with roles (traps on invalid input)
stable var auth = CanisterRBAC.initRoles([
    { name = "admin";  permissions = ["read", "write", "delete"] },
    { name = "viewer"; permissions = ["read"] },
]);

// Grant a user the "admin" role globally
let #ok(_) = CanisterRBAC.grantUserRole(auth, caller, "admin", []);

// Grant a user the "viewer" role on a specific resource
let #ok(_) = CanisterRBAC.grantUserRole(auth, caller, "viewer", [("project", "acme")]);

// Check if a user can perform an action on a resource
if (CanisterRBAC.hasPermission(auth, caller, "read", [("project", "acme")])) {
    // allowed
};

// Gate a function and get its return value, or trap on failure
let data = CanisterRBAC.requirePermission<Text>(auth, caller, "read", [("project", "acme")], func() : Text {
    "sensitive data"
});

// Gate a function with a Result return (non-trapping)
let result = CanisterRBAC.allow<Text>(auth, caller, "write", [("project", "acme")], func() : Text {
    "wrote something"
});
// result : Result<Text, Text> — #ok("wrote something") or #err("User does not have permission...")
```

## Resource Scopes

Each scope segment is `(resource_type, resource_id)`. Scopes are hierarchical — a grant at a parent applies to all descendants. Use `"*"` as the id to match any resource of that type.

```motoko
[]                                               // global
[("project", "acme")]                            // project level
[("project", "acme"), ("collection", "docs")]    // collection within project
[("project", "*")]                               // all projects (wildcard)
[("project", "acme"), ("collection", "*")]       // all collections within acme project
```

## API

### Setup
| Function | Returns | Description |
|---|---|---|
| `new()` | `VersionedStableStore` | Empty store |
| `initRoles(roles)` | `VersionedStableStore` | Store pre-loaded with roles (validates names, rejects duplicates, traps on error) |

### Roles and Permissions
| Function | Returns | Description |
|---|---|---|
| `createRole(store, name, permissions)` | `Result<(), Text>` | Create a role |
| `getRole(store, name)` | `Result<(Text, [Text]), Text>` | Get a role's name and permissions |
| `deleteRole(store, name)` | `Result<(), Text>` | Delete a role and all its grants |
| `renameRole(store, old, new)` | `Result<(), Text>` | Rename a role (updates all grants) |
| `addRolePermissions(store, role, perms)` | `Result<(), Text>` | Add permissions to a role |
| `removeRolePermissions(store, role, perms)` | `Result<(), Text>` | Remove permissions from a role |
| `getRolePermissions(store, role)` | `Result<[Text], Text>` | Get permissions for a role |
| `createPermission(store, name)` | `Result<(), Text>` | Create a standalone permission |
| `deletePermission(store, name)` | `Result<(), Text>` | Delete a permission from all roles |
| `renamePermission(store, old, new)` | `Result<(), Text>` | Rename a permission across all roles |
| `getAllRoles(store)` | `[(Text, [Text])]` | All roles with their permissions |
| `getAllPermissions(store)` | `[Text]` | All permission names |
| `getRolesWithPermission(store, perm)` | `Result<[(Text, [Text])], Text>` | Roles that have a permission |

### Granting and Revoking
| Function | Returns | Description |
|---|---|---|
| `grantUserRole(store, user, role, scope)` | `Result<(), Text>` | Grant a user a role at a scope |
| `revokeUserRole(store, user, role, scope)` | `Result<(), Text>` | Revoke a specific role+scope from a user |

### Checking Access
| Function | Returns | Description |
|---|---|---|
| `hasPermission(store, user, perm, scope)` | `Bool` | Boolean permission check |
| `allow<A>(store, user, perm, scope, fn)` | `Result<A, Text>` | Run `fn` if allowed, return `Result` |
| `allowVoid(store, user, perm, scope, fn)` | `Result<(), Text>` | Run void `fn` if allowed |
| `allowWithResult<A>(store, user, perm, scope, fn)` | `Result<A, Text>` | Run `fn` returning `Result` if allowed |
| `requirePermission<A>(store, user, perm, scope, fn)` | `A` | Run `fn` if allowed, **trap** on failure |

### Querying
| Function | Returns | Description |
|---|---|---|
| `getUserGrants(store, user)` | `[(ResourceScope, Text, [Text])]` | All grants for a user (scope, role, permissions) |
| `getAllUserGrants(store)` | `[(Principal, [(ResourceScope, Text, [Text])])]` | All grants for all users |
| `getUsersWithRole(store, role, scope)` | `Result<[Principal], Text>` | Users with a role at a scope (includes ancestors) |

### Scope Utilities
| Function | Returns | Description |
|---|---|---|
| `scope_to_key(scope)` | `Text` | Convert `ResourceScope` to string key |
| `key_to_scope(key)` | `ResourceScope` | Parse string key back to `ResourceScope` |
| `getScopeHierarchy(scope)` | `[ResourceScope]` | All parent scopes for hierarchical checking |

### Stable Storage
```motoko
stable var versioned_store : CanisterRBAC.Types.VersionedStableStore = CanisterRBAC.new();

system func postupgrade() {
    versioned_store := CanisterRBAC.upgrade(versioned_store);
};
```

## License

MIT
