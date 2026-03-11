import Result "mo:core@2.0.0/Result";
import Runtime "mo:core@2.0.0/Runtime";
import Text "mo:core@2.0.0/Text";
import Nat "mo:core@2.0.0/Nat";
import Array "mo:core@2.0.0/Array";

import Map "mo:map@9.0.1/Map";
import Set "mo:map@9.0.1/Set";

import Vector "mo:vector@0.4.2";
import Iter "mo:base/Iter";
import T "Types";
import Migrations "Migrations";

/// CanisterRBAC - A hierarchical Role-Based Access Control (RBAC) library for Motoko.
///
/// This module provides functions for managing roles, permissions, and user access
/// with support for hierarchical resource scopes and wildcard matching.
module CanisterRBAC {

    type Map<K, V> = Map.Map<K, V>;
    type Set<K> = Set.Set<K>;
    type Vector<A> = Vector.Vector<A>;
    type Result<A, B> = Result.Result<A, B>;

    /// Export Types module for external access to type definitions.
    public let Types = T;

    /// Creates a new empty authorization store.
    ///
    /// Returns a fresh `VersionedStableStore` with no roles, permissions, or grants.
    ///
    /// Example:
    /// ```motoko
    /// let store = CanisterRBAC.new();
    /// ```
    public func new() : T.VersionedStableStore {
        let store : T.StableStore = {
            var role_id_counter = 0;
            role_ids = Map.new<Nat, Text>();
            permissions = Map.new<Text, Set<Nat>>();
            roles = Map.new<Text, (Nat, Set<Text>)>();
            role_grants = Map.new<Nat, Map<Text, Set<Principal>>>();
        };
        Migrations.share(store);
    };

    /// Upgrades a versioned store from a previous version to the current version.
    ///
    /// Use this in `postupgrade` to migrate data after canister upgrades.
    ///
    /// Example:
    /// ```motoko
    /// system func postupgrade() {
    ///     versioned_store := CanisterRBAC.upgrade(versioned_store);
    /// };
    /// ```
    public func upgrade(prev_store : T.PrevVersionedStableStore) : T.VersionedStableStore {
        Migrations.upgrade(prev_store);
    };

    /// Extracts the current state from a versioned store.
    ///
    /// Use this to get the working `StableStore` from the versioned wrapper.
    ///
    /// Example:
    /// ```motoko
    /// let current = CanisterRBAC.get_current_state(versioned_store);
    /// ```
    public func get_current_state(store : T.VersionedStableStore) : T.StableStore {
        Migrations.get_current_state(store);
    };

    /// Converts a versioned store to its version string.
    ///
    /// Returns a human-readable version string like "v0.1.0".
    public func version_to_text(store : T.PrevVersionedStableStore) : Text {
        Migrations.to_text(store);
    };

    /// Initializes a store with predefined roles and their permissions.
    ///
    /// This is a convenience function for setting up common roles at initialization.
    ///
    /// Example:
    /// ```motoko
    /// stable let auth = CanisterRBAC.initRoles([
    ///     { name = "admin"; permissions = ["read", "write", "manage"] },
    ///     { name = "viewer"; permissions = ["read"] },
    /// ]);
    /// ```
    public func initRoles(init_roles : [T.InputRole]) : T.VersionedStableStore {
        let store = new();
        // Validate all inputs and check for duplicate role names before committing any changes
        let names_seen = Set.new<Text>();
        for (role in init_roles.vals()) {
            let role_name = switch (validate_name(role.name)) {
                case (#err(e)) Runtime.trap(e);
                case (#ok(n)) n;
            };
            if (Set.has(names_seen, Map.thash, role_name)) {
                Runtime.trap("Duplicate role name '" # role_name # "' in init_roles");
            };
            Set.add(names_seen, Map.thash, role_name);
            switch (validate_names(role.permissions)) {
                case (#err(e)) Runtime.trap(e);
                case (#ok(_)) {};
            };
        };

        for (role in init_roles.vals()) {
            switch (createRole(store, role.name, role.permissions)) {
                case (#err(e)) Runtime.trap(e);
                case (#ok(_)) {};
            };
        };
        store;
    };

    /// Creates a new standalone permission.
    ///
    /// Permissions can exist independently and be added to roles later.
    /// Returns an error if the permission already exists.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.createPermission(store, "audit");
    /// ```
    public func createPermission(auth : T.VersionedStableStore, _permission_name : Text) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let permission_name = switch (validate_name(_permission_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };

        switch (Map.get(state.permissions, Map.thash, permission_name)) {
            case (?_) return #err("Permission '" # permission_name # "' already exists");
            case (null) {
                ignore Map.put(state.permissions, Map.thash, permission_name, Set.new<Nat>());
            };
        };

        #ok();
    };

    /// Creates a new role with the specified permissions.
    ///
    /// Role names are case-insensitive (automatically lowercased).
    /// Returns an error if the role already exists.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.createRole(store, "editor", ["read", "write"]);
    /// ```
    public func createRole(auth : T.VersionedStableStore, _roleName : Text, _permissions : [Text]) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let roleName = switch (validate_name(_roleName)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let permissions = switch (validate_names(_permissions)) {
            case (#err(e)) return #err(e);
            case (#ok(ps)) ps;
        };

        switch (Map.get(state.roles, Map.thash, roleName)) {
            case (?_) return #err("Role '" # roleName # "' already exists");
            case (null) {};
        };

        let permissions_set = Set.new<Text>();
        for (perm in permissions.vals()) {
            Set.add(permissions_set, Map.thash, perm);
        };

        // Generate new role ID
        let role_id = state.role_id_counter;
        state.role_id_counter += 1;

        // Store role ID -> role name mapping
        ignore Map.put(state.role_ids, Map.nhash, role_id, roleName);

        // Store role name -> (role_id, permissions)
        ignore Map.put(state.roles, Map.thash, roleName, (role_id, permissions_set));

        // Update permissions map: add this role ID to each permission's set
        for (permission in Set.keys(permissions_set)) {
            let roles_with_permission = switch (Map.get(state.permissions, Map.thash, permission)) {
                case (?roles_set) roles_set;
                case (null) {
                    let new_set = Set.new<Nat>();
                    ignore Map.put(state.permissions, Map.thash, permission, new_set);
                    new_set;
                };
            };

            Set.add(roles_with_permission, Map.nhash, role_id);
        };

        #ok();
    };

    func format_name(name : Text) : Text {
        Text.toLower(name);
    };

    /// Validates and formats a name.
    ///
    /// Names must be non-empty and contain only alphanumeric characters,
    /// hyphens (-), underscores (_), or colons (:). The name is lowercased.
    private func validate_name(_name : Text) : Result<Text, Text> {
        let name = format_name(_name);
        if (name.size() == 0) return #err("Name cannot be empty");
        for (c in name.chars()) {
            let valid = (c >= 'a' and c <= 'z') or
                        (c >= '0' and c <= '9') or
                        c == '-' or c == '_' or c == ':';
            if (not valid) {
                return #err("Invalid name '" # _name # "'. Names must only contain alphanumeric characters, hyphens (-), underscores (_), or colons (:)");
            };
        };
        #ok(name);
    };

    private func validate_names(_names : [Text]) : Result<[Text], Text> {
        let buf = Vector.new<Text>();
        for (name in _names.vals()) {
            switch (validate_name(name)) {
                case (#err(e)) return #err(e);
                case (#ok(n)) Vector.add(buf, n);
            };
        };
        #ok(Vector.toArray(buf));
    };

    /// Validates and formats a scope segment name.
    ///
    /// Like `validate_name` but does not allow colons (:).
    /// Scope segments must only contain alphanumeric characters, hyphens (-), or underscores (_).
    private func validate_scope_name(_name : Text) : Result<Text, Text> {
        let name = format_name(_name);
        if (name.size() == 0) return #err("Scope segment cannot be empty");
        for (c in name.chars()) {
            let valid = (c >= 'a' and c <= 'z') or
                        (c >= '0' and c <= '9') or
                        c == '-' or c == '_';
            if (not valid) {
                return #err("Invalid scope segment '" # _name # "'. Scope segments must only contain alphanumeric characters, hyphens (-), or underscores (_)");
            };
        };
        #ok(name);
    };

    /// Validates and formats a resource scope.
    ///
    /// Each segment type and name must pass `validate_scope_name` rules (no colons allowed).
    /// The resource name may also be `"*"` (wildcard).
    private func validate_scope(_scope : T.ResourceScope) : Result<T.ResourceScope, Text> {
        let buf = Vector.new<T.ResourceSegment>();
        let size = _scope.size();
        var index = 0;
        
        for ((resource_type, resource_name) in _scope.vals()) {
            let vtype = switch (validate_scope_name(resource_type)) {
                case (#err(e)) return #err(e);
                case (#ok(n)) n;
            };
            let vname = if (resource_name == "*") {
                // Wildcard can only appear in the last segment
                if (index != size - 1) {
                    return #err("Wildcard '*' can only appear in the last segment of a scope. Found at position " # Nat.toText(index) # " in a scope of length " # Nat.toText(size));
                };
                "*"
            } else {
                switch (validate_scope_name(resource_name)) {
                    case (#err(e)) return #err(e);
                    case (#ok(n)) n;
                }
            };
            Vector.add(buf, (vtype, vname));
            index += 1;
        };
        #ok(Vector.toArray(buf));
    };

    let GLOBAL_SCOPE_KEY : Text = ":global";

    /// Converts a ResourceScope to a Text key for use in Map lookups.
    ///
    /// Example: `[("database", "users"), ("collection", "profiles")]` → `"database(users)/collection(profiles)"`p
    public func scope_to_key(scope : T.ResourceScope) : Text {
        var key = "";
        var first = true;
        for ((resource_type, resource_id) in scope.vals()) {
            if (not first) key #= "/";
            key #= resource_type # "(" # resource_id # ")";
            first := false;
        };

        if (Text.isEmpty(key)) {
            GLOBAL_SCOPE_KEY
        } else {
            key
        };
    };

    /// Converts a scope key string back to a ResourceScope array.
    ///
    /// Example: `"database(users)/collection(profiles)"` → `[("database", "users"), ("collection", "profiles")]`
    public func key_to_scope(key : Text) : T.ResourceScope {
        if (key == GLOBAL_SCOPE_KEY) return [];

        let segments = Vector.new<T.ResourceSegment>();
        let parts = Text.split(key, #char '/');
        for (part in parts) {
            // Parse "type(id)" format
            var resource_type = "";
            var resource_id = "";
            var in_parens = false;
            for (c in part.chars()) {
                if (c == '(') {
                    in_parens := true;
                } else if (c == ')') {
                    in_parens := false;
                } else if (in_parens) {
                    resource_id #= Text.fromChar(c);
                } else {
                    resource_type #= Text.fromChar(c);
                };
            };
            if (resource_type.size() > 0) {
                Vector.add(segments, (resource_type, resource_id));
            };
        };
        Vector.toArray(segments);
    };

    /// Adds permissions to an existing role.
    ///
    /// If a permission doesn't exist, it will be created.
    /// Returns an error if the role doesn't exist.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.addRolePermissions(store, "editor", ["delete"]);
    /// ```
    public func addRolePermissions(auth : T.VersionedStableStore, _role_name : Text, _permissions : [Text]) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let permissions = switch (validate_names(_permissions)) {
            case (#err(e)) return #err(e);
            case (#ok(ps)) ps;
        };

        let ?(role_id, role_permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        for (permission in permissions.vals()) {
            Set.add(role_permissions, Map.thash, permission);

            // Update permissions map: add this role ID to the permission's set
            let roles_with_permission = switch (Map.get(state.permissions, Map.thash, permission)) {
                case (?roles_set) roles_set;
                case (null) {
                    let new_set = Set.new<Nat>();
                    ignore Map.put(state.permissions, Map.thash, permission, new_set);
                    new_set;
                };
            };
            Set.add(roles_with_permission, Map.nhash, role_id);
        };

        #ok();
    };

    /// Gets the permissions for a specific role.
    ///
    /// Returns an error if the role doesn't exist.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(perms) = CanisterRBAC.getRolePermissions(store, "admin");
    /// // perms = ["read", "write", "manage"]
    /// ```
    public func getRolePermissions(auth : T.VersionedStableStore, _role_name : Text) : Result<[Text], Text> {
        let state = Migrations.get_current_state(auth);
        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let ?(_role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        #ok(Iter.toArray(Set.keys(permissions)));
    };

    /// Gets a role by name, returning its name and permissions.
    ///
    /// Returns an error if the role doesn't exist.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(role) = CanisterRBAC.getRole(store, "admin");
    /// // role = { name = "admin"; permissions = ["read", "write", "manage"] }
    /// ```
    public func getRole(auth : T.VersionedStableStore, _role_name : Text) : Result<(Text, [Text]), Text> {
        let state = Migrations.get_current_state(auth);
        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let ?(_role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        #ok((role_name, Iter.toArray(Set.keys(permissions))));
    };

    /// Removes permissions from a role.
    ///
    /// Returns an error if the role doesn't exist.
    /// Silently ignores permissions that the role doesn't have.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.removeRolePermissions(store, "editor", ["delete"]);
    /// ```
    public func removeRolePermissions(auth : T.VersionedStableStore, _role_name : Text, _permissions : [Text]) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let permissions = switch (validate_names(_permissions)) {
            case (#err(e)) return #err(e);
            case (#ok(ps)) ps;
        };

        let ?(role_id, role_permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        for (permission in permissions.vals()) {
            ignore Set.remove(role_permissions, Map.thash, permission);

            // Update permissions map: remove this role ID from the permission's set
            switch (Map.get(state.permissions, Map.thash, permission)) {
                case (?roles_set) {
                    ignore Set.remove(roles_set, Map.nhash, role_id);
                };
                case (null) {};
            };
        };

        #ok();
    };

    /// Renames an existing role.
    ///
    /// All existing grants are automatically updated to use the new name.
    /// Returns an error if the old role doesn't exist or if the new name is taken.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.renameRole(store, "editor", "content_editor");
    /// ```
    public func renameRole(auth : T.VersionedStableStore, _old_name : Text, _new_name : Text) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let old_name = switch (validate_name(_old_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let new_name = switch (validate_name(_new_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };

        // Get role ID and permissions
        let ?(role_id, permissions) = Map.get(state.roles, Map.thash, old_name) else return #err("Role '" # old_name # "' not found");

        // Check if new name already exists
        switch (Map.get(state.roles, Map.thash, new_name)) {
            case (?_) return #err("Role '" # new_name # "' already exists");
            case (null) {};
        };

        // Update role ID -> role name mapping (this is the only update needed for permissions!)
        ignore Map.put(state.role_ids, Map.nhash, role_id, new_name);

        // Add new role with same (role_id, permissions)
        ignore Map.put(state.roles, Map.thash, new_name, (role_id, permissions));

        // Remove old role
        ignore Map.remove(state.roles, Map.thash, old_name);

        #ok();
    };

    /// Renames a permission across all roles.
    ///
    /// All roles that have this permission will be updated.
    /// Returns an error if the old permission doesn't exist or new name is taken.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.renamePermission(store, "read", "view");
    /// ```
    public func renamePermission(auth : T.VersionedStableStore, _old_name : Text, _new_name : Text) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let old_name = switch (validate_name(_old_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let new_name = switch (validate_name(_new_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };

        // Get roles set for old permission
        let ?roles_set = Map.get(state.permissions, Map.thash, old_name) else return #err("Permission '" # old_name # "' not found");

        // Check if new permission already exists
        switch (Map.get(state.permissions, Map.thash, new_name)) {
            case (?_) return #err("Permission '" # new_name # "' already exists");
            case (null) {};
        };

        // Replace the permission name in each role's permissions set
        for (role_id in Set.keys(roles_set)) {
            // Get role name from role ID
            let ?role_name = Map.get(state.role_ids, Map.nhash, role_id) else Runtime.trap("Roles.renamePermission: Role ID not found");
            let ?(_role_id, role_permissions) = Map.get(state.roles, Map.thash, role_name) else Runtime.trap("Roles.renamePermission: Role not found");

            // Remove old permission and add new permission
            ignore Set.remove(role_permissions, Map.thash, old_name);
            Set.add(role_permissions, Map.thash, new_name);
        };

        // Add new permission with same roles set
        ignore Map.put(state.permissions, Map.thash, new_name, roles_set);

        // Remove old permission
        ignore Map.remove(state.permissions, Map.thash, old_name);

        #ok();
    };

    /// Deletes a permission from all roles.
    ///
    /// The permission is removed from every role that has it.
    /// Returns an error if the permission doesn't exist.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.deletePermission(store, "deprecated_permission");
    /// ```
    public func deletePermission(auth : T.VersionedStableStore, _permission_name : Text) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let permission_name = switch (validate_name(_permission_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };

        // Get roles set for this permission
        let ?roles_set = Map.get(state.permissions, Map.thash, permission_name) else return #err("Permission '" # permission_name # "' not found");

        // Remove the permission from each role's permissions set
        for (role_id in Set.keys(roles_set)) {
            let ?role_name = Map.get(state.role_ids, Map.nhash, role_id) else Runtime.trap("CanisterRBAC.deletePermission: Role ID not found");
            let ?(_role_id, role_permissions) = Map.get(state.roles, Map.thash, role_name) else Runtime.trap("CanisterRBAC.deletePermission: Role not found");

            ignore Set.remove(role_permissions, Map.thash, permission_name);
        };

        // Remove the permission from the permissions map
        ignore Map.remove(state.permissions, Map.thash, permission_name);

        #ok();
    };

    /// Gets all permissions in the store.
    ///
    /// Returns an array of all permission names.
    ///
    /// Example:
    /// ```motoko
    /// let perms = CanisterRBAC.getAllPermissions(store);
    /// // perms = ["read", "write", "manage", "delete"]
    /// ```
    public func getAllPermissions(auth : T.VersionedStableStore) : [Text] {
        let state = Migrations.get_current_state(auth);
        Iter.toArray(Map.keys(state.permissions));
    };

    /// Gets all roles with their permissions.
    ///
    /// Returns an array of tuples containing role names and their permissions.
    ///
    /// Example:
    /// ```motoko
    /// let roles = CanisterRBAC.getAllRoles(store);
    /// // roles = [("admin", ["read", "write", "manage"]), ("viewer", ["read"])]
    /// ```
    public func getAllRoles(auth : T.VersionedStableStore) : [(Text, [Text])] {
        let state = Migrations.get_current_state(auth);
        let results = Vector.new<(Text, [Text])>();
        for ((role_name, (_, permissions)) in Map.entries(state.roles)) {
            Vector.add(results, (role_name, Iter.toArray(Set.keys(permissions))));
        };
        Vector.toArray(results);
    };

    /// Gets all roles that have a specific permission.
    ///
    /// Returns an array of tuples containing role names and all their permissions.
    ///
    /// Example:
    /// ```motoko
    /// let roles = CanisterRBAC.getRolesWithPermission(store, "write");
    /// // Returns all roles that can write
    /// ```
    public func getRolesWithPermission(auth : T.VersionedStableStore, _permission_name : Text) : Result<[(Text, [Text])], Text> {
        let state = Migrations.get_current_state(auth);
        let permission_name = switch (validate_name(_permission_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let roles_buffer = Vector.new<(Text, [Text])>();

        switch (Map.get(state.permissions, Map.thash, permission_name)) {
            case (?role_ids_set) {
                for (role_id in Set.keys(role_ids_set)) {
                    let ?role_name = Map.get(state.role_ids, Map.nhash, role_id) else Runtime.trap("Roles.getRolesWithPermission: Role ID not found");
                    let ?(_role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else Runtime.trap("Roles.getRolesWithPermission: Role not found");

                    Vector.add(roles_buffer, (role_name, Iter.toArray(Set.keys(permissions))));
                };
            };
            case (null) {};
        };

        #ok(Vector.toArray(roles_buffer));
    };

    /// Deletes a role and removes all grants for that role.
    ///
    /// All users who had this role will lose it.
    /// Returns an error if the role doesn't exist.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.deleteRole(store, "temporary_role");
    /// ```
    public func deleteRole(auth : T.VersionedStableStore, _role_name : Text) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);
        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };

        // Get role ID and permissions
        let ?(role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        // Remove role from all permission sets in bidirectional map using role ID
        for (permission in Set.keys(permissions)) {
            switch (Map.get(state.permissions, Map.thash, permission)) {
                case (?roles_set) {
                    ignore Set.remove(roles_set, Map.nhash, role_id);
                };
                case (null) {};
            };
        };

        // Remove role from roles map
        ignore Map.remove(state.roles, Map.thash, role_name);

        // Remove role ID mapping
        ignore Map.remove(state.role_ids, Map.nhash, role_id);

        // Remove role grants from role_grants index
        ignore Map.remove(state.role_grants, Map.nhash, role_id);

        #ok();
    };

    /// Grants a role to a user at a specific resource scope.
    ///
    /// The grant is idempotent - granting the same role+scope twice has no effect.
    /// Use an empty scope `[]` for global/cluster-wide access.
    ///
    /// Example:
    /// ```motoko
    /// // Global admin access
    /// let #ok(_) = CanisterRBAC.grantUserRole(store, user, "admin", []);
    ///
    /// // Scoped editor access
    /// let #ok(_) = CanisterRBAC.grantUserRole(store, user, "editor", [("database", "users")]);
    /// ```
    public func grantUserRole(auth : T.VersionedStableStore, user : Principal, _role_name : Text, _resource_scope : T.ResourceScope) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);

        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let resource_scope = switch (validate_scope(_resource_scope)) {
            case (#err(e)) return #err(e);
            case (#ok(s)) s;
        };

        let ?(role_id, _permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        let resource_key = scope_to_key(resource_scope);
        let resources_with_role_map = switch (Map.get(state.role_grants, Map.nhash, role_id)) {
            case (?map) map;
            case (null) {
                let new_map = Map.new<Text, Set<Principal>>();
                ignore Map.put(state.role_grants, Map.nhash, role_id, new_map);
                new_map;
            };
        };

        let users_with_role_set = switch (Map.get(resources_with_role_map, Map.thash, resource_key)) {
            case (?set) set;
            case (null) {
                let new_set = Set.new<Principal>();
                ignore Map.put(resources_with_role_map, Map.thash, resource_key, new_set);
                new_set;
            };
        };

        ignore Set.put(users_with_role_set, Map.phash, user);

        #ok();
    };

    /// Revokes a role from a user at a specific resource scope.
    ///
    /// Only revokes the exact scope specified - parent or child grants are unaffected.
    /// Returns an error if the user doesn't have this role at the specified scope.
    ///
    /// Example:
    /// ```motoko
    /// let #ok(_) = CanisterRBAC.revokeUserRole(store, user, "editor", [("database", "users")]);
    /// ```
    public func revokeUserRole(auth : T.VersionedStableStore, user : Principal, _role_name : Text, _resource_scope : T.ResourceScope) : Result<(), Text> {
        let state = Migrations.get_current_state(auth);

        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let resource_scope = switch (validate_scope(_resource_scope)) {
            case (#err(e)) return #err(e);
            case (#ok(s)) s;
        };

        let ?(role_id, _permissions) = Map.get(state.roles, Map.thash, role_name) else return #err("Role '" # role_name # "' not found");

        let resource_key = scope_to_key(resource_scope);
        let ?resources_with_role_map = Map.get(state.role_grants, Map.nhash, role_id) else return #err("No grants found for role");

        let ?users_with_role_set = Map.get(resources_with_role_map, Map.thash, resource_key) else return #err("No users found with role at specified scope");

        if (not Set.has(users_with_role_set, Map.phash, user)) {
            return #err("User does not have the specified role at the given scope");
        };

        ignore Set.remove(users_with_role_set, Map.phash, user);

        if (Set.size(users_with_role_set) == 0) {
            ignore Map.remove(resources_with_role_map, Map.thash, resource_key);
        };

        if (Map.size(resources_with_role_map) == 0) {
            ignore Map.remove(state.role_grants, Map.nhash, role_id);
        };

        #ok();
    };

    /// Generates the hierarchy of parent scopes for a given resource scope.
    ///
    /// The hierarchy includes:
    /// 1. The exact scope
    /// 2. Wildcard variants at each level
    /// 3. Parent scopes (progressively shorter)
    /// 4. The global scope
    ///
    /// This is used internally for hierarchical permission checking.
    ///
    /// Example:
    /// ```motoko
    /// let hierarchy = CanisterRBAC.getScopeHierarchy([("database", "users"), ("collection", "profiles")]);
    /// // Returns:
    /// // [
    /// //   [("database", "users"), ("collection", "profiles")],
    /// //   [("database", "users"), ("collection", "*")],
    /// //   [("database", "users")],
    /// //   [("database", "*")],
    /// //   []
    /// // ]
    /// ```
    public func getScopeHierarchy(resource_scope : T.ResourceScope) : [T.ResourceScope] {
        let keys_buffer = Vector.new<T.ResourceScope>();
        let size = resource_scope.size();

        // Empty scope -> only global entry
        if (size == 0) {
            return [[]]; // Only the global scope
        };

        // Always start with the full scope
        Vector.add(keys_buffer, resource_scope);

        // Walk backwards through the scope hierarchy
        var i = Nat.sub(size, 1);
        label hierarchy_loop loop {
            let (key, val) = resource_scope[i];

            // Add wildcard variant at this level if not already a wildcard
            if (val != "*") {
                let prefix = if (i == 0) [] else Array.sliceToArray(resource_scope, 0, i);
                Vector.add(keys_buffer, Array.concat(prefix, [(key, "*")]));
            };

            if (i == 0) break hierarchy_loop;
            i := Nat.sub(i, 1);

            // After moving to previous level, add the concrete prefix at i+1
            let concrete_prefix = Array.sliceToArray(resource_scope, 0, Nat.add(i, 1));
            Vector.add(keys_buffer, concrete_prefix);
        };

        // Add global scope
        Vector.add(keys_buffer, []);

        Vector.toArray(keys_buffer);
    };

    /// Checks if a user has a specific permission at a resource scope.
    ///
    /// This function walks up the scope hierarchy, so a user with access at a
    /// parent scope will have access to all child scopes.
    ///
    /// Example:
    /// ```motoko
    /// // User has "editor" role at database level
    /// let #ok(_) = CanisterRBAC.grantUserRole(store, user, "editor", [("database", "users")]);
    ///
    /// // Check passes for child scope
    /// let allowed = CanisterRBAC.hasPermission(
    ///     store, user, "write",
    ///     [("database", "users"), ("collection", "profiles")]
    /// ); // true
    /// ```
    public func hasPermission(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope) : Bool {
        let state = Migrations.get_current_state(auth);

        let permission = format_name(_permission);
        let resource_scope = Array.map(
            _resource_scope,
            func((resource_type, resource_name) : T.ResourceSegment) : T.ResourceSegment {
                (format_name(resource_type), format_name(resource_name));
            },
        );

        let roles_with_permission = switch (Map.get(state.permissions, Map.thash, permission)) {
            case (?role_ids_set) role_ids_set;
            case (null) return false;
        };

        let resource_scope_hierarchy_list = getScopeHierarchy(resource_scope);

        for (scope in resource_scope_hierarchy_list.vals()) {
            let resource_key = scope_to_key(scope);

            for (role_id in Set.keys(roles_with_permission)) {
                switch (Map.get(state.role_grants, Map.nhash, role_id)) {
                    case (null) {};
                    case (?resources_with_role_map) {
                        switch (Map.get<Text, Set.Set<Principal>>(resources_with_role_map, Map.thash, resource_key)) {
                            case (?users_set) {
                                if (Set.has(users_set, Map.phash, user)) {
                                    return true;
                                };
                            };
                            case (null) {};
                        };
                    };
                };
            };
        };

        false;
    };

    /// Executes a callback if the user has the required permission.
    ///
    /// Returns `#ok(result)` if allowed, or `#err(message)` if denied.
    ///
    /// Example:
    /// ```motoko
    /// let result = CanisterRBAC.allow<Text>(
    ///     store, caller, "read", [("database", "users")],
    ///     func() : Text { "Data from users database" }
    /// );
    /// ```
    public func allow<A>(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> A) : Result<A, Text> {
        if (hasPermission(auth, user, _permission, _resource_scope)) {
            #ok(callback());
        } else {
            #err("User does not have permission '" # _permission # "' for the specified resource: " # scope_to_key(_resource_scope));
        };
    };

    /// Executes a callback if allowed, trapping on permission failure.
    ///
    /// Use `allow()` or `allowVoid()` for a testable, non-trapping alternative.
    ///
    /// Example:
    /// ```motoko
    /// let data = CanisterRBAC.requirePermission<Text>(store, caller, "read", [], func() {
    ///     "sensitive data"
    /// });
    /// ```
    public func requirePermission<A>(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> A) : A {
        switch (allow<A>(auth, user, _permission, _resource_scope, callback)) {
            case (#ok(result)) result;
            case (#err(err_msg)) Runtime.trap(err_msg);
        };
    };

    /// Executes a void callback if the user has the required permission.
    ///
    /// Convenience wrapper for callbacks that don't return a value.
    ///
    /// Example:
    /// ```motoko
    /// let result = CanisterRBAC.allowVoid(store, caller, "write", scope, func() {
    ///     // Perform write operation
    /// });
    /// ```
    public func allowVoid(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> ()) : Result<(), Text> {
        allow<()>(auth, user, _permission, _resource_scope, func() : () { callback(); () });
    };

    /// Executes a callback that returns a Result if the user has permission.
    ///
    /// Useful when the underlying operation can also fail.
    ///
    /// Example:
    /// ```motoko
    /// let result = CanisterRBAC.allowWithResult<Nat>(
    ///     store, caller, "write", scope,
    ///     func() : Result<Nat, Text> {
    ///         // Operation that might fail
    ///         #ok(42)
    ///     }
    /// );
    /// ```
    public func allowWithResult<A>(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> Result<A, Text>) : Result<A, Text> {
        if (hasPermission(auth, user, _permission, _resource_scope)) {
            callback();
        } else {
            #err("User does not have permission '" # _permission # "' for the specified resource: " # scope_to_key(_resource_scope));
        };
    };

    public func allowOrTrap(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> ()) : () {
        switch (allowVoid(auth, user, _permission, _resource_scope, callback)) {
            case (#ok(_)) ();
            case (#err(err_msg)) Runtime.trap(err_msg);
        };
    };

    // public func allowOrThrowError<A>(auth : T.VersionedStableStore, user : Principal, _permission : Text, _resource_scope : T.ResourceScope, callback : () -> A) : A {
    //     switch (allow(auth, user, _permission, _resource_scope, callback)) {
    //         case (#ok(response)) response;
    //         case (#err(err_msg)) throw Error.reject(err_msg);
    //     };
    // };

    /// Gets all authorization info for a specific user.
    ///
    /// Returns an array of all grants with scope, role, and permissions.
    ///
    /// Example:
    /// ```motoko
    /// let auth_info = CanisterRBAC.getUserGrants(store, user);
    /// // Returns: [([(“database”, “users”)], "editor", ["read", "write"]), ...]
    /// ```
    public func getUserGrants(auth : T.VersionedStableStore, user : Principal) : [(resource_scope : T.ResourceScope, role : Text, permissions : [Text])] {
        let state = Migrations.get_current_state(auth);

        let user_auth_buffer = Vector.new<(resource_scope : T.ResourceScope, role : Text, permissions : [Text])>();

        for ((role_id, scope_map) in Map.entries(state.role_grants)) {
            for ((scope_key, users) in Map.entries(scope_map)) {
                if (Set.has(users, Map.phash, user)) {
                    switch (Map.get(state.role_ids, Map.nhash, role_id)) {
                        case (?role_name) {
                            let ?(_role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else Runtime.trap("CanisterRBAC.getUserGrants: Role not found");

                            Vector.add(user_auth_buffer, (key_to_scope(scope_key), role_name, Iter.toArray(Set.keys(permissions))));
                        };
                        case (null) {};
                    };
                };
            };
        };

        return Vector.toArray(user_auth_buffer);
    };

    /// Gets all user authorizations in the system.
    ///
    /// Returns a map of all principals to their grants.
    ///
    /// Example:
    /// ```motoko
    /// let all_auth = CanisterRBAC.getAllUserGrants(store);
    /// // Returns: [(principal1, [...grants...]), (principal2, [...grants...]), ...]
    /// ```
    public func getAllUserGrants(auth : T.VersionedStableStore) : [(Principal, [(resource_scope : T.ResourceScope, role : Text, permissions : [Text])])] {
        let state = Migrations.get_current_state(auth);
        // Build a map of user -> [(resource_scope, role, permissions)]
        let users_map = Map.new<Principal, Vector<(resource_scope : T.ResourceScope, role : Text, permissions : [Text])>>();

        for ((role_id, scope_map) in Map.entries(state.role_grants)) {
            for ((scope_key, users) in Map.entries(scope_map)) {
                for (user in Set.keys(users)) {
                    let user_roles = switch (Map.get(users_map, Map.phash, user)) {
                        case (?vec) vec;
                        case (null) {
                            let new_vec = Vector.new<(resource_scope : T.ResourceScope, role : Text, permissions : [Text])>();
                            ignore Map.put(users_map, Map.phash, user, new_vec);
                            new_vec;
                        };
                    };

                    switch (Map.get(state.role_ids, Map.nhash, role_id)) {
                        case (?role_name) {
                            let ?(_role_id, permissions) = Map.get(state.roles, Map.thash, role_name) else Runtime.trap("CanisterRBAC.getAllUserGrants: Role not found");

                            Vector.add(user_roles, (key_to_scope(scope_key), role_name, Iter.toArray(Set.keys(permissions))));
                        };
                        case (null) {};
                    };
                };
            };
        };

        // Collect results into a vector then convert to array
        let result_vec = Vector.new<(Principal, [(resource_scope : T.ResourceScope, role : Text, permissions : [Text])])>();

        for ((user, roles_vec) in Map.entries(users_map)) {
            Vector.add(result_vec, (user, Vector.toArray(roles_vec)));
        };

        Vector.toArray(result_vec);
    };

    /// Gets all users who have a specific role with access to a resource scope.
    ///
    /// This checks hierarchically - users with grants at parent scopes or
    /// wildcard scopes that cover the requested scope are included.
    ///
    /// Example:
    /// ```motoko
    /// // Get all users who can edit the users database (directly or via wildcards)
    /// let editors = CanisterRBAC.getUsersWithRole(
    ///     store, "editor", [("database", "users")]
    /// );
    /// ```
    public func getUsersWithRole(auth : T.VersionedStableStore, _role_name : Text, _resource_scope : T.ResourceScope) : Result<[Principal], Text> {
        let state = Migrations.get_current_state(auth);

        let role_name = switch (validate_name(_role_name)) {
            case (#err(e)) return #err(e);
            case (#ok(n)) n;
        };
        let resource_scope = switch (validate_scope(_resource_scope)) {
            case (#err(e)) return #err(e);
            case (#ok(s)) s;
        };

        let ?(role_id, _permissions) = Map.get(state.roles, Map.thash, role_name) else return #ok([]);
        let ?resources_with_role_map = Map.get(state.role_grants, Map.nhash, role_id) else return #ok([]);

        // Collect users from all matching scopes in the hierarchy
        let users_set = Set.new<Principal>();
        let scope_hierarchy = getScopeHierarchy(resource_scope);

        for (scope in scope_hierarchy.vals()) {
            let scope_key = scope_to_key(scope);
            switch (Map.get(resources_with_role_map, Map.thash, scope_key)) {
                case (?scope_users) {
                    for (user in Set.keys(scope_users)) {
                        Set.add(users_set, Map.phash, user);
                    };
                };
                case (null) {};
            };
        };

        #ok(Iter.toArray(Set.keys(users_set)));
    };

};
