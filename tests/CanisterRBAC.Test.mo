// @testmode wasi
import Debug "mo:base/Debug";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Result "mo:core@2.0.0/Result";
import Array "mo:base/Array";
import { test; suite } "mo:test";

import CanisterRBAC "../src";

suite(
    "CanisterRBAC Tests",
    func() {
        let alice = Principal.fromText("un4fu-tqaaa-aaaab-qadjq-cai");
        let bob = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");
        let charlie = Principal.fromText("6rgy7-3uukz-jrj2k-crt3v-u2wjm-dmn3t-p26d6-ndilt-3gusv-75ybk-jae");

        // Helper function to assert that array contains expected values
        func arrayContains<T>(arr : [T], expected : [T], equals : (T, T) -> Bool) : Bool {
            for (value in expected.vals()) {
                let found = Array.find(arr, func(item : T) : Bool { equals(item, value) });
                switch (found) {
                    case (null) return false;
                    case (?_) {};
                };
            };
            return true;
        };

        // Helper function to assert that array does not contain values
        func assertNotContains<T>(arr : [T], notExpected : [T], equals : (T, T) -> Bool) : Bool {
            for (value in notExpected.vals()) {
                let found = Array.find(arr, func(item : T) : Bool { equals(item, value) });
                switch (found) {
                    case (null) {};
                    case (?_) return false;
                };
            };
            return true;
        };

        // Helper for Text arrays
        func arrayContainsText(arr : [Text], expected : [Text]) : Bool {
            arrayContains(arr, expected, Text.equal);
        };

        // Helper for Text arrays (not contains)
        func assertNotContainsText(arr : [Text], notExpected : [Text]) : Bool {
            assertNotContains(arr, notExpected, Text.equal);
        };

        // Helper for role tuples
        func arrayContainsRole(roles : [(Text, [Text])], expected : [Text]) : Bool {
            for (roleName in expected.vals()) {
                let found = Array.find(roles, func((name, _) : (Text, [Text])) : Bool { name == roleName });
                switch (found) {
                    case (null) return false;
                    case (?_) {};
                };
            };
            return true;
        };

        // Helper for Principal arrays
        func arrayContainsPrincipal(arr : [Principal], expected : [Principal]) : Bool {
            arrayContains(arr, expected, Principal.equal);
        };


        suite(
            "Initialization",
            func() {
                test(
                    "initRoles() creates store with initial roles",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "admin";
                                permissions = ["read", "write", "manage"];
                            },
                            {
                                name = "viewer";
                                permissions = ["read"];
                            },
                        ]);

                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 2;
                        assert arrayContainsRole(roles, ["admin", "viewer"]);

                        let #ok(admin_perms) = CanisterRBAC.getRolePermissions(store, "admin") else Debug.trap("Failed to get admin permissions");
                        assert admin_perms.size() == 3;
                        assert arrayContainsText(admin_perms, ["read", "write", "manage"]);

                        let #ok(viewer_perms) = CanisterRBAC.getRolePermissions(store, "viewer") else Debug.trap("Failed to get viewer permissions");
                        assert viewer_perms.size() == 1;
                        assert arrayContainsText(viewer_perms, ["read"]);
                    },
                );

                test(
                    "new() creates empty store",
                    func() {
                        let store = CanisterRBAC.new();
                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 0;
                    },
                );
            },
        );

        suite(
            "Role Management",
            func() {
                test(
                    "createRole() adds new role",
                    func() {
                        let store = CanisterRBAC.new();

                        let #ok(_) = CanisterRBAC.createRole(
                            store,
                            "editor",
                            ["read"],
                        ) else Debug.trap("Failed to create role");

                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 1;
                        assert arrayContainsRole(roles, ["editor"]);
                        let (_, perms) = roles[0];
                        assert arrayContainsText(perms, ["read"]);
                    },
                );

                test(
                    "addRolePermissions() adds permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "viewer";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.addRolePermissions(store, "viewer", ["write"]) else Debug.trap("Failed to add permissions");

                        let #ok(perms) = CanisterRBAC.getRolePermissions(store, "viewer") else Debug.trap("Failed to get permissions");
                        assert perms.size() == 2;
                        assert arrayContainsText(perms, ["read", "write"]);
                    },
                );

                test(
                    "removeRolePermissions() removes permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read", "write", "manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.removeRolePermissions(store, "admin", ["manage"]) else Debug.trap("Failed to remove permission");

                        let #ok(perms) = CanisterRBAC.getRolePermissions(store, "admin") else Debug.trap("Failed to get permissions");
                        assert perms.size() == 2;
                        assert arrayContainsText(perms, ["read", "write"]);
                        assert assertNotContainsText(perms, ["manage"]);
                    },
                );

                test(
                    "renameRole() renames existing role",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "old_name";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.getRolePermissions(store, "old_name") else Debug.trap("Old role name not found");

                        let #ok(_) = CanisterRBAC.renameRole(store, "old_name", "new_name") else Debug.trap("Failed to rename role");

                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 1;
                        let (role_name, role_perms) = roles[0];
                        assert role_name == "new_name";
                        assert role_perms.size() == 1;
                        assert arrayContainsText(role_perms, ["read"]);

                        let #ok(_) = CanisterRBAC.getRolePermissions(store, "new_name") else Debug.trap("New role name not found");
                        let #err(_) = CanisterRBAC.getRolePermissions(store, "old_name") else Debug.trap("Old role name still exists");
                    },
                );

                test(
                    "deleteRole() removes role",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "admin"; permissions = ["read", "write"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let #ok(_) = CanisterRBAC.deleteRole(store, "viewer") else Debug.trap("Failed to delete role");

                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 1;
                        let (remaining_role, _) = roles[0];
                        assert remaining_role == "admin";
                    },
                );
            },
        );

        suite(
            "Role Assignment - Cluster-wide",
            func() {
                test(
                    "grantUserRole() grants cluster-wide access",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read", "write"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed to grant role");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 1;
                        let (_, role0, perms0) = user_auth[0];
                        assert role0 == "admin";
                        assert arrayContainsText(perms0, ["read", "write"]);
                    },
                );

                test(
                    "grantUserRole() allows duplicate cluster-wide assignments (idempotent)",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("First grant failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Second grant failed");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 1;
                        let (_, role, perms) = user_auth[0];
                        assert role == "admin";
                        assert arrayContainsText(perms, ["read"]);
                    },
                );

                test(
                    "revokeUserRole() removes cluster-wide role",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed to grant");
                        let #ok(_) = CanisterRBAC.revokeUserRole(store, alice, "admin", []) else Debug.trap("Failed to revoke");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 0;
                    },
                );
            },
        );

        suite(
            "Role Assignment - Resource Scoped",
            func() {
                test(
                    "grantUserRole() grants scoped access",
                    func() {

                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["read", "write"];
                        }]);

                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", scope) else Debug.trap("Failed to grant scoped role");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 1;
                        let (rs1, role1, perms1) = user_auth[0];
                        assert role1 == "editor";
                        assert rs1 == [("database", "users")];
                        assert arrayContainsText(perms1, ["read", "write"]);
                    },
                );

                test(
                    "grantUserRole() stores hierarchical scopes separately",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let db_scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let coll_scope : CanisterRBAC.Types.ResourceScope = [("database", "users"), ("collection", "profiles")];

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", db_scope) else Debug.trap("Failed to grant db scope");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", coll_scope) else Debug.trap("Failed to grant coll scope");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        // Note: New implementation stores both scopes separately
                        assert user_auth.size() == 2;
                        for ((_, role, perms) in user_auth.vals()) {
                            assert role == "editor";
                            assert arrayContainsText(perms, ["write"]);
                        };
                    },
                );

                test(
                    "revokeUserRole() removes specific scoped role",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let scope1 : CanisterRBAC.Types.ResourceScope = [("database", "db1")];
                        let scope2 : CanisterRBAC.Types.ResourceScope = [("database", "db2")];

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", scope1) else Debug.trap("Failed to grant scope1");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", scope2) else Debug.trap("Failed to grant scope2");

                        let #ok(_) = CanisterRBAC.revokeUserRole(store, alice, "editor", scope1) else Debug.trap("Failed to revoke scope1");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 1;
                        let (rs2, role2, perms2) = user_auth[0];
                        assert role2 == "editor";
                        assert rs2 == [("database", "db2")];
                        assert arrayContainsText(perms2, ["write"]);
                    },
                );
            },
        );

        suite(
            "Permission Checking",
            func() {
                test(
                    "hasPermission() checks cluster-wide permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read", "write", "manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed to grant");

                        assert CanisterRBAC.hasPermission(store, alice, "read", []);
                        assert CanisterRBAC.hasPermission(store, alice, "write", []);
                        assert CanisterRBAC.hasPermission(store, alice, "manage", []);
                        assert not CanisterRBAC.hasPermission(store, alice, "delete", []);
                    },
                );

                test(
                    "hasPermission() checks scoped permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["read", "write"];
                        }]);

                        let db_scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", db_scope) else Debug.trap("Failed to grant");

                        // Should have permission for exact scope
                        assert CanisterRBAC.hasPermission(store, alice, "write", db_scope);

                        // Should have permission for child scope (hierarchical permission checking)
                        let coll_scope : CanisterRBAC.Types.ResourceScope = [("database", "users"), ("collection", "profiles")];
                        assert CanisterRBAC.hasPermission(store, alice, "write", coll_scope);

                        // Should NOT have permission for different scope
                        let other_scope : CanisterRBAC.Types.ResourceScope = [("database", "products")];
                        assert not CanisterRBAC.hasPermission(store, alice, "write", other_scope);
                    },
                );

                test(
                    "hasPermission() supports wildcard scope grants",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        let wildcard_scope : CanisterRBAC.Types.ResourceScope = [("database", "*")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", wildcard_scope) else Debug.trap("Failed to grant");

                        // Wildcard grants apply to specific resources via hierarchy checking
                        let specific_scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        assert CanisterRBAC.hasPermission(store, alice, "manage", specific_scope);

                        let specific_subscope : CanisterRBAC.Types.ResourceScope = [("database", "users"), ("collection", "profiles")];
                        assert CanisterRBAC.hasPermission(store, alice, "manage", specific_subscope);

                        // Exact wildcard match also works
                        assert CanisterRBAC.hasPermission(store, alice, "manage", wildcard_scope);

                        // Different resource type should not match
                        let different_type : CanisterRBAC.Types.ResourceScope = [("table", "users")];
                        assert not CanisterRBAC.hasPermission(store, alice, "manage", different_type);
                    },
                );

                test(
                    "hasPermission() returns false for non-existent user",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        assert not CanisterRBAC.hasPermission(store, alice, "read", []);
                    },
                );
            },
        );

        suite(
            "Versioning",
            func() {
                test(
                    "upgrade() handles v0_1_0",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let inner = CanisterRBAC.get_current_state(store);
                        let versioned : CanisterRBAC.Types.PrevVersionedStableStore = #v0_1_0(inner);
                        let upgraded = CanisterRBAC.upgrade(versioned);

                        switch (upgraded) { case (#v0_1_0(_)) {} };
                    },
                );

                test(
                    "get_current_state() extracts state",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "viewer";
                            permissions = ["read"];
                        }]);

                        let roles = CanisterRBAC.getAllRoles(store);
                        assert roles.size() == 1;
                        assert arrayContainsRole(roles, ["viewer"]);
                        let (_, perms) = roles[0];
                        assert arrayContainsText(perms, ["read"]);
                    },
                );

                test(
                    "version_to_text() returns version string",
                    func() {
                        let store = CanisterRBAC.new();
                        let inner = CanisterRBAC.get_current_state(store);
                        let versioned : CanisterRBAC.Types.PrevVersionedStableStore = #v0_1_0(inner);

                        let version_text = CanisterRBAC.version_to_text(versioned);
                        assert version_text == "v0.1.0";
                    },
                );
            },
        );

        suite(
            "Permission Helper Functions",
            func() {
                test(
                    "allow() executes callback when user has permission",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed to grant");

                        let result = CanisterRBAC.allow<Nat>(store, alice, "read", [], func() : Nat { 42 });

                        switch (result) {
                            case (#ok(value)) assert value == 42;
                            case (#err(_)) Debug.trap("Should have allowed access");
                        };
                    },
                );

                test(
                    "allow() returns error when user lacks permission",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "viewer";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "viewer", []) else Debug.trap("Failed to grant");

                        let result = CanisterRBAC.allow<Nat>(store, alice, "write", [], func() : Nat { 42 });

                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have denied access");
                            case (#err(msg)) assert Text.contains(msg, #text "does not have permission");
                        };
                    },
                );

                test(
                    "allowVoid() works with void callbacks",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed to grant");

                        var executed = false;
                        let result = CanisterRBAC.allowVoid(store, alice, "manage", [], func() { executed := true });

                        switch (result) {
                            case (#ok(_)) assert executed;
                            case (#err(_)) Debug.trap("Should have allowed access");
                        };
                    },
                );

                test(
                    "allowWithResult() executes callback returning Result",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", []) else Debug.trap("Failed to grant");

                        let result = CanisterRBAC.allowWithResult<Text>(
                            store,
                            alice,
                            "write",
                            [],
                            func() : Result.Result<Text, Text> {
                                #ok("success");
                            },
                        );

                        switch (result) {
                            case (#ok(value)) assert value == "success";
                            case (#err(_)) Debug.trap("Should have allowed access");
                        };
                    },
                );
            },
        );

        suite(
            "Permission Management",
            func() {
                test(
                    "createPermission() creates new permission",
                    func() {
                        let store = CanisterRBAC.new();
                        let #ok(_) = CanisterRBAC.createPermission(store, "delete") else Debug.trap("Failed to create permission");

                        let permissions = CanisterRBAC.getAllPermissions(store);
                        assert permissions.size() == 1;
                        assert arrayContainsText(permissions, ["delete"]);
                    },
                );

                test(
                    "getAllPermissions() returns all permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "admin";
                                permissions = ["read", "write", "manage"];
                            },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let permissions = CanisterRBAC.getAllPermissions(store);
                        assert permissions.size() == 3;
                        assert arrayContainsText(permissions, ["read", "write", "manage"]);
                    },
                );

                test(
                    "getRolesWithPermission() returns roles with specific permission",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "admin"; permissions = ["read", "write"] },
                            { name = "editor"; permissions = ["read", "write"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let #ok(roles_with_write) = CanisterRBAC.getRolesWithPermission(store, "write") else Debug.trap("Failed");
                        assert roles_with_write.size() == 2;
                        assert arrayContainsRole(roles_with_write, ["admin", "editor"]);

                        let #ok(roles_with_read) = CanisterRBAC.getRolesWithPermission(store, "read") else Debug.trap("Failed");
                        assert roles_with_read.size() == 3;
                        assert arrayContainsRole(roles_with_read, ["admin", "editor", "viewer"]);
                    },
                );

                test(
                    "renamePermission() renames permission across all roles",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "admin";
                                permissions = ["old_perm", "other"];
                            },
                            { name = "viewer"; permissions = ["old_perm"] },
                        ]);

                        let #ok(_) = CanisterRBAC.renamePermission(store, "old_perm", "new_perm") else Debug.trap("Failed to rename");

                        let #ok(admin_perms) = CanisterRBAC.getRolePermissions(store, "admin") else Debug.trap("Failed to get admin perms");
                        let #ok(viewer_perms) = CanisterRBAC.getRolePermissions(store, "viewer") else Debug.trap("Failed to get viewer perms");

                        // Check new_perm exists in both roles
                        assert arrayContainsText(admin_perms, ["new_perm"]);
                        assert arrayContainsText(viewer_perms, ["new_perm"]);

                        // Check old_perm doesn't exist
                        assert assertNotContainsText(admin_perms, ["old_perm"]);
                    },
                );
            },
        );

        suite(
            "User Query Functions",
            func() {
                test(
                    "getUsersWithRole() returns users with specific role at scope",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", scope) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "editor", scope) else Debug.trap("Failed");

                        let #ok(users) = CanisterRBAC.getUsersWithRole(store, "editor", scope) else Debug.trap("Failed");
                        assert users.size() == 2;
                        assert arrayContainsPrincipal(users, [alice, bob]);
                    },
                );

                test(
                    "getUsersWithRole() includes users with parent scope grants",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        // Alice has editor at database level
                        let db_scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", db_scope) else Debug.trap("Failed");

                        // Bob has editor at collection level
                        let coll_scope : CanisterRBAC.Types.ResourceScope = [("database", "users"), ("collection", "profiles")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "editor", coll_scope) else Debug.trap("Failed");

                        // Charlie has editor with wildcard
                        let wildcard_scope : CanisterRBAC.Types.ResourceScope = [("database", "*")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, charlie, "editor", wildcard_scope) else Debug.trap("Failed");

                        // Query for collection level - should include Alice (parent), Bob (exact), and Charlie (wildcard)
                        let #ok(users) = CanisterRBAC.getUsersWithRole(store, "editor", coll_scope) else Debug.trap("Failed");
                        assert users.size() == 3;
                        assert arrayContainsPrincipal(users, [alice, bob, charlie]);
                    },
                );

                test(
                    "getUserGrants() returns detailed auth info for user",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "admin"; permissions = ["read", "write"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "viewer", [("project", "demo")]) else Debug.trap("Failed");

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 2;
                        // Verify both roles are present
                        let roles = Array.map(user_auth, func((_, role, _) : (CanisterRBAC.Types.ResourceScope, Text, [Text])) : Text { role });
                        assert arrayContainsText(roles, ["admin", "viewer"]);
                    },
                );
            },
        );

        suite(
            "Multiple Users",
            func() {
                test(
                    "getAllUserGrants() returns all user assignments",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "admin"; permissions = ["manage"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "viewer", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, charlie, "admin", []) else Debug.trap("Failed");

                        let all_users = CanisterRBAC.getAllUserGrants(store);
                        assert all_users.size() == 3;
                        // Verify all three users are present
                        let users = Array.map(all_users, func((principal, _) : (Principal, [(CanisterRBAC.Types.ResourceScope, Text, [Text])])) : Principal { principal });
                        assert arrayContainsPrincipal(users, [alice, bob, charlie]);
                    },
                );

                test(
                    "renameRole() updates all user assignments",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "old_role";
                            permissions = ["read"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "old_role", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "old_role", []) else Debug.trap("Failed");

                        let #ok(_) = CanisterRBAC.renameRole(store, "old_role", "new_role") else Debug.trap("Failed to rename");

                        let alice_auth = CanisterRBAC.getUserGrants(store, alice);
                        let bob_auth = CanisterRBAC.getUserGrants(store, bob);

                        let (_ars, arole, _aperms) = alice_auth[0];
                        let (_brs, brole, _bperms) = bob_auth[0];

                        assert arole == "new_role";
                        assert brole == "new_role";
                    },
                );

                test(
                    "deleteRole() removes from all users",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "temp_role"; permissions = ["read"] },
                            { name = "permanent_role"; permissions = ["write"] },
                        ]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "temp_role", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "permanent_role", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "temp_role", []) else Debug.trap("Failed");

                        let #ok(_) = CanisterRBAC.deleteRole(store, "temp_role") else Debug.trap("Failed to delete");

                        let alice_auth = CanisterRBAC.getUserGrants(store, alice);
                        let bob_auth = CanisterRBAC.getUserGrants(store, bob);

                        assert alice_auth.size() == 1;
                        let (_ars, arole, aperms) = alice_auth[0];
                        assert arole == "permanent_role";
                        assert arrayContainsText(aperms, ["write"]);
                        assert bob_auth.size() == 0;
                    },
                );
            },
        );

        suite(
            "Scope Hierarchy",
            func() {
                test(
                    "getScopeHierarchy() returns all parent scopes for single-level scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [("database", "users")],
                            [("database", "*")],
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );

                test(
                    "getScopeHierarchy() returns all parent scopes for two-level scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users"), ("collection", "profiles")];
                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [("database", "users"), ("collection", "profiles")],
                            [("database", "users"), ("collection", "*")],
                            [("database", "users")],
                            [("database", "*")],
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );

                test(
                    "getScopeHierarchy() returns all parent scopes for three-level scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [
                            ("database", "users"),
                            ("collection", "profiles"),
                            ("document", "*"),
                        ];

                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [("database", "users"), ("collection", "profiles"), ("document", "*")],
                            [("database", "users"), ("collection", "profiles")],
                            [("database", "users"), ("collection", "*")],
                            [("database", "users")],
                            [("database", "*")],
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );

                test(
                    "getScopeHierarchy() handles scope with existing wildcard",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "*")];
                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [("database", "*")],
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );

                test(
                    "getScopeHierarchy() handles empty scope (global)",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [];
                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );

                test(
                    "getScopeHierarchy() returns correct order for complex scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [
                            ("org", "acme"),
                            ("team", "engineering"),
                        ];
                        let hierarchy = CanisterRBAC.getScopeHierarchy(scope);

                        let expected : [CanisterRBAC.Types.ResourceScope] = [
                            [("org", "acme"), ("team", "engineering")],
                            [("org", "acme"), ("team", "*")],
                            [("org", "acme")],
                            [("org", "*")],
                            [],
                        ];

                        Debug.print(debug_show ({ hierarchy; expected }));

                        assert hierarchy == expected;
                    },
                );
            },
        );

        suite(
            "Scope Conversion",
            func() {
                test(
                    "scope_to_key() converts empty scope to empty string",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [];
                        let key = CanisterRBAC.scope_to_key(scope);
                        assert key == ":global";
                    },
                );

                test(
                    "scope_to_key() converts single segment scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let key = CanisterRBAC.scope_to_key(scope);
                        assert key == "database(users)";
                    },
                );

                test(
                    "scope_to_key() converts multi-segment scope",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [
                            ("database", "users"),
                            ("collection", "profiles"),
                        ];
                        let key = CanisterRBAC.scope_to_key(scope);
                        assert key == "database(users)/collection(profiles)";
                    },
                );

                test(
                    "scope_to_key() handles wildcard values at end",
                    func() {
                        let scope : CanisterRBAC.Types.ResourceScope = [
                            ("database", "users"),
                            ("collection", "*"),
                        ];
                        let key = CanisterRBAC.scope_to_key(scope);
                        assert key == "database(users)/collection(*)";
                    },
                );

                test(
                    "key_to_scope() converts empty string to empty scope",
                    func() {
                        let key = "";
                        let scope = CanisterRBAC.key_to_scope(key);
                        assert scope == [];
                    },
                );

                test(
                    "key_to_scope() converts single segment key",
                    func() {
                        let key = "database(users)";
                        let scope = CanisterRBAC.key_to_scope(key);
                        assert scope == [("database", "users")];
                    },
                );

                test(
                    "key_to_scope() converts multi-segment key",
                    func() {
                        let key = "database(users)/collection(profiles)";
                        let scope = CanisterRBAC.key_to_scope(key);
                        assert scope == [("database", "users"), ("collection", "profiles")];
                    },
                );

                test(
                    "key_to_scope() handles wildcard values at end",
                    func() {
                        let key = "database(users)/collection(*)";
                        let scope = CanisterRBAC.key_to_scope(key);
                        assert scope == [("database", "users"), ("collection", "*")];
                    },
                );

                test(
                    "scope_to_key() and key_to_scope() are inverse operations",
                    func() {
                        let original : CanisterRBAC.Types.ResourceScope = [
                            ("org", "acme"),
                            ("team", "engineering"),
                            ("project", "auth"),
                        ];
                        let key = CanisterRBAC.scope_to_key(original);
                        let restored = CanisterRBAC.key_to_scope(key);
                        assert original == restored;
                    },
                );

                test(
                    "key_to_scope() and scope_to_key() are inverse operations",
                    func() {
                        let original_key = "database(main)/table(users)/row(123)";
                        let scope = CanisterRBAC.key_to_scope(original_key);
                        let restored_key = CanisterRBAC.scope_to_key(scope);
                        assert original_key == restored_key;
                    },
                );
            },
        );

        suite(
            "deletePermission",
            func() {
                test(
                    "deletePermission() removes permission from all roles",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "admin";
                                permissions = ["read", "write", "delete"];
                            },
                            { name = "editor"; permissions = ["read", "write"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let #ok(_) = CanisterRBAC.deletePermission(store, "read") else Debug.trap("Failed to delete permission");

                        // Verify permission is removed from all roles
                        let #ok(admin_perms) = CanisterRBAC.getRolePermissions(store, "admin") else Debug.trap("Failed");
                        let #ok(editor_perms) = CanisterRBAC.getRolePermissions(store, "editor") else Debug.trap("Failed");
                        let #ok(viewer_perms) = CanisterRBAC.getRolePermissions(store, "viewer") else Debug.trap("Failed");

                        assert assertNotContainsText(admin_perms, ["read"]);
                        assert assertNotContainsText(editor_perms, ["read"]);
                        assert assertNotContainsText(viewer_perms, ["read"]);

                        // Verify other permissions still exist
                        assert arrayContainsText(admin_perms, ["write", "delete"]);
                        assert arrayContainsText(editor_perms, ["write"]);

                        // Verify permission is removed from getAllPermissions
                        let all_perms = CanisterRBAC.getAllPermissions(store);
                        assert assertNotContainsText(all_perms, ["read"]);
                    },
                );

                test(
                    "deletePermission() returns error for non-existent permission",
                    func() {
                        let store = CanisterRBAC.new();
                        let result = CanisterRBAC.deletePermission(store, "nonexistent");
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "not found");
                        };
                    },
                );
            },
        );

        suite(
            "Case Insensitivity",
            func() {
                test(
                    "role names are case insensitive",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "Admin";
                            permissions = ["READ"];
                        }]);

                        // Should find role with different case
                        let #ok(perms) = CanisterRBAC.getRolePermissions(store, "ADMIN") else Debug.trap("Failed");
                        assert arrayContainsText(perms, ["read"]);

                        // Granting with different case should work
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "aDmIn", []) else Debug.trap("Failed");
                        assert CanisterRBAC.hasPermission(store, alice, "read", []);
                    },
                );

                test(
                    "permission names are case insensitive",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["READ", "Write", "MANAGE"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed");

                        // Check with different cases
                        assert CanisterRBAC.hasPermission(store, alice, "read", []);
                        assert CanisterRBAC.hasPermission(store, alice, "READ", []);
                        assert CanisterRBAC.hasPermission(store, alice, "ReAd", []);
                    },
                );

                test(
                    "scope segments are case insensitive",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("Database", "Users")]) else Debug.trap("Failed");

                        // Check with different cases
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("DATABASE", "USERS")]);
                    },
                );
            },
        );

        suite(
            "Error Handling",
            func() {
                test(
                    "createRole() fails for duplicate role",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let result = CanisterRBAC.createRole(store, "admin", ["write"]);
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "already exists");
                        };
                    },
                );

                test(
                    "createPermission() fails for duplicate permission",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let result = CanisterRBAC.createPermission(store, "read");
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "already exists");
                        };
                    },
                );

                test(
                    "grantUserRole() fails for non-existent role",
                    func() {
                        let store = CanisterRBAC.new();

                        let result = CanisterRBAC.grantUserRole(store, alice, "nonexistent", []);
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "not found");
                        };
                    },
                );

                test(
                    "revokeUserRole() fails when user doesn't have role",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        let result = CanisterRBAC.revokeUserRole(store, alice, "admin", []);
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(_)) {};
                        };
                    },
                );

                test(
                    "renameRole() fails when target name exists",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "admin"; permissions = ["manage"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        let result = CanisterRBAC.renameRole(store, "admin", "viewer");
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "already exists");
                        };
                    },
                );

                test(
                    "renamePermission() fails when target name exists",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read", "write"];
                        }]);

                        let result = CanisterRBAC.renamePermission(store, "read", "write");
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) assert Text.contains(msg, #text "already exists");
                        };
                    },
                );

                test(
                    "grantUserRole() fails with wildcard in middle of scope",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        // Wildcard at position 0 in a 2-segment scope is invalid
                        let invalid_scope : CanisterRBAC.Types.ResourceScope = [
                            ("database", "*"),
                            ("collection", "profiles"),
                        ];
                        let result = CanisterRBAC.grantUserRole(store, alice, "admin", invalid_scope);
                        switch (result) {
                            case (#ok(_)) Debug.trap("Should have failed");
                            case (#err(msg)) {
                                assert Text.contains(msg, #text "Wildcard");
                                assert Text.contains(msg, #text "last segment");
                            };
                        };
                    },
                );

                test(
                    "grantUserRole() succeeds with wildcard at end of scope",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["read"];
                        }]);

                        // Wildcard at the last position is valid
                        let valid_scope : CanisterRBAC.Types.ResourceScope = [
                            ("database", "users"),
                            ("collection", "*"),
                        ];
                        let result = CanisterRBAC.grantUserRole(store, alice, "admin", valid_scope);
                        switch (result) {
                            case (#ok(_)) {}; // Success
                            case (#err(msg)) Debug.trap("Should have succeeded: " # msg);
                        };
                    },
                );

                test(
                    "grantUserRole() succeeds with single-segment wildcard scope",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        // Single segment with wildcard is valid (it's the last segment)
                        let valid_scope : CanisterRBAC.Types.ResourceScope = [("database", "*")];
                        let result = CanisterRBAC.grantUserRole(store, alice, "admin", valid_scope);
                        switch (result) {
                            case (#ok(_)) {}; // Success
                            case (#err(msg)) Debug.trap("Should have succeeded: " # msg);
                        };
                    },
                );
            },
        );

        suite(
            "Hierarchical Permission Inheritance",
            func() {
                test(
                    "global grant gives access to all scopes",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "super_admin";
                            permissions = ["manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "super_admin", []) else Debug.trap("Failed");

                        // Global grant should work for any scope
                        assert CanisterRBAC.hasPermission(store, alice, "manage", []);
                        assert CanisterRBAC.hasPermission(store, alice, "manage", [("database", "users")]);
                        assert CanisterRBAC.hasPermission(store, alice, "manage", [("database", "users"), ("collection", "profiles")]);
                        assert CanisterRBAC.hasPermission(store, alice, "manage", [("database", "users"), ("collection", "profiles"), ("document", "123")]);
                    },
                );

                test(
                    "parent scope grant cascades to child scopes",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "db_admin";
                            permissions = ["read", "write", "delete"];
                        }]);

                        // Grant at database level
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "db_admin", [("database", "users")]) else Debug.trap("Failed");

                        // Should have access to database and all children
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "profiles")]);
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "posts")]);
                        assert CanisterRBAC.hasPermission(store, alice, "delete", [("database", "users"), ("collection", "profiles"), ("document", "abc")]);

                        // Should NOT have access to different database
                        assert not CanisterRBAC.hasPermission(store, alice, "write", [("database", "products")]);
                    },
                );

                test(
                    "wildcard at intermediate level grants access to children",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "collection_reader";
                            permissions = ["read"];
                        }]);

                        // Grant access to any collection within users database
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "collection_reader", [("database", "users"), ("collection", "*")]) else Debug.trap("Failed");

                        // Should have access to any collection
                        assert CanisterRBAC.hasPermission(store, alice, "read", [("database", "users"), ("collection", "profiles")]);
                        assert CanisterRBAC.hasPermission(store, alice, "read", [("database", "users"), ("collection", "settings")]);
                        assert CanisterRBAC.hasPermission(store, alice, "read", [("database", "users"), ("collection", "posts"), ("document", "123")]);

                        // Should NOT have access to different database's collections
                        assert not CanisterRBAC.hasPermission(store, alice, "read", [("database", "products"), ("collection", "items")]);
                    },
                );

                test(
                    "child scope grant doesn't give access to parent",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "doc_editor";
                            permissions = ["write"];
                        }]);

                        // Grant only at document level
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "doc_editor", [("database", "users"), ("collection", "profiles"), ("document", "123")]) else Debug.trap("Failed");

                        // Should have access to specific document
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "profiles"), ("document", "123")]);

                        // Should NOT have access to parent scopes
                        assert not CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "profiles")]);
                        assert not CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                        assert not CanisterRBAC.hasPermission(store, alice, "write", []);
                    },
                );
            },
        );

        suite(
            "Multiple Roles and Permissions",
            func() {
                test(
                    "user can have multiple roles at same scope",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "reader"; permissions = ["read"] },
                            { name = "writer"; permissions = ["write"] },
                        ]);

                        let scope : CanisterRBAC.Types.ResourceScope = [("database", "users")];
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "reader", scope) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "writer", scope) else Debug.trap("Failed");

                        assert CanisterRBAC.hasPermission(store, alice, "read", scope);
                        assert CanisterRBAC.hasPermission(store, alice, "write", scope);

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 2;
                    },
                );

                test(
                    "user can have same role at different scopes",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "users")]) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "products")]) else Debug.trap("Failed");

                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "products")]);
                        assert not CanisterRBAC.hasPermission(store, alice, "write", [("database", "orders")]);

                        let user_auth = CanisterRBAC.getUserGrants(store, alice);
                        assert user_auth.size() == 2;
                    },
                );

                test(
                    "permission from any role is sufficient",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "role_a";
                                permissions = ["perm_a", "perm_shared"];
                            },
                            {
                                name = "role_b";
                                permissions = ["perm_b", "perm_shared"];
                            },
                        ]);

                        // Alice has role_a, Bob has role_b
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "role_a", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "role_b", []) else Debug.trap("Failed");

                        // Alice can do perm_a but not perm_b
                        assert CanisterRBAC.hasPermission(store, alice, "perm_a", []);
                        assert not CanisterRBAC.hasPermission(store, alice, "perm_b", []);

                        // Bob can do perm_b but not perm_a
                        assert CanisterRBAC.hasPermission(store, bob, "perm_b", []);
                        assert not CanisterRBAC.hasPermission(store, bob, "perm_a", []);

                        // Both can do shared permission
                        assert CanisterRBAC.hasPermission(store, alice, "perm_shared", []);
                        assert CanisterRBAC.hasPermission(store, bob, "perm_shared", []);
                    },
                );
            },
        );

        suite(
            "Scope Independence",
            func() {
                test(
                    "revoking parent scope doesn't affect child scope grant",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        // Grant at both parent and child
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "users")]) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "users"), ("collection", "profiles")]) else Debug.trap("Failed");

                        // Revoke parent
                        let #ok(_) = CanisterRBAC.revokeUserRole(store, alice, "editor", [("database", "users")]) else Debug.trap("Failed");

                        // Child grant should still work
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "profiles")]);

                        // Parent scope no longer works
                        assert not CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                    },
                );

                test(
                    "revoking child scope doesn't affect parent scope grant",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "editor";
                            permissions = ["write"];
                        }]);

                        // Grant at both parent and child
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "users")]) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "editor", [("database", "users"), ("collection", "profiles")]) else Debug.trap("Failed");

                        // Revoke child
                        let #ok(_) = CanisterRBAC.revokeUserRole(store, alice, "editor", [("database", "users"), ("collection", "profiles")]) else Debug.trap("Failed");

                        // Parent grant still gives access to everything including child
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users")]);
                        assert CanisterRBAC.hasPermission(store, alice, "write", [("database", "users"), ("collection", "profiles")]);
                    },
                );
            },
        );

        suite(
            "requirePermission",
            func() {
                test(
                    "requirePermission() executes callback and returns result when allowed",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed");

                        var executed = false;
                        let result = CanisterRBAC.requirePermission<Text>(store, alice, "manage", [], func() : Text {
                            executed := true;
                            "admin data";
                        });

                        assert executed;
                        assert result == "admin data";
                    },
                );

                test(
                    "allowVoid() executes callback and returns #ok when allowed",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "admin", []) else Debug.trap("Failed");

                        var executed = false;
                        let result = CanisterRBAC.allowVoid(store, alice, "manage", [], func() {
                            executed := true;
                        });

                        assert executed;
                        assert result == #ok(());
                    },
                );

                test(
                    "allowVoid() returns #err and skips callback when denied",
                    func() {
                        let store = CanisterRBAC.initRoles([{
                            name = "admin";
                            permissions = ["manage"];
                        }]);

                        var executed = false;
                        let result = CanisterRBAC.allowVoid(store, bob, "manage", [], func() {
                            executed := true;
                        });

                        assert not executed;
                        assert result != #ok(());
                    },
                );
            },
        );

        suite(
            "Real World Use Cases",
            func() {
                test(
                    "multi-tenant SaaS: org admin can manage org, team lead can manage team",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "org_admin";
                                permissions = ["org:read", "org:write", "org:manage"];
                            },
                            {
                                name = "team_lead";
                                permissions = ["team:read", "team:write", "team:manage"];
                            },
                            { name = "member"; permissions = ["team:read"] },
                        ]);

                        // Alice is org admin for Acme
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "org_admin", [("org", "acme")]) else Debug.trap("Failed");

                        // Bob is team lead for engineering
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "team_lead", [("org", "acme"), ("team", "engineering")]) else Debug.trap("Failed");

                        // Charlie is member of engineering
                        let #ok(_) = CanisterRBAC.grantUserRole(store, charlie, "member", [("org", "acme"), ("team", "engineering")]) else Debug.trap("Failed");

                        // Alice can manage anything in org
                        assert CanisterRBAC.hasPermission(store, alice, "org:manage", [("org", "acme")]);
                        assert CanisterRBAC.hasPermission(store, alice, "org:manage", [("org", "acme"), ("team", "engineering")]);

                        // Bob can manage his team but not the org
                        assert CanisterRBAC.hasPermission(store, bob, "team:manage", [("org", "acme"), ("team", "engineering")]);
                        assert not CanisterRBAC.hasPermission(store, bob, "org:manage", [("org", "acme")]);

                        // Charlie can only read team
                        assert CanisterRBAC.hasPermission(store, charlie, "team:read", [("org", "acme"), ("team", "engineering")]);
                        assert not CanisterRBAC.hasPermission(store, charlie, "team:write", [("org", "acme"), ("team", "engineering")]);
                    },
                );

                test(
                    "document management: folder permissions cascade to documents",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            {
                                name = "folder_admin";
                                permissions = ["read", "write", "delete", "share"];
                            },
                            { name = "editor"; permissions = ["read", "write"] },
                            { name = "viewer"; permissions = ["read"] },
                        ]);

                        // Alice is admin of public folder
                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "folder_admin", [("folder", "public")]) else Debug.trap("Failed");

                        // Bob can edit docs in reports subfolder
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "editor", [("folder", "public"), ("subfolder", "reports")]) else Debug.trap("Failed");

                        // Alice can do everything in public folder
                        assert CanisterRBAC.hasPermission(store, alice, "delete", [("folder", "public"), ("subfolder", "reports"), ("doc", "q1-report")]);

                        // Bob can edit in reports but not delete
                        assert CanisterRBAC.hasPermission(store, bob, "write", [("folder", "public"), ("subfolder", "reports"), ("doc", "q1-report")]);
                        assert not CanisterRBAC.hasPermission(store, bob, "delete", [("folder", "public"), ("subfolder", "reports"), ("doc", "q1-report")]);

                        // Bob cannot access other subfolders
                        assert not CanisterRBAC.hasPermission(store, bob, "write", [("folder", "public"), ("subfolder", "drafts")]);
                    },
                );

                test(
                    "API gateway: endpoint-specific permissions",
                    func() {
                        let store = CanisterRBAC.initRoles([
                            { name = "api_admin"; permissions = ["api:users:read", "api:users:write", "api:products:read"] },
                            {
                                name = "user_service";
                                permissions = ["api:users:read", "api:users:write"];
                            },
                            {
                                name = "readonly_client";
                                permissions = ["api:users:read", "api:products:read"];
                            },
                        ]);

                        let #ok(_) = CanisterRBAC.grantUserRole(store, alice, "api_admin", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, bob, "user_service", []) else Debug.trap("Failed");
                        let #ok(_) = CanisterRBAC.grantUserRole(store, charlie, "readonly_client", []) else Debug.trap("Failed");

                        // Admin can do anything users or user_service can do
                        assert CanisterRBAC.hasPermission(store, alice, "api:users:read", []);
                        assert CanisterRBAC.hasPermission(store, alice, "api:users:write", []);
                        assert CanisterRBAC.hasPermission(store, alice, "api:products:read", []);

                        // User service can read and write users
                        assert CanisterRBAC.hasPermission(store, bob, "api:users:read", []);
                        assert CanisterRBAC.hasPermission(store, bob, "api:users:write", []);
                        assert not CanisterRBAC.hasPermission(store, bob, "api:products:read", []);

                        // Readonly client can only read
                        assert CanisterRBAC.hasPermission(store, charlie, "api:users:read", []);
                        assert not CanisterRBAC.hasPermission(store, charlie, "api:users:write", []);
                    },
                );
            },
        );
    },
);
