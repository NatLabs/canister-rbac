import Map "mo:map@9.0.1/Map";
import Set "mo:map@9.0.1/Set";

module {
    type Map<K, V> = Map.Map<K, V>;
    type Set<K> = Set.Set<K>;

    // Resource segment: (resource_type, identifier)
    // Example: ("database", "users") or ("collection", "profiles")
    public type ResourceSegment = (Text, Text);

    // Resource scope: hierarchical path of segments
    // Example: [("database", "users"), ("collection", "profiles")]
    public type ResourceScope = [ResourceSegment];

    public type InputRole = {
        name : Text;
        permissions : [Text];
    };

    // New simplified structure
    public type StableStoreV0 = {
        var role_id_counter : Nat; // Forever incrementing counter for role IDs
        role_ids : Map<Nat, Text>; // role_id → role_name ("1" → "admin")

        /// Bidirectional mapping: permission -> Set of role IDs that have it
        permissions : Map<Text, Set<Nat>>; // "read" → {1, 2} (role IDs)

        /// Role name -> (role_id, Set of permissions)
        roles : Map<Text, (Nat, Set<Text>)>; // "admin" → (1, {"manage", "write", "read"})

        // Role-centric grants index: role_id → scope_key → Set of users
        role_grants : Map<Nat, Map<Text, Set<Principal>>>; // 1 → {"db(main)/table(users)" → {user1, user2}}
    };

    public type StableStore = StableStoreV0;

    public type VersionedStableStore = {
        #v0_1_0 : StableStore;
    };

    public type PrevVersionedStableStore = {
        #v0_1_0 : StableStore;
    };

};
