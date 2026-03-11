import T "Types";

module {

    public func upgrade(prev_store : T.PrevVersionedStableStore) : T.VersionedStableStore {
        switch (prev_store) {
            case (#v0_1_0(state)) {
                #v0_1_0(state);
            };
        };
    };

    public func share(store : T.StableStore) : T.VersionedStableStore {
        #v0_1_0(store);
    };

    public func get_current_state(store : T.VersionedStableStore) : T.StableStore {
        let upgraded = upgrade(store);
        switch (upgraded) {
            case (#v0_1_0(state)) state;
        };
    };

    public func to_text(store : T.PrevVersionedStableStore) : Text {
        switch (store) {
            case (#v0_1_0(_)) { "v0.1.0" };
        };
    };

};
