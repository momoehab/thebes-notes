import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Iter "mo:core/Iter";
import Text "mo:core/Text";

persistent actor Note {

  public type Item = { id : Nat; title : Text; body : Text };

  // let notes = Map.empty<Nat, Item>();
  var curId : Nat = 0;

  let shelves = Map.empty<Text, Map.Map<Nat, Item>>();

  func shelfOrNew(owner : Text) : Map.Map<Nat, Item> {
    switch (Map.get(shelves, Text.compare, owner)) {
      case (?shelf) {
        shelf;
      };

      case null {
        let newShelf = Map.empty<Nat, Item>();

        Map.add(
          shelves,
          Text.compare,
          owner,
          newShelf,
        );

        newShelf;
      };
    };
  };

  func shelf(owner : Text) : ?Map.Map<Nat, Item> {
    Map.get(
      shelves,
      Text.compare,
      owner,
    );
  };

  public func add(title : Text, body : Text, owner : Text) : async Bool {
    if (owner == "") { return false };
    let item : Item = {
      id = curId;
      title = title;
      body;
    };
    Map.add(shelfOrNew(owner), Nat.compare, curId, item);
    curId += 1;
    true;
  };

  public func edit(id : Nat, title : Text, body : Text, owner : Text) : async Bool {
    if (owner == "") {
      return false;
    };
    switch (shelf(owner)) {
      case null {
        false;
      };
      case (?s) {
        if (Map.containsKey(s, Nat.compare, id)) {
          let item : Item = { id = id; title = title; body };
          Map.add(s, Nat.compare, id, item);
          true;

        } else {
          false;
        };
      };
    };
  };

  public func remove(id : Nat, owner : Text) : async Bool {
    if (owner == "") {
      return false;
    };

    switch (shelf(owner)) {
      case null {
        false;
      };

      case (?s) {
        if (Map.containsKey(s, Nat.compare, id)) {
          Map.remove(s, Nat.compare, id);
          true;
        } else {
          false;
        };
      };
    };
  };

  public query func get_notes(owner : Text) : async [Item] {
    if (owner == "") {
      return [];
    };
    switch (shelf(owner)) {
      case null { [] };
      case (?s) {

        Iter.toArray(Map.values(s));
      };
    };
  };
};
