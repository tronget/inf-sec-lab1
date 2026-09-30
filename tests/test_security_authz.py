"""Broken access control / IDOR: a user may only touch their own resources."""

from __future__ import annotations


def test_user_cannot_read_another_users_note(client, alice, bob, make_note):
    note = make_note(alice["headers"], "alice private")
    response = client.get("/api/data/{}".format(note["id"]), headers=bob["headers"])
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "forbidden"
    assert "alice private" not in response.get_data(as_text=True)


def test_user_cannot_delete_another_users_note(client, alice, bob, make_note):
    note = make_note(alice["headers"], "alice private")
    assert (
        client.delete("/api/data/{}".format(note["id"]), headers=bob["headers"]).status_code == 403
    )
    # The note is still there for its owner.
    assert (
        client.get("/api/data/{}".format(note["id"]), headers=alice["headers"]).status_code == 200
    )


def test_listing_never_leaks_other_users_rows(client, alice, bob, make_note):
    make_note(alice["headers"], "alice secret note")
    make_note(bob["headers"], "bob secret note")

    alice_body = client.get("/api/data", headers=alice["headers"]).get_json()
    bob_body = client.get("/api/data", headers=bob["headers"]).get_json()

    assert [item["title"] for item in alice_body["items"]] == ["alice secret note"]
    assert [item["title"] for item in bob_body["items"]] == ["bob secret note"]


def test_search_cannot_reach_across_owners(client, alice, bob, make_note):
    make_note(alice["headers"], "quarterly report")
    body = client.get(
        "/api/data", headers=bob["headers"], query_string={"q": "quarterly"}
    ).get_json()
    assert body["total"] == 0


def test_owner_id_in_body_cannot_be_forged(client, alice, bob):
    response = client.post(
        "/api/data", headers=bob["headers"], json={"title": "forged", "owner_id": 1}
    )
    assert response.status_code == 422  # extra fields are forbidden outright
