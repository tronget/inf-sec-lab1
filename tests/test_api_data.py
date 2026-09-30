"""The functional data endpoints: list, create, read, delete."""

from __future__ import annotations

import pytest


def test_data_requires_authentication(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.get_json()["error"]["code"] == "unauthorized"


def test_data_returns_empty_page_for_new_user(client, alice):
    response = client.get("/api/data", headers=alice["headers"])
    assert response.status_code == 200
    assert response.get_json() == {
        "items": [],
        "page": 1,
        "per_page": 20,
        "total": 0,
        "query": None,
    }


def test_create_note_returns_201(client, alice):
    response = client.post(
        "/api/data",
        headers=alice["headers"],
        json={"title": "Groceries", "content": "milk, bread"},
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["title"] == "Groceries"
    assert body["content"] == "milk, bread"
    assert body["id"] > 0


def test_create_note_requires_authentication(client):
    assert client.post("/api/data", json={"title": "x"}).status_code == 401


def test_create_note_validates_body(client, alice):
    assert client.post("/api/data", headers=alice["headers"], json={}).status_code == 422
    assert client.post("/api/data", headers=alice["headers"], json={"title": ""}).status_code == 422
    assert (
        client.post(
            "/api/data", headers=alice["headers"], json={"title": "ok", "owner_id": 99}
        ).status_code
        == 422
    )


def test_create_note_requires_json_object(client, alice):
    response = client.post(
        "/api/data", headers=alice["headers"], data="oops", content_type="application/json"
    )
    assert response.status_code == 400


def test_created_note_is_listed(client, alice, make_note):
    make_note(alice["headers"], "First note")
    response = client.get("/api/data", headers=alice["headers"])
    body = response.get_json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "First note"


def test_listing_is_scoped_to_the_owner(client, alice, bob, make_note):
    make_note(alice["headers"], "alice-only")
    response = client.get("/api/data", headers=bob["headers"])
    assert response.get_json()["total"] == 0


def test_pagination(client, alice, make_note):
    for index in range(5):
        make_note(alice["headers"], f"note-{index}")

    page1 = client.get("/api/data?page=1&per_page=2", headers=alice["headers"]).get_json()
    page3 = client.get("/api/data?page=3&per_page=2", headers=alice["headers"]).get_json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2
    assert len(page3["items"]) == 1
    assert {item["id"] for item in page1["items"]}.isdisjoint(
        {item["id"] for item in page3["items"]}
    )


@pytest.mark.parametrize("query", ["page=0", "per_page=0", "per_page=101", "page=abc", "foo=bar"])
def test_invalid_pagination_is_rejected(client, alice, query):
    response = client.get("/api/data?" + query, headers=alice["headers"])
    assert response.status_code == 422


def test_search_filters_by_title(client, alice, make_note):
    make_note(alice["headers"], "shopping list")
    make_note(alice["headers"], "meeting notes")
    body = client.get("/api/data?q=shopping", headers=alice["headers"]).get_json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "shopping list"
    assert body["query"] == "shopping"


def test_get_single_note(client, alice, make_note):
    note = make_note(alice["headers"], "readable", "body text")
    response = client.get("/api/data/{}".format(note["id"]), headers=alice["headers"])
    assert response.status_code == 200
    assert response.get_json()["content"] == "body text"


def test_get_missing_note_returns_404(client, alice):
    assert client.get("/api/data/424242", headers=alice["headers"]).status_code == 404


def test_delete_note_returns_204_and_is_gone(client, alice, make_note):
    note = make_note(alice["headers"], "temporary")
    assert (
        client.delete("/api/data/{}".format(note["id"]), headers=alice["headers"]).status_code
        == 204
    )
    assert (
        client.get("/api/data/{}".format(note["id"]), headers=alice["headers"]).status_code == 404
    )


def test_delete_missing_note_returns_404(client, alice):
    assert client.delete("/api/data/999999", headers=alice["headers"]).status_code == 404


def test_oversized_body_is_rejected(client, alice):
    response = client.post(
        "/api/data",
        headers=alice["headers"],
        data=b"{" + b"a" * 200_000 + b"}",
        content_type="application/json",
    )
    assert response.status_code == 413


def test_timestamps_always_carry_a_utc_offset(client, alice, make_note):
    """Every route must render timestamps in the same offset-aware format."""
    created = make_note(alice["headers"], "timestamped")
    fetched = client.get("/api/data/{}".format(created["id"]), headers=alice["headers"]).get_json()
    listed = client.get("/api/data", headers=alice["headers"]).get_json()["items"][0]
    profile = client.get("/api/me", headers=alice["headers"]).get_json()

    for value in (
        created["created_at"],
        created["updated_at"],
        fetched["created_at"],
        listed["created_at"],
        profile["created_at"],
    ):
        assert value.endswith("+00:00"), value
    assert created["created_at"] == fetched["created_at"] == listed["created_at"]
