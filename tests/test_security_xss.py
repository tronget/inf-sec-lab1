"""Cross-site scripting: every echoed value is HTML-escaped and JSON-typed."""

from __future__ import annotations

import pytest

from app.security.sanitize import normalize_text, sanitize_text, strip_control_chars

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg/onload=alert(1)>",',
    "javascript:alert(document.cookie)",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('xss')>",
]


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_stored_payload_is_escaped_on_output(client, alice, make_note, payload):
    created = make_note(alice["headers"], payload, payload)

    # No raw HTML metacharacter survives into the response body.
    for field in ("title", "content"):
        assert "<" not in created[field]
        assert ">" not in created[field]
        assert '"' not in created[field]
        assert "'" not in created[field]

    listed = client.get("/api/data", headers=alice["headers"])
    raw_body = listed.get_data(as_text=True)
    assert "<script" not in raw_body
    assert "<img" not in raw_body
    assert "<svg" not in raw_body
    assert "<iframe" not in raw_body


@pytest.mark.parametrize("payload", [p for p in XSS_PAYLOADS if "<" in p])
def test_html_payloads_come_back_entity_encoded(client, alice, make_note, payload):
    created = make_note(alice["headers"], payload, payload)
    assert "&lt;" in created["title"]
    assert "&gt;" in created["title"]


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_responses_are_always_json(client, alice, make_note, payload):
    make_note(alice["headers"], payload)
    response = client.get("/api/data", headers=alice["headers"])
    assert response.headers["Content-Type"].startswith("application/json")
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_single_note_response_is_escaped(client, alice, make_note):
    note = make_note(alice["headers"], "<b>bold</b>", "<script>alert(1)</script>")
    body = client.get("/api/data/{}".format(note["id"]), headers=alice["headers"]).get_json()
    assert body["title"] == "&lt;b&gt;bold&lt;/b&gt;"
    assert body["content"] == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_search_echo_is_escaped(client, alice):
    response = client.get(
        "/api/data", headers=alice["headers"], query_string={"q": "<script>alert(1)</script>"}
    )
    assert "<script>" not in response.get_data(as_text=True)
    assert response.get_json()["query"].startswith("&lt;script&gt;")


def test_validation_error_details_are_escaped(client, alice):
    response = client.post(
        "/api/data", headers=alice["headers"], json={"<script>x</script>": "value", "title": "t"}
    )
    assert response.status_code == 422
    assert "<script>" not in response.get_data(as_text=True)


def test_sanitize_text_escapes_html():
    assert sanitize_text("<script>") == "&lt;script&gt;"
    assert sanitize_text('"quoted"') == "&#34;quoted&#34;"
    assert sanitize_text("a&b") == "a&amp;b"
    assert sanitize_text(None) == ""


def test_strip_control_chars_removes_smuggling_characters():
    assert strip_control_chars("a\x00b\x1fc") == "abc"
    assert strip_control_chars("keep\ttab\nnewline") == "keep\ttab\nnewline"


def test_normalize_text_applies_nfkc_and_trimming():
    assert normalize_text("  ﬁne  ") == "fine"
    assert normalize_text("abcdef", max_length=3) == "abc"


def test_control_characters_are_stripped_from_stored_values(client, alice, make_note):
    note = make_note(alice["headers"], "clean\x00title")
    assert note["title"] == "cleantitle"
