"""Unit tests for the AntiScam AI Python SDK client helpers."""

import pytest

from antiscamai.client import (
    AntiScamClient,
    AntiScamConfig,
    InspectRequest,
    extract_urls,
    flatten_to_text,
    read_body,
    _fallback,
)


class TestExtractUrls:
    def test_extracts_https_url(self):
        result = extract_urls("Visit https://example.com for info.")
        assert set(result) == {"https://example.com"}

    def test_extracts_http_url(self):
        result = extract_urls("Check http://test.org now.")
        assert set(result) == {"http://test.org"}

    def test_returns_empty_for_no_urls(self):
        assert extract_urls("no urls here") == []

    def test_deduplicates_urls(self):
        result = extract_urls("https://example.com https://example.com")
        assert len(result) == 1

    def test_extracts_multiple_distinct_urls(self):
        result = extract_urls("https://a.com and https://b.com")
        assert len(result) == 2


class TestFlattenToText:
    def test_returns_string_unchanged_when_long_enough(self):
        assert flatten_to_text("hello world") == "hello world"

    def test_ignores_short_strings(self):
        assert flatten_to_text("ab") == ""

    def test_flattens_dict_values(self):
        result = flatten_to_text({"a": "foo bar", "b": "baz qux"})
        assert "foo bar" in result
        assert "baz qux" in result

    def test_flattens_list_values(self):
        result = flatten_to_text(["hello world", "test value"])
        assert "hello world" in result
        assert "test value" in result

    def test_flattens_nested_objects(self):
        result = flatten_to_text({"a": {"b": "deep value here"}})
        assert "deep value here" in result


class TestReadBody:
    def test_string_body(self):
        text, urls = read_body("hello world content")
        assert text == "hello world content"
        assert urls == []

    def test_bytes_body(self):
        text, urls = read_body(b"bytes content here")
        assert text == "bytes content here"

    def test_dict_body(self):
        text, urls = read_body({"message": "test content here"})
        assert "test content here" in text

    def test_extracts_urls_from_body(self):
        _, urls = read_body("visit https://phishing.example.com today")
        assert set(urls) == {"https://phishing.example.com"}

    def test_empty_body(self):
        text, urls = read_body(None)
        assert text == ""
        assert urls == []


class TestAntiScamClient:
    def test_raises_if_api_key_is_empty(self):
        with pytest.raises(ValueError, match="api_key is required"):
            AntiScamClient(AntiScamConfig(api_key=""))

    def test_creates_client_with_valid_api_key(self):
        client = AntiScamClient(AntiScamConfig(api_key="test-key-123"))
        assert client is not None

    def test_inspect_sync_falls_back_on_network_error(self):
        client = AntiScamClient(
            AntiScamConfig(
                api_key="test-key",
                endpoint="http://localhost:1",  # unreachable
                timeout_ms=100,
                on_error="allow",
            )
        )
        result = client.inspect_sync(InspectRequest(body_text="hello"))
        assert result.decision == "allow"
        assert result.should_block is False
        assert result.request_id == "error-fallback"

    def test_inspect_sync_fail_closed_on_network_error(self):
        client = AntiScamClient(
            AntiScamConfig(
                api_key="test-key",
                endpoint="http://localhost:1",  # unreachable
                timeout_ms=100,
                on_error="block",
            )
        )
        result = client.inspect_sync(InspectRequest(body_text="hello"))
        assert result.decision == "block"
        assert result.should_block is True


class TestFallback:
    def test_allow_fallback(self):
        resp = _fallback("allow")
        assert resp.decision == "allow"
        assert resp.should_block is False

    def test_block_fallback(self):
        resp = _fallback("block")
        assert resp.decision == "block"
        assert resp.should_block is True

    def test_fallback_has_zero_threat_score(self):
        resp = _fallback("allow")
        assert resp.threat_score == 0

    def test_fallback_has_no_threats(self):
        resp = _fallback("allow")
        assert resp.threats == []
