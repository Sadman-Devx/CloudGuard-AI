import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from apps.ai_copilot.providers import MetaModelProvider, ProviderError, ProviderNotConfigured


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_POST(self):
        server = self.server
        length = int(self.headers.get("Content-Length", 0))
        server.requests.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "body": json.loads(self.rfile.read(length)),
            }
        )
        mode = server.mode
        if mode == "slow":
            time.sleep(1.0)
        if mode.startswith("http_"):
            self.send_response(int(mode[5:]))
            self.end_headers()
            return
        body = server.reply if mode == "ok" else b"not json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.requests, httpd.mode = [], "ok"
    httpd.reply = json.dumps(
        {
            "model": "muse-test-1",
            "choices": [{"message": {"role": "assistant", "content": '{"explanation": "hi"}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "note": "ignored"},
        }
    ).encode()
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def make(server, **kw):
    params = dict(
        api_key="secret-key",
        model="muse-test-1",
        base_url=f"http://127.0.0.1:{server.server_address[1]}",
        path="/v1/chat/completions",
        timeout=5,
    )
    params.update(kw)
    return MetaModelProvider(**params)


def test_not_configured_without_key_or_model():
    with pytest.raises(ProviderNotConfigured):
        MetaModelProvider(api_key="", model="m", base_url="http://x", path="/p", timeout=1)
    with pytest.raises(ProviderNotConfigured):
        MetaModelProvider(api_key="k", model="", base_url="http://x", path="/p", timeout=1)


def test_success_sends_bearer_key_and_parses_text_and_usage(server):
    result = make(server).complete("SYS", "USER")
    assert result.text == '{"explanation": "hi"}'
    assert result.model == "muse-test-1"
    assert result.usage == {"prompt_tokens": 10, "completion_tokens": 5}
    request = server.requests[0]
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == "Bearer secret-key"
    assert request["body"]["model"] == "muse-test-1"
    assert [m["role"] for m in request["body"]["messages"]] == ["system", "user"]
    assert "response_format" not in request["body"]


def test_json_mode_is_optional(server):
    make(server, json_mode=True).complete("s", "u")
    assert server.requests[0]["body"]["response_format"] == {"type": "json_object"}


def test_content_parts_list_is_supported(server):
    server.reply = json.dumps(
        {
            "choices": [
                {"message": {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}}
            ]
        }
    ).encode()
    assert make(server).complete("s", "u").text == "ab"


@pytest.mark.parametrize(
    ("code", "retryable"), [(429, True), (500, True), (503, True), (401, False), (400, False)]
)
def test_http_errors_classified(server, code, retryable):
    server.mode = f"http_{code}"
    with pytest.raises(ProviderError) as exc:
        make(server).complete("s", "u")
    assert exc.value.retryable is retryable
    assert str(code) in str(exc.value)
    assert "secret-key" not in str(exc.value)


def test_non_json_body_is_retryable_error(server):
    server.mode = "garbage"
    with pytest.raises(ProviderError) as exc:
        make(server).complete("s", "u")
    assert exc.value.retryable


def test_response_without_text_is_error(server):
    server.reply = json.dumps({"choices": []}).encode()
    with pytest.raises(ProviderError, match="did not contain any text"):
        make(server).complete("s", "u")


def test_timeout_is_retryable(server):
    server.mode = "slow"
    with pytest.raises(ProviderError) as exc:
        make(server, timeout=0.2).complete("s", "u")
    assert exc.value.retryable and "timed out" in str(exc.value)


def test_connection_refused_is_retryable_error():
    provider = MetaModelProvider(
        api_key="k", model="m", base_url="http://127.0.0.1:1", path="/v1/chat/completions", timeout=1
    )
    with pytest.raises(ProviderError) as exc:
        provider.complete("s", "u")
    assert exc.value.retryable