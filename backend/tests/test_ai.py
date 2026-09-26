"""Phase 9 grounded AI, fallback, root cause, and repository Q&A."""

from app.core.config import Settings
from app.services.ai.architect import architect_answer
from app.services.ai.prompts import build_context_pack, build_grounded_messages
from app.services.ai.provider import SYSTEM_INSTRUCTION, AIProvider
from app.services.ai.qa import ask
from app.services.ai.root_cause import UNDETERMINED, deterministic_root_cause
from app.services.ai.sanitize import finding_brief
from tests.intelligence_helpers import finding, snapshot


def _settings(**overrides) -> Settings:
    values = dict(
        database_url="sqlite://",
        environment="test",
        log_level="WARNING",
        workspace_root="./workspaces",
        cors_origins="http://localhost:5173",
        openai_api_key="",
    )
    values.update(overrides)
    return Settings(**values)


def test_grounded_prompt_generation() -> None:
    context = snapshot([finding()])
    pack = build_context_pack(context, "Why is RSA used here a migration concern?")
    messages = build_grounded_messages(pack, "Why is RSA used here a migration concern?")
    assert messages[0]["content"] == SYSTEM_INSTRUCTION
    assert "Do not invent algorithms" in messages[0]["content"]
    assert '"algorithm": "RSA"' in messages[1]["content"]
    assert pack["findings"][0]["id"] == 1


def test_no_secret_leakage_in_grounded_context() -> None:
    row = finding(
        evidence='password="hunter2" token=sk-abcdefghijklmnopqrstuvwxyz123456 rsa.generate_private_key'
    )
    pack = build_context_pack(snapshot([row]), "summarize")
    dumped = str(pack)
    assert "hunter2" not in dumped
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in dumped
    assert "[REDACTED]" in dumped
    brief = finding_brief(row)
    assert "hunter2" not in brief["evidence"]


def test_deterministic_fallback_without_api_key() -> None:
    settings = _settings()
    result = architect_answer(snapshot([finding()]), settings)
    assert result["source"] == "deterministic_fallback"
    assert result["provider_available"] is False
    assert "RSA" in result["answer"]
    assert result["supporting_findings"] == [1]


def test_missing_api_key_keeps_provider_unavailable() -> None:
    provider = AIProvider(_settings(openai_api_key=""))
    assert provider.available is False


def test_mocked_provider_is_used_when_key_present(monkeypatch) -> None:
    settings = _settings(openai_api_key="test-key")
    provider = AIProvider(settings)

    def fake_complete(messages):
        assert messages[0]["content"] == SYSTEM_INSTRUCTION
        return "Observed RSA in src/auth.py. This is a recommendation, not a completed migration."

    monkeypatch.setattr(provider, "complete", fake_complete)
    result = architect_answer(snapshot([finding()]), settings, provider=provider)
    assert result["source"] == "ai"
    assert "Observed RSA" in result["answer"]


def test_unsupported_question() -> None:
    result = ask(snapshot([finding()]), _settings(), "What is the weather in Paris?")
    assert result["supporting_findings"] == []
    assert "does not contain enough evidence" in result["answer"]


def test_repository_qa_uses_supporting_evidence() -> None:
    deps = [
        type("Dep", (), {"id": 9, "name": "cryptography", "ecosystem": "pypi", "version": "42.0.5", "crypto_relevance": "cryptographic_library", "manifest_file": "requirements.txt", "library": "cryptography"})()
    ]
    result = ask(snapshot([finding()], dependencies=deps), _settings(), "Where is RSA used and what depends on it?")
    assert 1 in result["supporting_findings"]
    assert "src/auth.py" in result["supporting_files"]
    assert "cryptography" in result["supporting_dependencies"]
    assert "RSA" in result["answer"]


def test_root_cause_requires_evidence() -> None:
    context = snapshot([finding(usage="key_agreement", cryptographic_role="key_establishment")])
    determined = deterministic_root_cause(context, context.findings[0])
    assert determined["determined"] is True
    assert determined["root_cause"] == "legacy key exchange"

    weak = deterministic_root_cause(snapshot([finding(usage="dependency_only")]), finding(id=2, usage="dependency_only", algorithm=None))
    assert weak["determined"] is False
    assert weak["root_cause"] == UNDETERMINED


def test_architect_does_not_fabricate_findings() -> None:
    result = architect_answer(snapshot([finding(id=7, algorithm="ECDSA")]), _settings())
    assert result["supporting_findings"] == [7]
    assert "ECDSA" in result["answer"]
    assert "RSA" not in result["answer"]
