from pathlib import Path

from runtime_contracts.protocol.decision_provider import DECISION_PROVIDER_CONTRACT_VERSION


def test_decision_provider_contract_doc_names_canonical_contract() -> None:
    text = Path("docs/DECISION_PROVIDER_CONTRACT.md").read_text(encoding="utf-8")

    assert DECISION_PROVIDER_CONTRACT_VERSION in text
    for required in (
        "permitted_options",
        "score_semantics",
        "class_prob",
        "outcome_prob",
        "abstain_reason",
        "input_digest",
        "response_digest",
        "not an execution receipt",
    ):
        assert required in text
