import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.describers.gpt4o_describer import (
    get_prompt_template,
    build_prompt,
    describe_instance,
    describe_batch,
)


def test_get_prompt_template_sigma():
    template = get_prompt_template("T-SIGMA")
    assert "Sigma" in template
    assert "{gold_artifact}" in template


def test_get_prompt_template_yara():
    template = get_prompt_template("T-YARA")
    assert "YARA" in template


def test_get_prompt_template_stix():
    template = get_prompt_template("T-STIX")
    assert "STIX" in template


def test_get_prompt_template_unknown():
    with pytest.raises(ValueError, match="Unknown task"):
        get_prompt_template("T-UNKNOWN")


def test_build_prompt():
    instance = {
        "task": "T-SIGMA",
        "gold_artifact": "title: Test Rule\ndetection:\n  selection:\n    field: value",
        "metadata": {"original_title": "Test Rule", "mitre_attack": ["T1003"]},
    }
    prompt = build_prompt(instance)
    assert "Test Rule" in prompt
    assert isinstance(prompt, str)


async def test_describe_instance_mock():
    instance = {
        "task": "T-SIGMA",
        "gold_artifact": "title: Test\ndetection:\n  sel:\n    x: y\n  condition: sel",
        "metadata": {"original_title": "Test"},
    }

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Create a Sigma rule that detects..."
    mock_response.usage.prompt_tokens = 100
    mock_response.usage.completion_tokens = 50

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    result = await describe_instance(instance, mock_client, model="gpt-4o")

    assert result["nl_description"] == "Create a Sigma rule that detects..."
    assert result["nl_description_model"] == "gpt-4o"
    assert "gold_artifact" in result


async def test_describe_batch_mock():
    instances = [
        {
            "task": "T-SIGMA",
            "gold_artifact": f"title: Rule {i}\ndetection:\n  sel:\n    x: y\n  condition: sel",
            "metadata": {"original_title": f"Rule {i}"},
        }
        for i in range(5)
    ]

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "NL description"
    mock_response.usage.prompt_tokens = 100
    mock_response.usage.completion_tokens = 50

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    results, cost = await describe_batch(
        instances, mock_client, model="gpt-4o", max_concurrent=2
    )

    assert len(results) == 5
    assert all(r["nl_description"] == "NL description" for r in results)
    assert cost > 0
