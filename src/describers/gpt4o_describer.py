"""GPT-4o NL description generation for CyberOutputBench instances."""

import asyncio

from src.utils.io import setup_logging

logger = setup_logging("gpt4o_describer")

PRICING = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "openai/gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "anthropic/claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "anthropic/claude-sonnet-4.6": {"input": 3.00, "output": 15.00},
}

PROMPT_TEMPLATES = {
    "T-SIGMA": (
        "You are a cybersecurity expert. Given the following Sigma detection rule, "
        "write a clear natural language description that could be used as a prompt to "
        "recreate this rule from scratch. The description should specify the log source, "
        "detection logic, and conditions without revealing the exact YAML syntax.\n\n"
        "Sigma Rule:\n```yaml\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Create a Sigma rule to detect...'"
    ),
    "T-YARA": (
        "You are a malware analyst. Given the following YARA rule, write a clear "
        "natural language description that could be used as a prompt to recreate this "
        "rule from scratch. The description should specify what the rule detects, "
        "key indicators, and matching conditions without revealing exact syntax.\n\n"
        "YARA Rule:\n```yara\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Write a YARA rule to detect...'"
    ),
    "T-STIX": (
        "You are a threat intelligence analyst. Given the following STIX 2.1 bundle, "
        "write a clear natural language description that could be used as a prompt to "
        "recreate this bundle from scratch. The description should specify the threat "
        "actors, malware, indicators, and relationships without revealing JSON syntax.\n\n"
        "STIX Bundle:\n```json\n{gold_artifact}\n```\n\n"
        "Additional context: {metadata}\n\n"
        "Write a concise task prompt starting with 'Create a STIX 2.1 bundle describing...'"
    ),
}


def get_prompt_template(task: str) -> str:
    if task not in PROMPT_TEMPLATES:
        raise ValueError(f"Unknown task: {task}")
    return PROMPT_TEMPLATES[task]


def build_prompt(instance: dict) -> str:
    template = get_prompt_template(instance["task"])
    return template.format(
        gold_artifact=instance["gold_artifact"],
        metadata=str(instance.get("metadata", {})),
    )


async def describe_instance(
    instance: dict,
    client,
    model: str = "gpt-4o",
    max_retries: int = 3,
) -> dict:
    prompt = build_prompt(instance)

    for attempt in range(max_retries):
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=512,
            )
            description = response.choices[0].message.content.strip()
            usage = response.usage

            result = dict(instance)
            result["nl_description"] = description
            result["nl_description_model"] = model
            result["_usage"] = {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
            }
            return result

        except Exception as e:
            wait = 2 ** (attempt + 1)
            logger.warning(
                "API error (attempt %d/%d): %s. Retrying in %ds.",
                attempt + 1, max_retries, e, wait,
            )
            await asyncio.sleep(wait)

    logger.error("Failed to describe instance after %d retries", max_retries)
    result = dict(instance)
    result["nl_description"] = ""
    result["nl_description_model"] = model
    return result


async def describe_batch(
    instances: list[dict],
    client,
    model: str = "gpt-4o",
    max_concurrent: int = 10,
) -> tuple[list[dict], float]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _describe(inst):
        async with semaphore:
            return await describe_instance(inst, client, model)

    tasks = [_describe(inst) for inst in instances]
    results = await asyncio.gather(*tasks)

    pricing = PRICING.get(model, PRICING["gpt-4o"])
    total_input = sum(r.get("_usage", {}).get("prompt_tokens", 0) for r in results)
    total_output = sum(r.get("_usage", {}).get("completion_tokens", 0) for r in results)
    cost = (total_input * pricing["input"] + total_output * pricing["output"]) / 1_000_000

    for r in results:
        r.pop("_usage", None)

    logger.info(
        "Described %d instances. Tokens: %d in / %d out. Cost: $%.4f",
        len(results), total_input, total_output, cost,
    )

    return list(results), cost
