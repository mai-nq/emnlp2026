"""Quality validation using domain-specific tools."""

import json

import yaml

from src.utils.io import setup_logging

logger = setup_logging("quality_validator")


def validate_sigma(artifact: str) -> tuple[bool, list[str]]:
    """Validate a Sigma rule YAML string using pySigma."""
    errors = []
    try:
        rule_dict = yaml.safe_load(artifact)
    except yaml.YAMLError as e:
        return False, [f"Invalid YAML: {e}"]

    if not isinstance(rule_dict, dict):
        return False, ["Not a YAML mapping"]

    # Basic required field check first
    required = ["title", "logsource", "detection"]
    for field in required:
        if field not in rule_dict:
            errors.append(f"Missing required field: {field}")
    if errors:
        return False, errors

    # Use pySigma for deeper validation
    try:
        from sigma.rule import SigmaRule

        SigmaRule.from_yaml(artifact)
        return True, []
    except Exception as e:
        return False, [f"pySigma validation error: {e}"]


def validate_yara(artifact: str) -> tuple[bool, list[str]]:
    """Validate a YARA rule by attempting compilation."""
    try:
        import yara

        yara.compile(source=artifact)
        return True, []
    except yara.SyntaxError as e:
        return False, [f"YARA syntax error: {e}"]
    except yara.Error as e:
        return False, [f"YARA error: {e}"]
    except Exception as e:
        return False, [f"Unexpected error: {e}"]


def validate_stix(artifact: str) -> tuple[bool, list[str]]:
    """Validate a STIX 2.1 bundle JSON string."""
    errors = []
    try:
        bundle = json.loads(artifact)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]

    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        return False, ["Not a STIX bundle (missing type: bundle)"]

    objects = bundle.get("objects", [])
    if not objects:
        return False, ["Bundle has no objects"]

    # Basic schema checks per object
    for i, obj in enumerate(objects):
        if "type" not in obj:
            errors.append(f"Object {i}: missing 'type'")
        if "id" not in obj:
            errors.append(f"Object {i}: missing 'id'")

    # Try stix2-validator if available (warnings only, basic checks above are authoritative)
    try:
        from stix2validator import validate_string
        from stix2validator.errors import ValidationError

        try:
            result = validate_string(artifact)
            if not result.is_valid:
                for msg in result.errors:
                    logger.warning("stix2-validator: %s", msg)
        except ValidationError as e:
            logger.warning("stix2-validator: %s", e)
    except ImportError:
        logger.debug("stix2-validator not available, using basic checks only")

    return len(errors) == 0, errors


_VALIDATORS = {
    "T-SIGMA": validate_sigma,
    "T-YARA": validate_yara,
    "T-STIX": validate_stix,
}


def validate_instance(instance: dict) -> dict:
    """Validate a single instance's gold_artifact. Adds _valid and _errors fields."""
    result = dict(instance)
    task = instance["task"]
    validator = _VALIDATORS.get(task)

    if validator is None:
        result["_valid"] = False
        result["_errors"] = [f"No validator for task: {task}"]
        return result

    is_valid, errors = validator(instance["gold_artifact"])
    result["_valid"] = is_valid
    result["_errors"] = errors
    return result


def filter_trivial(instances: list[dict], min_components: int = 3) -> list[dict]:
    """Remove instances with fewer than min_components total components."""
    result = []
    for inst in instances:
        c = inst.get("complexity", {})
        total = sum(v for v in c.values() if isinstance(v, (int, float)))
        if total >= min_components:
            result.append(inst)
    filtered = len(instances) - len(result)
    if filtered:
        logger.info("Filtered %d trivial instances (<%d components)", filtered, min_components)
    return result
