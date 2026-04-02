"""Parse MITRE ATT&CK STIX 2.1 bundles into CyberOutputBench instance schema."""

import json
from pathlib import Path

from src.utils.io import setup_logging

logger = setup_logging("stix_parser")

SRO_TYPES = {"relationship", "sighting"}


def parse_stix_bundle(bundle: dict, source: str) -> dict | None:
    objects = bundle.get("objects", [])
    if not objects:
        return None

    sdos = [o for o in objects if o.get("type") not in SRO_TYPES]
    sros = [o for o in objects if o.get("type") in SRO_TYPES]

    rel_types = set()
    for sro in sros:
        rt = sro.get("relationship_type", "")
        if rt:
            rel_types.add(rt)

    mitre_ids = []
    for obj in objects:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id:
                    mitre_ids.append(ext_id)

    gold_artifact = json.dumps(bundle, indent=2, ensure_ascii=False)

    return {
        "task": "T-STIX",
        "source": source,
        "gold_artifact": gold_artifact,
        "metadata": {
            "mitre_attack": mitre_ids,
            "license": "Apache-2.0",
            "object_types": list({o["type"] for o in objects}),
            "relationship_types": list(rel_types),
        },
        "complexity": {
            "num_sdos": len(sdos),
            "num_sros": len(sros),
            "num_objects": len(objects),
            "reasoning_depth": len(sdos) + len(sros),
        },
    }


def extract_technique_bundles(bundle_path: Path) -> list[dict]:
    bundle_path = Path(bundle_path)
    try:
        with open(bundle_path) as f:
            full_bundle = json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to load STIX bundle: %s", bundle_path)
        return []

    if not isinstance(full_bundle, dict):
        logger.warning("Skipping non-bundle STIX file: %s", bundle_path)
        return []

    objects = full_bundle.get("objects", [])
    obj_by_id = {o["id"]: o for o in objects if "id" in o}

    techniques = [o for o in objects if o.get("type") == "attack-pattern"]

    rels_by_source = {}
    rels_by_target = {}
    for o in objects:
        if o.get("type") == "relationship":
            src = o.get("source_ref", "")
            tgt = o.get("target_ref", "")
            rels_by_source.setdefault(src, []).append(o)
            rels_by_target.setdefault(tgt, []).append(o)

    results = []
    for tech in techniques:
        tech_id = tech["id"]
        sub_objects = [tech]
        seen_ids = {tech_id}

        related_rels = rels_by_source.get(tech_id, []) + rels_by_target.get(tech_id, [])

        for rel in related_rels:
            if rel["id"] not in seen_ids:
                sub_objects.append(rel)
                seen_ids.add(rel["id"])
            other_id = (
                rel["target_ref"] if rel["source_ref"] == tech_id else rel["source_ref"]
            )
            if other_id not in seen_ids and other_id in obj_by_id:
                sub_objects.append(obj_by_id[other_id])
                seen_ids.add(other_id)

        sub_bundle = {
            "type": "bundle",
            "id": f"bundle--technique-{tech_id}",
            "objects": sub_objects,
        }

        parsed = parse_stix_bundle(sub_bundle, source=str(bundle_path))
        if parsed is not None:
            parsed["metadata"]["technique_name"] = tech.get("name", "")
            results.append(parsed)

    return results


def extract_stix_rules(stix_dir: Path) -> list[dict]:
    stix_dir = Path(stix_dir)
    results = []
    for path in sorted(stix_dir.rglob("*.json")):
        extracted = extract_technique_bundles(path)
        results.extend(extracted)
    return results
