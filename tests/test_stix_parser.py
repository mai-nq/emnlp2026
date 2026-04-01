import json
from pathlib import Path

from src.parsers.stix_parser import (
    parse_stix_bundle,
    extract_technique_bundles,
    extract_stix_rules,
)


def test_parse_stix_bundle(sample_stix_bundle):
    result = parse_stix_bundle(sample_stix_bundle, source="test/bundle.json")
    assert result["task"] == "T-STIX"
    assert '"type": "bundle"' in result["gold_artifact"]
    assert result["complexity"]["num_sdos"] == 2
    assert result["complexity"]["num_sros"] == 1
    assert result["complexity"]["num_objects"] == 3


def test_parse_stix_bundle_empty():
    bundle = {"type": "bundle", "id": "bundle--empty", "objects": []}
    result = parse_stix_bundle(bundle, source="empty.json")
    assert result is None


def test_extract_technique_bundles(sample_stix_bundle, tmp_dir):
    bundle = dict(sample_stix_bundle)
    bundle["objects"] = list(bundle["objects"]) + [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "name": "Spearphishing",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--tech",
            "spec_version": "2.1",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "relationship_type": "uses",
            "source_ref": "malware--1234",
            "target_ref": "attack-pattern--001",
        },
    ]
    path = tmp_dir / "enterprise-attack.json"
    path.write_text(json.dumps(bundle))
    results = extract_technique_bundles(path)
    assert len(results) >= 1
    assert any("Spearphishing" in r["gold_artifact"] for r in results)


def test_extract_stix_rules(tmp_dir):
    stix_dir = tmp_dir / "stix"
    stix_dir.mkdir()
    for domain in ["enterprise-attack", "mobile-attack"]:
        bundle = {
            "type": "bundle",
            "id": f"bundle--{domain}",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{domain}",
                    "spec_version": "2.1",
                    "created": "2026-01-01T00:00:00Z",
                    "modified": "2026-01-01T00:00:00Z",
                    "name": f"Technique {domain}",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T0001"}
                    ],
                }
            ],
        }
        sub = stix_dir / domain
        sub.mkdir()
        (sub / f"{domain}.json").write_text(json.dumps(bundle))
    results = extract_stix_rules(stix_dir)
    assert len(results) >= 2
