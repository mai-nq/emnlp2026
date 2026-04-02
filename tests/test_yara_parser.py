from pathlib import Path

from src.parsers.yara_parser import parse_yara_file, extract_yara_rules


def test_parse_yara_file_single_rule(sample_yara_rule_text, tmp_dir):
    path = tmp_dir / "test.yar"
    path.write_text(sample_yara_rule_text)
    results = parse_yara_file(path)
    assert len(results) == 1
    rule = results[0]
    assert rule["task"] == "T-YARA"
    assert "Test_Malware" in rule["gold_artifact"]
    assert rule["metadata"]["original_title"] == "Test_Malware"
    assert rule["complexity"]["num_strings"] == 2
    assert rule["complexity"]["num_conditions"] >= 1


def test_parse_yara_file_multiple_rules(tmp_dir):
    text = '''rule Rule_A {
    strings:
        $a = "alpha"
    condition:
        $a
}

rule Rule_B {
    strings:
        $b1 = "beta"
        $b2 = "gamma"
    condition:
        any of ($b*)
}'''
    path = tmp_dir / "multi.yar"
    path.write_text(text)
    results = parse_yara_file(path)
    assert len(results) == 2
    assert results[0]["metadata"]["original_title"] == "Rule_A"
    assert results[1]["complexity"]["num_strings"] == 2


def test_parse_yara_file_with_meta(tmp_dir):
    text = '''rule Emotet {
    meta:
        description = "Detects Emotet loader"
        author = "Analyst"
        reference = "https://example.com"
    strings:
        $s1 = "DllRegisterServer"
    condition:
        $s1
}'''
    path = tmp_dir / "meta.yar"
    path.write_text(text)
    results = parse_yara_file(path)
    assert results[0]["metadata"]["description"] == "Detects Emotet loader"


def test_parse_yara_file_invalid(tmp_dir):
    path = tmp_dir / "bad.yar"
    path.write_text("this is not a yara rule at all")
    results = parse_yara_file(path)
    assert results == []


def test_extract_yara_rules(tmp_dir):
    rules_dir = tmp_dir / "yara_rules"
    rules_dir.mkdir()
    for i in range(2):
        text = f'''rule Test_{i} {{
    strings:
        $s = "test{i}"
    condition:
        $s
}}'''
        (rules_dir / f"rule_{i}.yar").write_text(text)
    results = extract_yara_rules(rules_dir)
    assert len(results) == 2
