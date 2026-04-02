# tests/test_cli.py
from click.testing import CliRunner

from scripts.build_dataset import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "CyberOutputBench" in result.output


def test_cli_fetch_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["fetch", "--help"])
    assert result.exit_code == 0
    assert "Clone source repositories" in result.output


def test_cli_extract_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["extract", "--help"])
    assert result.exit_code == 0


def test_cli_describe_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["describe", "--help"])
    assert result.exit_code == 0


def test_cli_split_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["split", "--help"])
    assert result.exit_code == 0


def test_cli_annotate_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["annotate", "--help"])
    assert result.exit_code == 0


def test_cli_validate_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "--help"])
    assert result.exit_code == 0


def test_cli_export_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["export", "--help"])
    assert result.exit_code == 0
