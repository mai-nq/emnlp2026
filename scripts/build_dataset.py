#!/usr/bin/env python3
"""CyberOutputBench dataset construction CLI."""

import asyncio
import json
import subprocess
from pathlib import Path

import click

from src.utils.io import load_config, read_jsonl, write_jsonl, setup_logging
from src.parsers.sigma_parser import extract_sigma_rules
from src.parsers.yara_parser import extract_yara_rules
from src.parsers.stix_parser import extract_stix_rules
from src.annotators.complexity import annotate_complexity
from src.validators.quality import validate_instance, filter_trivial
from src.splitter import deduplicate, assign_ids, split_dataset

logger = setup_logging("build_dataset")

DEFAULT_CONFIG = "configs/dataset.yaml"


@click.group()
@click.option("--config", default=DEFAULT_CONFIG, help="Path to dataset.yaml config")
@click.pass_context
def cli(ctx, config):
    """CyberOutputBench dataset construction pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)
    ctx.obj["config_path"] = config


@cli.command()
@click.pass_context
def fetch(ctx):
    """Clone source repositories into data/raw/."""
    config = ctx.obj["config"]
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)

    repos = {
        "sigma": config["sources"]["sigma_repo"],
        "yara_forge": config["sources"]["yara_forge"],
        "mitre_stix": config["sources"]["mitre_stix"],
    }

    for name, url in repos.items():
        dest = raw_dir / name
        if dest.exists():
            logger.info("Repo %s already exists, pulling latest...", name)
            subprocess.run(["git", "-C", str(dest), "pull"], check=True)
        else:
            logger.info("Cloning %s from %s...", name, url)
            subprocess.run(["git", "clone", "--depth=1", url, str(dest)], check=True)

    click.echo(f"Fetched {len(repos)} repos to {raw_dir}")


@cli.command()
@click.pass_context
def extract(ctx):
    """Extract rules from cloned repos into data/extracted/ JSONL files."""
    raw_dir = Path("data/raw")
    out_dir = Path("data/extracted")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sigma
    sigma_dir = raw_dir / "sigma" / "rules"
    if sigma_dir.exists():
        sigma_rules = extract_sigma_rules(sigma_dir)
        write_jsonl(sigma_rules, out_dir / "sigma.jsonl")
        click.echo(f"Extracted {len(sigma_rules)} Sigma rules")
    else:
        click.echo("Warning: Sigma rules directory not found", err=True)

    # YARA
    yara_dir = raw_dir / "yara_forge"
    if yara_dir.exists():
        yara_rules = extract_yara_rules(yara_dir)
        write_jsonl(yara_rules, out_dir / "yara.jsonl")
        click.echo(f"Extracted {len(yara_rules)} YARA rules")
    else:
        click.echo("Warning: YARA Forge directory not found", err=True)

    # STIX
    stix_dir = raw_dir / "mitre_stix"
    if stix_dir.exists():
        stix_rules = extract_stix_rules(stix_dir)
        write_jsonl(stix_rules, out_dir / "stix.jsonl")
        click.echo(f"Extracted {len(stix_rules)} STIX technique bundles")
    else:
        click.echo("Warning: MITRE STIX directory not found", err=True)


@cli.command()
@click.option("--task", type=click.Choice(["sigma", "yara", "stix", "all"]), default="all")
@click.pass_context
def describe(ctx, task):
    """Generate NL descriptions via GPT-4o for extracted instances."""
    config = ctx.obj["config"]
    extracted_dir = Path("data/extracted")
    out_dir = Path("data/described")
    out_dir.mkdir(parents=True, exist_ok=True)

    from openai import AsyncOpenAI
    from src.describers.gpt4o_describer import describe_batch

    client = AsyncOpenAI()
    model = config["description"]["model"]
    max_concurrent = config["description"]["max_concurrent"]
    cost_limit = config["description"]["cost_limit_usd"]

    tasks = ["sigma", "yara", "stix"] if task == "all" else [task]
    total_cost = 0.0

    for t in tasks:
        input_path = extracted_dir / f"{t}.jsonl"
        if not input_path.exists():
            click.echo(f"Skipping {t}: {input_path} not found", err=True)
            continue

        instances = read_jsonl(input_path)
        # Skip already described
        instances = [i for i in instances if not i.get("nl_description")]

        if not instances:
            click.echo(f"All {t} instances already described")
            continue

        if total_cost >= cost_limit:
            click.echo(f"Cost limit ${cost_limit} reached. Stopping.", err=True)
            break

        click.echo(f"Describing {len(instances)} {t} instances...")
        results, cost = asyncio.run(
            describe_batch(instances, client, model=model, max_concurrent=max_concurrent)
        )
        total_cost += cost

        write_jsonl(results, out_dir / f"{t}.jsonl")
        click.echo(f"Described {len(results)} {t} instances (cost: ${cost:.4f})")

    click.echo(f"Total description cost: ${total_cost:.4f}")


@cli.command()
@click.pass_context
def annotate(ctx):
    """Add difficulty/complexity annotations to described instances.

    Note: Run BEFORE split. Annotates all instances so both train and test
    have difficulty labels (needed for stratified splitting).
    """
    config = ctx.obj["config"]
    described_dir = Path("data/described")

    # Pass config thresholds if provided
    diff_dist = config.get("dataset", {}).get("difficulty_distribution")

    for task_file in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
        path = described_dir / task_file
        if not path.exists():
            continue
        instances = read_jsonl(path)
        annotated = annotate_complexity(instances)
        write_jsonl(annotated, path)
        click.echo(f"Annotated {len(annotated)} instances in {task_file}")


@cli.command()
@click.pass_context
def split(ctx):
    """Deduplicate and split into train/test sets."""
    config = ctx.obj["config"]
    described_dir = Path("data/described")
    out_dir = Path("data/final")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Merge all tasks
    all_instances = []
    for task_file in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
        path = described_dir / task_file
        if path.exists():
            all_instances.extend(read_jsonl(path))

    # Dedup
    unique = deduplicate(all_instances)

    # Split first, then assign IDs (so IDs are contiguous within each split)
    test_size = config["split"]["test_size"]
    seed = config["split"]["seed"]
    test_per_task = test_size // 3

    train, test = split_dataset(unique, test_per_task=test_per_task, seed=seed)

    # Assign sequential IDs within each split
    train = assign_ids(train)
    test = assign_ids(test)

    write_jsonl(train, out_dir / "train.jsonl")
    write_jsonl(test, out_dir / "test.jsonl")
    click.echo(f"Split: {len(test)} test, {len(train)} train")


@cli.command()
@click.pass_context
def validate(ctx):
    """Run tool-based validation on test set gold artifacts."""
    config = ctx.obj["config"]
    final_dir = Path("data/final")
    test_path = final_dir / "test.jsonl"

    if not test_path.exists():
        click.echo("Error: test.jsonl not found. Run 'split' first.", err=True)
        return

    instances = read_jsonl(test_path)
    min_comp = config["dataset"]["min_components"]

    # Filter trivial
    filtered = filter_trivial(instances, min_components=min_comp)
    click.echo(f"After trivial filter: {len(filtered)}/{len(instances)}")

    # Validate each
    validated = [validate_instance(i) for i in filtered]
    valid = [v for v in validated if v["_valid"]]
    invalid = [v for v in validated if not v["_valid"]]

    click.echo(f"Valid: {len(valid)}, Invalid: {len(invalid)}")

    # Write validated set
    write_jsonl(validated, final_dir / "test_validated.jsonl")

    # Log errors
    if invalid:
        for inv in invalid[:10]:
            logger.warning("Invalid %s: %s", inv.get("id", "?"), inv["_errors"])


@cli.command()
@click.option("--output", default="data/final/cyberoutputbench.json", help="Output path")
@click.pass_context
def export(ctx, output):
    """Export validated test set to benchmark release format (JSON)."""
    final_dir = Path("data/final")
    validated_path = final_dir / "test_validated.jsonl"

    if not validated_path.exists():
        click.echo("Error: test_validated.jsonl not found. Run 'validate' first.", err=True)
        return

    instances = read_jsonl(validated_path)

    # Keep only valid instances, remove internal fields
    export_data = []
    for inst in instances:
        if not inst.get("_valid", False):
            continue
        clean = {k: v for k, v in inst.items() if not k.startswith("_")}
        export_data.append(clean)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    click.echo(f"Exported {len(export_data)} instances to {output_path}")

    # Print stats
    by_task = {}
    for inst in export_data:
        task = inst["task"]
        by_task.setdefault(task, {"easy": 0, "medium": 0, "hard": 0})
        diff = inst.get("difficulty", "medium")
        by_task[task][diff] = by_task[task].get(diff, 0) + 1

    for task, dists in sorted(by_task.items()):
        total = sum(dists.values())
        click.echo(f"  {task}: {total} (E={dists['easy']}, M={dists['medium']}, H={dists['hard']})")


if __name__ == "__main__":
    cli()
