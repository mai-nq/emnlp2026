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
@click.option("--pool", type=click.Choice(["test", "sft", "rl", "all"]), default="all",
              help="Which pool to describe: test, sft, rl, or all")
@click.option("--api-key", envvar="OPENROUTER_API_KEY", help="OpenRouter API key")
@click.pass_context
def describe(ctx, task, pool, api_key):
    """Generate NL descriptions via OpenRouter API (hybrid model strategy)."""
    config = ctx.obj["config"]
    desc_cfg = config["description"]
    max_concurrent = desc_cfg["max_concurrent"]
    cost_limit = desc_cfg["cost_limit_usd"]

    from openai import AsyncOpenAI
    from src.describers.gpt4o_describer import describe_batch

    base_url = desc_cfg.get("base_url", "https://openrouter.ai/api/v1")
    client = AsyncOpenAI(base_url=base_url, api_key=api_key)

    # Model per pool
    model_map = {
        "test": desc_cfg.get("test_model", "anthropic/claude-sonnet-4-6"),
        "sft": desc_cfg.get("sft_model", "anthropic/claude-sonnet-4-6"),
        "rl": desc_cfg.get("rl_model", "openai/gpt-4o-mini"),
    }

    pools_to_run = ["test", "sft", "rl"] if pool == "all" else [pool]
    tasks_to_run = ["sigma", "yara", "stix"] if task == "all" else [task]
    total_cost = 0.0

    for p in pools_to_run:
        model = model_map[p]
        pool_dir = Path(f"data/splits/{p}")
        out_dir = Path(f"data/described/{p}")
        out_dir.mkdir(parents=True, exist_ok=True)

        for t in tasks_to_run:
            input_path = pool_dir / f"{t}.jsonl"
            if not input_path.exists():
                click.echo(f"Skipping {p}/{t}: {input_path} not found", err=True)
                continue

            instances = read_jsonl(input_path)
            # Skip already described
            already_done = set()
            out_path = out_dir / f"{t}.jsonl"
            if out_path.exists():
                done = read_jsonl(out_path)
                already_done = {d["gold_artifact"][:100] for d in done if d.get("nl_description")}
            todo = [i for i in instances if i["gold_artifact"][:100] not in already_done]

            if not todo:
                click.echo(f"[{p}] All {t} instances already described")
                continue

            if total_cost >= cost_limit:
                click.echo(f"Cost limit ${cost_limit} reached. Stopping.", err=True)
                return

            click.echo(f"[{p}] Describing {len(todo)}/{len(instances)} {t} instances with {model}...")
            results, cost = asyncio.run(
                describe_batch(todo, client, model=model, max_concurrent=max_concurrent)
            )
            total_cost += cost

            # Append to existing results
            if already_done and out_path.exists():
                write_jsonl(results, out_path, append=True)
            else:
                write_jsonl(results, out_path)
            click.echo(f"[{p}] Described {len(results)} {t} instances (cost: ${cost:.4f})")

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
    """Deduplicate and split into test / sft / rl / remaining pools.

    Writes per-task JSONL files to data/splits/{test,sft,rl}/ for the
    describe step, and also writes merged files to data/final/.
    """
    import random as stdlib_random

    config = ctx.obj["config"]
    extracted_dir = Path("data/described")  # annotated data lives here
    splits_dir = Path("data/splits")
    final_dir = Path("data/final")

    # Merge all tasks
    all_instances = []
    for task_file in ["sigma.jsonl", "yara.jsonl", "stix.jsonl"]:
        path = extracted_dir / task_file
        if path.exists():
            all_instances.extend(read_jsonl(path))

    # Dedup
    unique = deduplicate(all_instances)

    # --- Test split (stratified by difficulty) ---
    test_size = config["split"]["test_size"]
    seed = config["split"]["seed"]
    test_per_task = test_size // 3

    diff_dist = config.get("dataset", {}).get("difficulty_distribution")
    train_pool, test = split_dataset(unique, test_per_task=test_per_task, seed=seed, difficulty_dist=diff_dist)

    # --- SFT and RL splits from train_pool ---
    train_cfg = config.get("training", {})
    sft_per_task = train_cfg.get("sft_per_task", 6000)
    rl_per_task = train_cfg.get("rl_per_task", 10000)

    rng = stdlib_random.Random(seed)

    # Group train_pool by task
    by_task = {}
    for inst in train_pool:
        by_task.setdefault(inst["task"], []).append(inst)

    sft_instances = []
    rl_instances = []
    remaining = []

    for task, pool in by_task.items():
        rng.shuffle(pool)
        sft_n = min(sft_per_task, len(pool))
        sft_instances.extend(pool[:sft_n])

        leftover = pool[sft_n:]
        rl_n = min(rl_per_task, len(leftover))
        rl_instances.extend(leftover[:rl_n])

        remaining.extend(leftover[rl_n:])

    # Assign IDs
    test = assign_ids(test)
    sft_instances = assign_ids(sft_instances)
    rl_instances = assign_ids(rl_instances)

    # --- Write per-task files for describe step ---
    task_map = {"T-SIGMA": "sigma", "T-YARA": "yara", "T-STIX": "stix"}

    for split_name, instances in [("test", test), ("sft", sft_instances), ("rl", rl_instances)]:
        split_dir = splits_dir / split_name
        split_dir.mkdir(parents=True, exist_ok=True)
        by_t = {}
        for inst in instances:
            by_t.setdefault(inst["task"], []).append(inst)
        for task_key, insts in by_t.items():
            fname = task_map.get(task_key, task_key.lower().replace("t-", "")) + ".jsonl"
            write_jsonl(insts, split_dir / fname)

    # --- Write merged final files ---
    final_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(test, final_dir / "test.jsonl")
    click.echo(f"Test:  {len(test)} instances")

    write_jsonl(sft_instances, final_dir / "sft.jsonl")
    click.echo(f"SFT:   {len(sft_instances)} instances ({sft_per_task}/task target)")

    write_jsonl(rl_instances, final_dir / "rl.jsonl")
    click.echo(f"RL:    {len(rl_instances)} instances ({rl_per_task}/task target)")

    write_jsonl(remaining, final_dir / "remaining.jsonl")
    click.echo(f"Remaining: {len(remaining)} (CPT corpus)")

    # Summary per task
    click.echo("\nPer-task breakdown:")
    for split_name, instances in [("test", test), ("sft", sft_instances), ("rl", rl_instances)]:
        by_t = {}
        for inst in instances:
            by_t.setdefault(inst["task"], 0)
            by_t[inst["task"]] += 1
        click.echo(f"  {split_name}: {dict(sorted(by_t.items()))}")


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
