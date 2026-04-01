# Dataset Construction Pipeline — Design Spec

**Date:** 2026-04-01
**Status:** Approved
**Scope:** Scripts to build the CyberOutputBench dataset (600 instances across YARA, Sigma, STIX)

---

## Decisions

- **Architecture:** Single CLI entry point (`build_dataset.py`) with click subcommands
- **Data sources:** Auto-clone SigmaHQ/sigma, YARA Forge, MITRE ATT&CK STIX repos
- **NL description generation:** GPT-4o via OpenAI API
- **Language/structure:** Python scripts in `scripts/`, shared modules in `src/`

## Project Structure

```
cyberoutputbech/
├── scripts/
│   └── build_dataset.py          # Main CLI (click subcommands)
├── src/
│   ├── __init__.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── sigma_parser.py       # Parse SigmaHQ rules → structured dict
│   │   ├── yara_parser.py        # Parse YARA Forge rules → structured dict
│   │   └── stix_parser.py        # Parse MITRE ATT&CK STIX → structured dict
│   ├── describers/
│   │   ├── __init__.py
│   │   └── gpt4o_describer.py    # GPT-4o NL description generation
│   ├── annotators/
│   │   ├── __init__.py
│   │   └── complexity.py         # Difficulty/complexity annotation
│   ├── validators/
│   │   ├── __init__.py
│   │   └── quality.py            # QC checks (functional validation, dedup)
│   └── utils/
│       ├── __init__.py
│       └── io.py                 # JSONL read/write, logging, config
├── data/                         # Git-ignored, intermediate outputs
│   ├── raw/                      # Cloned repos
│   ├── extracted/                # Parsed rules (JSONL per task)
│   ├── described/                # With NL descriptions
│   └── final/                    # Train/test split, ready for evaluation
└── configs/
    └── dataset.yaml              # Configurable params
```

## Data Flow

```
[fetch] → data/raw/ (cloned repos)
    ↓
[extract] → data/extracted/{sigma,yara,stix}.jsonl
    ↓
[describe] → data/described/{sigma,yara,stix}.jsonl (+ NL descriptions)
    ↓
[split] → data/final/train.jsonl + data/final/test.jsonl
    ↓
[annotate] → data/final/test_annotated.jsonl (+ difficulty, complexity)
    ↓
[validate] → data/final/test_validated.jsonl (+ QC flags)
    ↓
[export] → data/final/cyberoutputbench.json (benchmark release format)
```

Each step is resumable — reads from previous output, saves checkpoints.

## Instance Schema (JSONL)

```json
{
  "id": "sigma-001",
  "task": "T-SIGMA",
  "source": "SigmaHQ/rules/windows/process_creation/proc_creation_win_lsass_dump.yml",
  "gold_artifact": "title: LSASS Memory Dump...\n...",
  "nl_description": "Create a Sigma rule to detect...",
  "nl_description_model": "gpt-4o-2024-11-20",
  "difficulty": "medium",
  "complexity": {
    "num_selections": 3,
    "num_filters": 2,
    "num_conditions": 5,
    "reasoning_depth": 3
  },
  "metadata": {
    "mitre_attack": ["T1003.001"],
    "license": "DRL-1.1",
    "original_title": "LSASS Memory Dump Detection"
  },
  "split": "test"
}
```

## Key Components

### Parsers
- `sigma_parser.py`: Read YAML, extract title/description/detection/logsource, count selection criteria + filters
- `yara_parser.py`: Parse rule blocks via `plyara`, extract strings/conditions/meta, count components
- `stix_parser.py`: Parse JSON bundles, extract SDOs/SROs, count objects and relationships

### Describer (GPT-4o)
- Input: gold artifact + metadata
- Output: NL description (task prompt for benchmark)
- Rate limiting, retry with exponential backoff, cost tracking
- Batched with `asyncio` for throughput (~10 concurrent)
- Prompt template per task type (YARA/Sigma/STIX)

### Splitter
- SHA256 hash-based deduplication on normalized artifacts
- Stratified split: 200/task for test set, difficulty distribution (60/80/60)
- Remaining instances → training pool for CyberOutputBench-LM SFT
- Fixed seed (42) for reproducibility

### Validators
- YARA: compile with `yara-python` — must not error
- Sigma: validate with `pySigma` — required fields present
- STIX: validate with `stix2-validator` — schema conformance
- Filter out: trivial instances (<3 components), duplicates, ambiguous (multiple valid interpretations flagged manually)

## Config (`configs/dataset.yaml`)

```yaml
sources:
  sigma_repo: "https://github.com/SigmaHQ/sigma.git"
  yara_forge: "https://github.com/YARAHQ/yara-forge.git"
  mitre_stix: "https://github.com/mitre-attack/attack-stix-data.git"

dataset:
  target_per_task: 200
  difficulty_distribution: {easy: 60, medium: 80, hard: 60}
  min_components: 3

description:
  model: "gpt-4o"
  max_concurrent: 10
  cost_limit_usd: 50.0

split:
  test_size: 600  # 200 per task
  seed: 42
```

## Dependencies

```
click>=8.0
pyyaml>=6.0
plyara>=2.1
yara-python>=4.3
pySigma>=0.10
stix2-validator>=3.0
stix2>=3.0
openai>=1.0
aiohttp>=3.9
tqdm>=4.65
```
