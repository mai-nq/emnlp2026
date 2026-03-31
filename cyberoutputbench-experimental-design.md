# CyberOutputBench: Experimental Design
## Benchmarking LLMs on Executable Security Artifact Generation

**Target:** ARR May 2026 → EMNLP 2026
**Timeline:** 8 tuần (Tháng 4–5/2026)

---

## 1. Research Questions

**RQ1 (Syntactic Competence):** LLMs có thể tạo ra security artifacts đúng cú pháp ở mức nào? Tỷ lệ syntactic correctness khác nhau như thế nào giữa YARA, Sigma, và STIX 2.1?

**RQ2 (Semantic Correctness):** Khi output đúng cú pháp, nó có capture đúng logic phát hiện/mô tả mối đe dọa được yêu cầu không? Các lỗi ngữ nghĩa phổ biến nhất là gì?

**RQ3 (Operational Safety):** Output có chứa rủi ro vận hành không? (ví dụ: YARA rule quá rộng match mọi file, Sigma rule gây false positive storm, STIX bundle với relationship sai)

**RQ4 (Factor Analysis):** Những yếu tố nào ảnh hưởng đến chất lượng output? (model size, domain pretraining, prompting strategy, task complexity)

---

## 2. Task Definitions

### Task 1: YARA Rule Generation (T-YARA)
**Input:** Mô tả ngôn ngữ tự nhiên về malware hoặc threat indicator
**Output:** YARA rule hoàn chỉnh có thể compile và match đúng target

**Ví dụ input:**
```
Write a YARA rule to detect the Emotet trojan loader. The malware 
typically contains the strings "DllRegisterServer" and "DllInstall" 
in the export table, uses XOR encoding with a key size of 4 bytes, 
and has a PE file size between 200KB and 800KB.
```

**Ví dụ expected output:**
```yara
rule Emotet_Loader {
    meta:
        description = "Detects Emotet trojan loader"
        author = "CyberOutputBench"
        date = "2026-01"
    strings:
        $export1 = "DllRegisterServer" ascii
        $export2 = "DllInstall" ascii
        $xor_pattern = { ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and
        filesize > 200KB and filesize < 800KB and
        all of ($export*) and
        for any i in (0..3) : (
            @xor_pattern[i] != 0x00
        )
}
```

**Phân bố độ khó (200 instances):**
- Easy (60): Single-string detection, basic file properties
- Medium (80): Multiple conditions, wildcard patterns, PE structure checks
- Hard (60): Complex logic (loops, regex, module imports like `pe`, `math`, `hash`)

### Task 2: Sigma Rule Generation (T-SIGMA)
**Input:** Mô tả hành vi tấn công hoặc sự kiện cần phát hiện trong log
**Output:** Sigma rule YAML hợp lệ tuân thủ Sigma specification

**Ví dụ input:**
```
Create a Sigma rule to detect potential credential dumping via LSASS 
memory access. The rule should trigger when a process other than 
known legitimate tools (like svchost.exe or wmiprvse.exe) accesses 
lsass.exe with PROCESS_VM_READ access rights. Target Sysmon Event ID 10.
```

**Phân bố độ khó (200 instances):**
- Easy (60): Single log source, simple detection logic, 1–2 conditions
- Medium (80): Multiple selection criteria, filter/exclude logic, timeframe
- Hard (60): Aggregation conditions, correlation across log sources, near/temporal logic

### Task 3: STIX 2.1 Bundle Generation (T-STIX)
**Input:** Mô tả threat intelligence bằng ngôn ngữ tự nhiên
**Output:** STIX 2.1 Bundle JSON hợp lệ với đúng SDOs, SROs, và relationships

**Ví dụ input:**
```
Create a STIX 2.1 bundle describing the following threat intelligence: 
APT29 (Cozy Bear) conducted a spear-phishing campaign in January 2026 
targeting government agencies. They used a malware called "SunBurst" 
delivered via trojanized software update. The C2 server communicated 
over HTTPS to the domain "updates.example[.]com" on port 443.
```

**Phân bố độ khó (200 instances):**
- Easy (60): 2–3 SDOs with simple relationships (indicator→malware)
- Medium (80): 5–8 SDOs, multiple relationship types, proper referencing
- Hard (60): Complex campaigns with multiple attack patterns, sightings, opinions

---

## 3. Dataset Construction

### 3.1 Data Sources

| Source | Loại | Số lượng ước tính | Giấy phép | Ghi chú |
|--------|------|-------------------|-----------|---------|
| SigmaHQ/sigma (GitHub) | Sigma rules + context | ~3,000+ rules (Core + ET tiers) | DRL 1.1 | **Primary source cho T-SIGMA.** Metadata chất lượng cao (title, description, ATT&CK tags, severity). Core package có FP testing. |
| YARA Forge Core Set | Curated YARA rules | ~500+ rules (high accuracy) | Various OSS | **Primary source cho T-YARA.** Chỉ ~40-60% community YARA rules có đủ context cho NL prompts; Forge Core Set đạt ~80%. |
| YARA-Rules/rules (GitHub) | YARA rules | ~500 rules | GPL-2.0 | Secondary source, cần filtering kỹ |
| Awesome-YARA collections | YARA rules + descriptions | ~800 rules | Various OSS | Supplementary, metadata không đồng đều |
| MITRE ATT&CK STIX data (v18+) | STIX 2.1 bundles | ~700+ techniques | Apache 2.0 | **Primary source cho T-STIX.** Structured SDOs/SROs, detection objects mới. |
| NVD/CVE descriptions | Threat context for YARA/STIX | ~200K CVEs | Public domain | Context cho forward construction |
| MITRE TRAM mappings | CTI report → ATT&CK | ~500 reports | Apache 2.0 | NL source cho Phase 2 |
| VirusTotal blog reports | Malware descriptions | ~200 reports | Fair use (summaries) | NL source cho Phase 2 |

**Benign sample sources (cho YARA VER testing):**
| Source | Loại | Ghi chú |
|--------|------|---------|
| Debian package repositories | Linux binaries | Freely distributable |
| Windows 10/11 system DLLs | Windows PE files | Standard clean corpus |
| GoodWare dataset | Curated benign executables | BODMAS dataset sử dụng 77,142 benign samples |

**Lưu ý:** MalwareBazaar API cho phép 2,000 downloads/ngày nhưng **không cung cấp benign samples** — cần source riêng.

### 3.1.1 Train/Test Data Split (cho CyberOutputBench-LM)

```
Full corpus (3000+ Sigma, 1000+ YARA, 1000+ STIX)
    ├── Test Set (600 instances) ← KHÔNG BAO GIỜ dùng cho training
    │     ├── T-YARA test (200)
    │     ├── T-SIGMA test (200)
    │     └── T-STIX test (200)
    └── Training Pool (phần còn lại) ← Dùng cho CPT + SFT
          ├── CPT: raw rules dạng text
          └── SFT: reverse-engineered (NL, artifact) pairs
```

- Hash-based deduplication giữa train và test instances
- Không có gold artifact nào từ test set xuất hiện trong training data
- Report chính xác train/test split trong paper

### 3.2 Dataset Construction Pipeline

**Phase 1: Reverse-Engineering Approach (Tuần 1)**
Tương tự phương pháp SQL-to-text trong text-to-SQL benchmarks:
1. Thu thập gold-standard YARA/Sigma/STIX artifacts từ các repo trên
2. Dùng GPT-4o để generate NL descriptions từ mỗi artifact
3. Human expert review và chỉnh sửa NL descriptions
4. Filter: chỉ giữ instances có description chất lượng cao

**Phase 2: Forward Construction (Tuần 1–2)**
1. Từ CVE descriptions và CTI reports, human experts viết NL requirements
2. Experts cũng viết gold-standard artifacts tương ứng
3. Cross-validate: expert A viết description, expert B viết artifact → so sánh

**Phase 3: Complexity Annotation (Tuần 2)**
Mỗi instance được annotate với:
- **Difficulty level:** Easy / Medium / Hard
- **Structural complexity:** Số components (strings, conditions, SDOs)
- **Reasoning depth:** Số bước suy luận từ NL → artifact
- **Domain specificity:** Generic security vs. specific malware family

### 3.3 Quality Control

- **Inter-annotator agreement:** 50 instances được annotate bởi 2 experts, tính Cohen's κ
- **Functional validation:** Mọi gold YARA rules compile với `yara`, Sigma rules validate với `sigma-cli`, STIX bundles validate với `stix2-validator`
- **Adversarial filtering:** Loại bỏ instances quá trivial (< 3 components) hoặc quá ambiguous (multiple valid interpretations)

### 3.4 Final Dataset Statistics (Target)

| Task | Total | Easy | Medium | Hard | Avg. components |
|------|-------|------|--------|------|-----------------|
| T-YARA | 200 | 60 | 80 | 60 | 5.2 strings + 3.1 conditions |
| T-SIGMA | 200 | 60 | 80 | 60 | 3.8 selection criteria + 1.4 filters |
| T-STIX | 200 | 60 | 80 | 60 | 4.6 SDOs + 3.2 SROs |
| **Total** | **600** | **180** | **240** | **180** | — |

---

## 4. Evaluation Metrics

### 4.1 Metric Hierarchy (Gating-based)

Thiết kế theo mô hình gating: metric sau chỉ tính khi metric trước pass.

```
[Refusal Rate] → [Parsability] → [Syntactic Correctness] → [Semantic Correctness] → [Operational Safety]
   Pre-Gate          Gate 0           Gate 1                    Gate 2                    Gate 3
```

#### Pre-Gate: Refusal Rate (RR)
**Định nghĩa:** Tỷ lệ outputs mà model từ chối tạo artifact (ví dụ: "I cannot generate malware detection rules" hoặc safety disclaimers thay vì artifact).

**Công thức:** RR = |refusals| / |total outputs|

**Rationale:** Inspired by CyberSecEval 4's False Refusal Rate (FRR). Một số models (đặc biệt safety-tuned commercial models) có thể từ chối tạo YARA/Sigma rules vì lo ngại security. RR đo safety-utility tradeoff — model quá an toàn sẽ có RR cao nhưng không hữu ích cho SOC teams.

**Detection:** Classify output as refusal nếu: (a) không chứa artifact structure nào, VÀ (b) chứa refusal keywords ("I cannot", "I'm unable", "against my guidelines", "potentially harmful").

### 4.2 Metric Definitions

#### Level 0: Parsability Rate (PR)
**Định nghĩa:** Tỷ lệ outputs có thể parse thành cấu trúc tương ứng
- YARA: Output chứa valid `rule` block structure
- Sigma: Output là valid YAML với required fields (`title`, `logsource`, `detection`)
- STIX: Output là valid JSON với `type: "bundle"` và `objects` array

**Công thức:** PR = |parsable outputs| / |total outputs|

#### Level 1: Syntactic Correctness Rate (SCR)
**Định nghĩa:** Tỷ lệ outputs pass tool-based validation
- YARA: `yara -C rule.yar` compiles without errors
- Sigma: `sigma check rule.yml` passes (hoặc `pySigma` validation)
- STIX: `stix2-validator bundle.json` passes schema validation

**Công thức:** SCR = |syntactically correct| / |parsable outputs|

**Lưu ý:** SCR chỉ tính trên outputs đã pass PR (gating).

#### Level 2: Validation Execution Rate (VER) — Semantic Correctness

Đây là metric quan trọng nhất, tương đương Execution Accuracy (EX) trong text-to-SQL.

**T-YARA VER (Three-Tier Evaluation):**

Đánh giá YARA VER theo 3 tầng để giải quyết bottleneck malware sample logistics:

**Tier 1 — Structural Semantic Match (tất cả 200 instances):**
1. Extract condition clause AST từ cả generated và gold rules (qua `yara-python` parsed representation)
2. Compute condition-clause equivalence: cả hai rules check cùng strings/hex patterns với cùng logical connectives?
3. Compute string-set coverage: bao nhiêu % string definitions của gold rule có trong generated rule?
4. Score: F1 over matched condition components
5. **Không cần malware samples**

**Tier 2 — Synthetic Sample Execution (tất cả 200 instances):**
1. Cho mỗi gold YARA rule, programmatically generate minimal PE file thỏa mãn conditions sử dụng `lief` library
2. Tạo per rule: 1 true-positive synthetic file + 3 near-miss negatives (match all-but-one condition) + 2 benign files (clean Windows DLLs/Debian binaries)
3. Chạy cả gold và generated rules trên synthetic samples
4. Tính:
   - True Positive Rate: Generated rule match đúng synthetic TP file
   - False Positive Rate: Generated rule KHÔNG match near-miss + benign files
   - VER_YARA_T2 = (TP ≥ 0.8) AND (FP ≤ 0.2)
5. **Synthetic samples distributable** (không như malware) → cải thiện reproducibility

**Tier 3 — Real Malware Spot-Check (~50 instances):**
1. Cho ~50 rules có confirmed matching samples trên MalwareBazaar
2. Download samples trong isolated environment
3. Chạy rules, report TP/FP rates
4. Compute correlation giữa Tier 2 và Tier 3 scores (Spearman ρ) để validate synthetic approach

**Primary metric:** VER_YARA = Tier 2 score (reproducible, full coverage)
**Validation:** Tier 3 correlation (ground truth check)
**Supplementary:** Tier 1 (structural analysis, useful for error diagnosis)

**Rationale:** Prior work (LLMCloudHunter) không evaluate YARA execution. Synthetic testing approach tương tự cách Sigma ecosystem dùng synthetic log entries. YARA rules là pattern-matching specifications → construct satisfying inputs là constraint-satisfaction problem, không phải creative problem.

**T-SIGMA VER:**
1. Convert Sigma rule sang **Splunk SPL** (primary backend, 85-90% conversion success trên Core rules) via `pySigma` + Splunk backend. Secondary: Elasticsearch ES|QL.
2. So sánh converted query với gold-standard query:
   - Exact Match (EM): Converted query == gold query (after normalization)
   - Execution Match (EXM): Cả hai query trả về cùng kết quả trên test log dataset
3. VER_SIGMA = EXM rate
4. **Report riêng:** Conversion failure rate (pySigma không convert được) — tách khỏi rule quality. Nếu generated rule syntactically correct (SCR pass) nhưng pySigma fail → lỗi thuộc về conversion pipeline, không phải model.

**T-STIX VER:**
1. Parse generated STIX bundle
2. So sánh với gold-standard bundle:
   - Object Coverage (OC): % SDOs trong gold có tương ứng trong generated
   - Relationship Accuracy (RA): % SROs đúng cả source_ref, target_ref, và relationship_type
   - Property Completeness (PC): % required properties được populate đúng
3. VER_STIX = weighted average: 0.4×OC + 0.4×RA + 0.2×PC

**Justification cho trọng số:**
- **OC = 0.4:** Trong CTI workflow, thiếu threat object (e.g., bỏ sót malware SDO hoặc indicator) = mất cơ hội detection. Recall-critical. Bundle thiếu đối tượng tạo false confidence rằng threat landscape đã fully characterized.
- **RA = 0.4:** Relationships là đặc trưng phân biệt STIX với flat IOC lists. Relationship sai (e.g., link malware với wrong threat actor, dùng `uses` thay vì `attributed-to`) propagate errors qua downstream graph queries và TIP correlation engines. Weighted ngang OC vì graph đúng nhưng thiếu node cũng nguy hiểm như graph đủ nhưng sai connections.
- **PC = 0.2:** Missing optional properties (e.g., `description`, `aliases`, `first_seen`) giảm informativeness nhưng không break downstream processing. Required properties đã được enforce tại SCR gate → PC ở VER level chỉ capture "nice to have" completeness.

**Empirical validation:** Xem Ablation A8 (Section 9) — test rank-order stability dưới nhiều weight configurations.

**Ngoài composite score, report riêng OC, RA, PC** trong results tables để readers có thể apply trọng số riêng.

#### Level 3: Operational Safety Score (OSS)

Đánh giá rủi ro vận hành của artifacts đúng cú pháp:

**T-YARA OSS dimensions:**
- Overly broad: Rule match >10% benign files → penalty
- Missing meta: Thiếu description/author/date → minor penalty
- Performance risk: Regex quá phức tạp hoặc deep recursion → penalty

**T-SIGMA OSS dimensions:**
- False positive risk: Detection logic quá rộng (e.g., chỉ match process name mà không có filter)
- Missing filter: Không có exclude/filter cho known-good processes → penalty
- Log source mismatch: Rule target log source không tồn tại → penalty

**T-STIX OSS dimensions:**
- Dangling references: SRO reference SDO không tồn tại trong bundle → penalty
- Temporal inconsistency: created > modified timestamps → penalty
- Missing required context: Campaign without intrusion-set → minor penalty

**Công thức:** OSS = 1 - (weighted_penalties / max_penalty)

### 4.3 Aggregate Metrics

**Overall Score per task:**
```
TaskScore = (1 - RR) × PR × SCR × VER × OSS
```
trong đó RR = Refusal Rate (Pre-Gate metric).

**CyberOutputBench Score (tổng hợp):**
```
COB_Score = (TaskScore_YARA + TaskScore_SIGMA + TaskScore_STIX) / 3
```

**Breakdown reporting:** Báo cáo riêng cho mỗi difficulty level (Easy/Medium/Hard) và mỗi gate.

---

## 5. Models Under Evaluation

### 5.1 Model Selection (11 models)

**Lưu ý về Model Vintage:** Benchmark đánh giá models available tính đến tháng 4/2026. Contribution chính là **TASK + METRICS** (model-independent), không phải leaderboard snapshot. Tương tự cách Spider (text-to-SQL) được publish với GPT-3 era models nhưng vẫn là standard benchmark nhiều năm sau. Released code có `models/` config directory — thêm model mới chỉ cần 1 file YAML config.

| Nhóm | Model | Params | Exact Version ID | Lý do chọn |
|------|-------|--------|-----------------|------------|
| **Commercial frontier** | GPT-4o | — | `gpt-4o-2024-11-20` (pin tại thời điểm chạy) | Baseline mạnh nhất trên CyberMetric/CTIBench |
| | Claude 3.7 Sonnet | — | `claude-3-7-sonnet-20250219` | Top agentic security (Cybench, SEC-bench) |
| | Gemini 2.0 Flash | — | Pin tại thời điểm chạy | Google SecOps integration |
| **Open-source general** | Llama 3.1 70B Instruct | 70B | HF revision hash | Base cho Foundation-Sec-8B, controlled comparison |
| | Qwen 2.5 72B Instruct | 72B | HF revision hash | Base cho AISOC platform (ShieldNet) |
| | DeepSeek-V3 | 671B MoE | **Qua API** ($0.14/M input, $0.28/M output) | Strong code generation; API rẻ 10x so với self-host |
| **Domain-specific** | Foundation-Sec-8B (Cisco) | 8B | `fdtn-ai/Foundation-Sec-8B-Instruct` | SOTA open-weight security model, Llama 3.1 base |
| | CyberPal 2.0 (8B)* | 8B | Verify HF availability | Security SLM, expert CoT (AAAI 2025) |
| | WhiteRabbitNeo 33B | 33B | `WhiteRabbitNeo-33B-v1.5` | Offensive/defensive security |
| **Code-specialized** | DeepSeek Coder 33B | 33B | `deepseek-coder-33b-instruct` | Strong formal language generation |
| **Ours** | **CyberOutputBench-LM** | 8B | Release cùng benchmark | Llama 3.1 8B + security CPT + artifact SFT (xem Section 5.4) |

*\*CyberPal 2.0: AAAI 2025 paper nhưng weights có thể chưa public. **Backup:** Foundation-Sec-8B-Reasoning (`fdtn-ai/Foundation-Sec-8B-Reasoning`), publicly available, thêm chiều reasoning vào evaluation.*

**Late-breaking model provision:** Nếu model lớn mới ra trước submission (e.g., GPT-5, Claude 4), chạy ZS+S condition only (600 calls, ~$15-50, 1 ngày effort) và thêm vào bảng kết quả.

### 5.2 Inference Configuration

**Hybrid approach:** Pass@1 (primary, deterministic) + Pass@3 (secondary, stochastic sampling trên subset).

| Parameter | Pass@1 (Primary) | Pass@3 (Secondary) |
|-----------|------------------|-------------------|
| Temperature | 0.0 | 0.7 |
| Top-p | 1.0 | 0.95 |
| Max tokens | 2048 (YARA/Sigma), 4096 (STIX) | Giống Pass@1 |
| Repetitions | 1 per instance | 3 per instance |
| Models | Tất cả 11 models | Top 4 (3 commercial + best open-source) |
| Conditions | ZS, ZS+S (all); FS, CoT (top 5 by ZS) | ZS+S only |

**Rationale:** Temperature 0.0 cho output gần deterministic → lặp nhiều lần vô nghĩa. Pass@3 với temp=0.7 trên subset đo ceiling của stochastic sampling. Gap giữa Pass@1 và Pass@3 là finding bổ sung.

**Revised call budget:**
| Condition | Calculation | Calls |
|-----------|------------|-------|
| Pass@1 core (ZS, ZS+S) | 11 models × 600 × 2 | 13,200 |
| Pass@1 ablation (FS, CoT) | 5 models × 600 × 2 | 6,000 |
| Pass@3 subset | 4 models × 600 × 1 × 3 | 7,200 |
| **Grand total** | | **~26,400** (giảm từ 54,000) |

### 5.3 Non-LLM Baselines

Ba baselines để quantify giá trị LLMs thêm vào so với methods đơn giản hơn:

**Baseline 1: Template-Fill (Rule-based)**
- 5 templates per task covering common patterns
- Rule-based system extract keywords từ NL description → chọn template → fill values
- Expected: PR/SCR cao (templates syntactically valid by construction), VER thấp
- Trả lời: "Bao nhiêu có thể giải bằng pattern matching mà không cần understanding?"

**Baseline 2: Retrieval-Augmented (IR-based)**
- BM25 hoặc sentence-transformer retrieve artifact giống nhất từ reference corpus (KHÔNG phải test set)
- Return as-is hoặc minimal string substitution
- Expected: VER trung bình trên Easy, thấp trên Hard
- Trả lời: "Task này chỉ là memorization known rules?"

**Baseline 3: Random Selection**
- Random chọn artifact cùng loại từ reference corpus
- Establishes absolute floor, sanity-check metrics

**Implementation cost:** ~3 ngày engineering (tuần 1-2).

### 5.4 CyberOutputBench-LM: Domain-Specific Model Training

**Mục tiêu:** Trả lời trực tiếp RQ4 bằng controlled experiment — cùng base model (Llama 3.1 8B), training khác nhau → artifact generation quality khác bao nhiêu?

**Stage 1 — Continued Pretraining (CPT)** trên security formal language corpus:
| Data Source | Content | Est. Tokens |
|-------------|---------|-------------|
| YARA language spec + documentation | Syntax, modules, conditions | ~500K |
| SigmaHQ rule corpus (minus test set) + Sigma spec | YAML structure, detection logic | ~5M |
| STIX 2.1 spec + MITRE ATT&CK full STIX data | JSON schema, SDO/SRO structure | ~10M |
| CTI reports (MITRE TRAM, public APT reports) | Threat descriptions, IOCs | ~20M |
| Security docs (OWASP, NIST, CWE descriptions) | Domain knowledge | ~15M |
| **Total** | | **~50M tokens** |

CPT trên 50M tokens với 8B model: **~8-12 giờ trên 4×A100**.

**Stage 2 — Supervised Fine-Tuning (SFT)** trên (NL → artifact) pairs:
| Task | Training pairs | Source |
|------|---------------|--------|
| YARA | ~400 pairs | Reverse-engineered từ YARA Forge (LOẠI TRỪ 200 test rules) |
| Sigma | ~1,500 pairs | Reverse-engineered từ SigmaHQ (LOẠI TRỪ 200 test rules) |
| STIX | ~500 pairs | Generated từ MITRE ATT&CK (LOẠI TRỪ 200 test bundles) |
| **Total** | **~2,400 pairs** | |

SFT với LoRA (rank=64): **~2-4 giờ trên 2×A100**.

**Data Leakage Prevention:** Xem Section 3.1.1 về train/test split. Hash-based dedup, report chính xác split trong paper.

**Controlled comparison matrix:**
| Model | Base | Security CPT | Artifact SFT | → Isolate effect |
|-------|------|-------------|-------------|------------------|
| Llama 3.1 8B Instruct | Llama 3.1 | ✗ | ✗ | Pure general baseline |
| Foundation-Sec-8B | Llama 3.1 | ✓ (Cisco corpus) | ✗ | General security CPT |
| **CyberOutputBench-LM** | Llama 3.1 | ✓ (artifact-focused) | ✓ | Artifact-specific training |

→ Quantify: (a) general security CPT cải thiện bao nhiêu, (b) artifact SFT thêm bao nhiêu nữa.

---

## 6. Prompting Strategies

### 6.1 Four prompting conditions (ablation)

**Condition A: Zero-shot (ZS)**
```
Generate a {YARA rule / Sigma rule / STIX 2.1 bundle} for the following:
{NL description}
Output only the {rule/bundle}, no explanations.
```

**Condition B: Zero-shot with Schema (ZS+S)**
```
You are a cybersecurity expert. Generate a {artifact_type}.

Schema reference:
{Condensed schema/specification for the artifact type}

Task:
{NL description}

Output only the valid {artifact}, no explanations.
```

Schema references:
- YARA: Condensed syntax guide (keywords, modules, conditions)
- Sigma: YAML structure template with required/optional fields
- STIX: SDO/SRO type list with required properties

**Condition C: Few-shot (FS)**
```
Here are examples of converting threat descriptions to {artifact_type}:

Example 1:
Input: {example NL}
Output: {example artifact}

Example 2:
Input: {example NL}
Output: {example artifact}

Now generate for:
Input: {NL description}
Output:
```

Few-shot examples: 2 examples per task, stratified by difficulty (1 easy + 1 medium). Examples held out from evaluation set.

**Condition D: Chain-of-Thought (CoT)**
```
You are a cybersecurity expert. Generate a {artifact_type}.

Think step by step:
1. Identify the key indicators/behaviors from the description
2. Map them to the appropriate {YARA strings and conditions / 
   Sigma detection fields / STIX objects and relationships}
3. Consider edge cases and potential false positives
4. Write the complete {artifact}

Task: {NL description}
```

### 6.2 Prompting Ablation Design

| Condition | Schema | Examples | CoT | Models tested |
|-----------|--------|----------|-----|---------------|
| ZS | ✗ | ✗ | ✗ | All 11 |
| ZS+S | ✓ | ✗ | ✗ | All 11 |
| FS | ✗ | ✓ | ✗ | Top 5 (by ZS performance) |
| CoT | ✗ | ✗ | ✓ | Top 5 (by ZS performance) |

**Total inference calls (revised — xem Section 5.2 cho rationale):**
- Pass@1 core (ZS + ZS+S): 11 models × 600 instances × 2 conditions × 1 rep = 13,200
- Pass@1 ablation (FS + CoT): 5 models × 600 instances × 2 conditions × 1 rep = 6,000
- Pass@3 subset: 4 models × 600 instances × 1 condition × 3 reps = 7,200
- **Grand total: ~26,400 inference calls** (giảm 51% từ 54,000 nhờ hybrid temperature approach)

*Lưu ý: 11 models = 10 external + CyberOutputBench-LM. Baselines (Template-Fill, Retrieval, Random) không cần API calls.*

---

## 7. Error Taxonomy

### 7.1 Syntactic Error Categories

| ID | Category | YARA Example | Sigma Example | STIX Example |
|----|----------|-------------|---------------|--------------|
| S1 | Structure error | Missing `condition:` block | Missing `detection:` key | Missing `type` field |
| S2 | Type mismatch | String literal where hex expected | Int where string expected | Wrong property type |
| S3 | Reference error | Undefined string variable in condition | Non-existent field in selection | Dangling `id` reference |
| S4 | Syntax violation | Unclosed brackets/braces | Invalid YAML indentation | Invalid JSON |
| S5 | Spec violation | Invalid module import | Unknown logsource category | Non-standard SDO type |

### 7.2 Semantic Error Categories

| ID | Category | Description | Severity |
|----|----------|-------------|----------|
| E1 | Missing indicator | Key threat indicator from description not captured | High |
| E2 | Wrong logic | AND/OR logic inverted, wrong comparison operator | High |
| E3 | Incomplete coverage | Partial capture of description requirements | Medium |
| E4 | Over-specification | Adds constraints not in the description | Low |
| E5 | Wrong abstraction level | Too specific (single hash) or too generic (any PE file) | Medium |
| E6 | Hallucinated content | Invents indicators/relationships not in input | High |
| E7 | Wrong taxonomy mapping | Maps to wrong ATT&CK technique or CWE | Medium |

### 7.3 Error Analysis Protocol

Cho mỗi model, sample 30 erroneous outputs (10 per task), có 2 annotators:
1. Classify errors theo taxonomy trên
2. Rate severity (1–3)
3. Tính inter-annotator agreement (Cohen's κ)

---

## 8. Human Evaluation Protocol

### 8.1 Expert Evaluation Subset

- **Sample size:** 90 instances (30 per task, stratified by difficulty)
- **Models evaluated by humans:** Top 3 performing models + 1 domain-specific model
- **Evaluators:** 2 security analysts với ≥3 năm kinh nghiệm SOC/CTI

### 8.2 Human Evaluation Dimensions

| Dimension | Scale | Description |
|-----------|-------|-------------|
| Functional correctness | 1–5 | Would this artifact work as intended in production? |
| Completeness | 1–5 | Does it capture all requirements from the description? |
| Operational readiness | 1–5 | Could a SOC analyst deploy this without modification? |
| False positive risk | 1–5 | How likely is this to generate excessive false positives? |

### 8.3 Human–Automatic Correlation

Tính Spearman ρ giữa human scores và automatic metrics (VER, OSS) để validate automatic evaluation pipeline.

---

## 9. Ablation Studies

### 9.1 Planned Ablations

| Ablation | Biến thay đổi | Hypothesis |
|----------|---------------|-----------|
| A1: Schema impact | ZS vs ZS+S | Schema context cải thiện SCR đáng kể (>15%) |
| A2: Few-shot impact | ZS vs FS | Examples cải thiện cả SCR và VER |
| A3: CoT impact | ZS vs CoT | CoT cải thiện VER nhưng có thể giảm PR (verbose output) |
| A4: Model size | 8B vs 33B vs 70B (cùng family) | Size scaling trên security formal languages |
| A5: Domain pretraining | Llama 3.1 8B vs Foundation-Sec-8B | Domain pretraining effect on artifact quality |
| A6: Task difficulty | Easy vs Medium vs Hard | Performance degradation pattern across tasks |
| A7: Cross-task transfer | Model ranking consistency across 3 tasks | Some models better at specific artifact types |
| A8: STIX VER weight sensitivity | VER_STIX dưới 4 weight configs | Model rankings ổn định (tau > 0.8) → weights robust |
| A9: Domain pretraining depth | Llama 3.1 8B vs Foundation-Sec-8B vs CyberOutputBench-LM | Artifact-specific SFT thêm bao nhiêu so với general security CPT |

**A8 Weight Configurations:**
| Config | OC | RA | PC |
|--------|-----|-----|-----|
| Equal | 1/3 | 1/3 | 1/3 |
| OC-heavy | 0.6 | 0.3 | 0.1 |
| RA-heavy | 0.3 | 0.6 | 0.1 |
| Proposed | 0.4 | 0.4 | 0.2 |

Compute Kendall's tau giữa model rankings dưới mỗi config. Nếu tau > 0.8 → rankings weight-robust (strongest reviewer defense). Computationally free — chỉ reweight already-computed scores.

### 9.2 Statistical Testing

- Paired bootstrap test cho metric comparisons (p < 0.05)
- McNemar's test cho binary outcomes (pass/fail)
- Effect size reporting (Cohen's d) cho all comparisons

---

## 10. Automated Evaluation Infrastructure

### 10.1 Validation Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│ LLM Output  │───>│ Refusal      │───>│ Parser       │───>│ Validator    │───>│ Executor     │
│ (raw text)  │    │ Detector     │    │ (3-stage     │    │ (syntax      │    │ (semantic    │
│             │    │              │    │  extraction) │    │  check)      │    │  evaluation) │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
       │                  │                  │                  │                   │
       ▼                  ▼                  ▼                  ▼                   ▼
   Raw output          RR metric         PR metric         SCR metric          VER metric
```

#### Parser: Three-Stage Extraction Pipeline

LLMs thường thêm explanations dù prompt nói "no explanations". Parser xử lý bằng 3 bước fallback:

**Stage 1 — Fenced Code Block Extraction:**
- Pattern: `` ```(yara|yaml|json|sigma|stix)?\n(.*?)\n``` ``
- Nếu đúng 1 code block → dùng nội dung block đó
- Nếu nhiều blocks → dùng block dài nhất hoặc block có language tag match expected type

**Stage 2 — Structure-Aware Regex Extraction:**
- **YARA:** Match từ `rule\s+\w+` đến closing `}` tương ứng (brace-depth counter, KHÔNG dùng single regex vì nested braces)
- **Sigma:** Tìm dòng đầu tiên bắt đầu bằng `title:`, lấy YAML block cho đến khi gặp non-YAML content. Hoặc thử `yaml.safe_load()` trên toàn output rồi check `detection` key.
- **STIX:** Tìm JSON object ngoài cùng chứa `"type": "bundle"`. Thử `json.loads()` trên toàn output trước. Nếu fail, tìm `{` đầu tiên và scan matching `}` bằng brace counter.

**Stage 3 — Aggressive Cleanup Fallback:**
- Strip common preambles: dòng bắt đầu bằng "Here is", "Sure,", "Below is", "```"
- Strip trailing explanations: mọi thứ sau artifact's closing delimiter
- Cho STIX: thử `json.loads()` sau khi strip leading/trailing non-JSON characters
- Nếu tất cả fail → PR = 0, log raw output cho manual inspection

**Logging & Transparency:**
- Log stage nào succeeded cho mỗi output
- Report distribution (e.g., "82% code block, 15% regex, 2% cleanup, 1% unparseable")
- Distribution này bản thân là finding: đo mức độ models tuân thủ formatting instructions
- **Extraction pipeline bias:** Report extraction success rates per model để detect systematic bias (model dùng code blocks vs không)

**Validation của extractor:**
- Trước khi chạy trên ~26K outputs, validate trên dev set ~100 hand-checked outputs từ pilot run (tuần 2)
- Report extractor precision/recall trong appendix

### 10.2 Tool Stack

| Component | Tool | Purpose |
|-----------|------|---------|
| YARA compiler | `yara-python` 4.x | Compile + rule validation |
| YARA scanner | `yara` CLI | Scan synthetic/malware/benign samples |
| YARA synthetic PE generator | `lief` Python library | Tạo minimal PE files thỏa mãn rule conditions (VER Tier 2) |
| Sigma validator | `sigma-cli` / `pySigma` | Schema validation |
| Sigma converter | `pySigma` Splunk backend (primary) + ES|QL (secondary) | Convert to SPL/ES|QL for EXM. 85-90% conversion success on Core rules |
| STIX validator | `stix2-validator` | STIX 2.1 schema validation |
| STIX comparator | Custom (based on `stix2` library) | Object/relationship comparison (OC, RA, PC) |
| Test malware corpus | MalwareBazaar samples (~50 rules, Tier 3 spot-check) | YARA real malware validation |
| Test benign corpus | Windows system DLLs + Debian binaries | False positive testing (YARA VER Tier 2 + Tier 3) |
| Test log dataset | Sigma test logs + synthetic | Sigma execution testing |
| Model training | Transformers + PEFT (LoRA) | CyberOutputBench-LM CPT + SFT |
| Retrieval baseline | `sentence-transformers` + BM25 | Baseline 2: IR-based retrieval |

### 10.3 Reproducibility

- Tất cả evaluation scripts public trên GitHub
- Docker container với pre-installed tools
- Fixed random seeds cho sampling
- API call logs với timestamps

---

## 11. Expected Contributions

1. **CyberOutputBench dataset:** 600 curated instances across 3 security artifact types (YARA, Sigma, STIX 2.1), với gold-standard outputs, NL descriptions, và complexity annotations

2. **Gating evaluation framework:** Hierarchical metric system (RR → PR → SCR → VER → OSS) specific to executable security artifact generation, bao gồm novel synthetic sample testing methodology cho YARA VER

3. **Comprehensive evaluation:** 11 LLMs (+ 3 baselines) × 4 prompting conditions, revealing which models and strategies work best for each artifact type

4. **Error taxonomy:** First systematic categorization of syntactic and semantic errors in LLM-generated security artifacts

5. **CyberOutputBench-LM:** Domain-specific 8B model (Llama 3.1 + security CPT + artifact SFT) với controlled comparison isolating effects of general security pretraining vs artifact-specific fine-tuning

6. **Practical findings:** Actionable insights for SOC teams (which model for which task, minimum prompting requirements, safety-utility tradeoff via Refusal Rate, operational safety guardrails)

---

## 12. Timeline (8 Weeks, 4 Parallel Tracks)

| Tuần | Expert 1 | Expert 2 | Engineering | Model Training |
|------|----------|----------|-------------|----------------|
| 1 | Phase 1: YARA reverse-eng (100 inst) từ YARA Forge Core Set | Phase 1: Sigma reverse-eng (100 inst) từ SigmaHQ Core | Build Parser pipeline (3-stage extraction), setup validation toolchain | Prepare CPT corpus (~50M tokens: specs, docs, rules từ training pool) |
| 2 | Phase 1: STIX (100 inst) + begin Phase 2 YARA forward construction | Cross-validate W1 YARA output; Phase 1 STIX cross-check | Synthetic YARA sample generator (`lief`), Sigma test log generator | **Run CPT (~12hrs trên 4×A100)**; prepare SFT pairs (~2,400) |
| 2-3 | — | — | **Pilot run:** 20 instances × 3 models qua full pipeline. Validate extractor, synthetic samples, baselines | **Run SFT (~4hrs trên 2×A100)**; validate trên dev set |
| 3 | Phase 2 forward construction (~100 remaining) + complexity annotation | Cross-validate W2; complexity annotation; IAA trên 50 instances | Run ZS + ZS+S inference (11 models + 3 baselines) trên ~400 ready instances | CyberOutputBench-LM joins evaluation |
| 4 | Finalize dataset (QC, adversarial filtering, đạt 600 instances) | Error taxonomy annotation trên W3 outputs | Run FS + CoT (top 5 models); compute PR, SCR; add ~200 remaining instances | — |
| 5 | Human evaluation (90 inst, top 3 + 1 domain-specific model) | Human evaluation (2nd annotator, same 90 inst) | Compute VER (3-tier YARA, Sigma EXM, STIX weighted), OSS; statistical testing | — |
| 6 | Error analysis deep dive (30 samples × top models) | Error analysis (2nd annotator for IAA) | Ablation computations (A1–A9 including weight sensitivity) | — |
| 7 | Paper: methodology, results, model training section | Paper: related work, error taxonomy sections | Code cleanup, reproducibility packaging (Docker container) | — |
| 8 | Revision, internal review, response to feedback | Figures, tables, appendix | Data/code/model release preparation | — |

**Key design decisions:**
- Dataset construction extends Weeks 1–4 (thay vì dồn tuần 1–2)
- Inference bắt đầu Week 3 với ~400 instances sẵn, thêm ~200 ở Week 4
- Model training chạy song song Weeks 1–3 trên lab cluster (tổng ~16-20 A100-hours)
- Pilot run (Week 2-3) bắt integration bugs sớm

**Fallback plans:**
- Nếu không đủ 600 instances → giảm xuống 450 (150/task), vẫn lớn hơn SecQA (242) và LLMCloudHunter (12)
- Nếu model training delay → chạy inference 10 external models trước, thêm CyberOutputBench-LM ở Week 4
- Nếu human evaluators không available Week 5 → dời sang Week 5-6, paper writing nén lại

---

## 13. Cost Estimation

### 13.1 Inference Costs

| Category | Detail | Estimate |
|----------|--------|----------|
| **Commercial APIs** | | |
| GPT-4o | ~4,200 calls × ~$0.014/call (avg across conditions) | ~$59 |
| Claude 3.7 Sonnet | ~4,200 calls × ~$0.020/call | ~$84 |
| Gemini 2.0 Flash | ~4,200 calls × ~$0.001/call | ~$4 |
| **DeepSeek-V3 (API)** | ~2,400 calls × ~$0.006/call ($0.14/M in, $0.28/M out) | ~$15 |
| **Open-source GPU** | | |
| Llama 3.1 70B, Qwen 2.5 72B | 2×A100, ~8s/call, ~22 GPU-hrs combined | ~$88 |
| 8B models (Foundation-Sec, CyberPal) | 1×A100, ~3s/call, ~4 GPU-hrs combined | ~$16 |
| 33B models (WhiteRabbitNeo, DS Coder) | 1×A100, ~5s/call, ~7 GPU-hrs combined | ~$28 |
| **Inference subtotal** | | **~$294** |

### 13.2 Model Training Costs

| Stage | Hardware | Time | Cost (cloud rate $4/hr×A100) |
|-------|----------|------|-----|
| CPT (50M tokens, 8B model) | 4×A100 | ~12 hrs | ~$192* |
| SFT (2,400 pairs, LoRA rank=64) | 2×A100 | ~4 hrs | ~$32* |
| **Training subtotal** | | | **~$224*** |

*\*Trên lab cluster → actual cost = $0. Cloud equivalent listed cho reproducibility.*

### 13.3 Human Costs

| Item | Detail | Estimate |
|------|--------|----------|
| Expert annotation (dataset) | 2 experts × ~80 hrs × $50/hr | $8,000 |
| Human evaluation | 2 evaluators × ~20 hrs × $50/hr | $2,000 |
| **Human subtotal** | | **~$10,000** |

### 13.4 Total Budget

| Category | Estimate |
|----------|----------|
| Inference (API + GPU) | ~$294 |
| Model training (lab cluster) | $0 (cloud equivalent: ~$224) |
| Human annotation + evaluation | ~$10,000 |
| Infrastructure (Docker, CI, storage) | ~$50 |
| **Grand total** | **~$10,344** |

**Key observations:**
- Compute cost rất thấp (~$294 cho inference, $0 cho training trên lab cluster) → high reproducibility
- Dominant cost là human annotation ($10,000) — standard cho benchmark papers
- DeepSeek-V3 qua API rẻ hơn ~10x so với self-hosting trên 4×A100

---

## 14. Risk Mitigation

| Rủi ro | Xác suất | Impact | Giải pháp |
|--------|----------|--------|-----------|
| Không đủ 600 instances chất lượng | Trung bình | Medium | Giảm xuống 450 (150/task), vẫn lớn hơn LLMCloudHunter (12) 37x |
| YARA data chỉ 40-60% có đủ context | Trung bình | Medium | Dùng YARA Forge Core Set (~80% usable); tăng forward construction |
| CyberPal 2.0 weights không public | Trung bình | Low | Backup: Foundation-Sec-8B-Reasoning (publicly available) |
| API rate limits cho commercial models | Thấp | Low | Stagger calls, batch processing, retry logic |
| Synthetic YARA samples không representative | Thấp | High | Validate bằng Tier 3 real malware spot-check (50 instances) |
| Model training không converge | Thấp | Medium | LoRA SFT trên 2,400 pairs rất stable; fallback = chạy eval không có own model |
| Human evaluators không available | Thấp | Medium | Recruit qua ShieldNet team + security community contacts |
| pySigma conversion fails | Trung bình | Low | Report conversion failure rate riêng; dùng Splunk SPL (85-90% success) |
| Concurrent work published trước | Rất thấp | High | Chưa thấy nhóm nào target cùng hướng; LLMCloudHunter chỉ Sigma+GPT-4o+12 reports |

**Pilot run (Week 2-3):** Chạy 2-3 models trên 20 instances qua full pipeline end-to-end. Bắt integration bugs sớm, validate extraction pipeline, calibrate synthetic samples, test baselines. Nếu pilot phát hiện vấn đề lớn → có 5 tuần để fix trước deadline.

---

## 15. Related Work Positioning

### Differentiation từ existing benchmarks:

| Benchmark | Dataset Size | Executable Eval? | Khác biệt với CyberOutputBench |
|-----------|-------------|------------------|--------------------------------|
| CyberMetric / SecBench | 44,823 MCQs | ✗ | MCQ knowledge only, không đo generation |
| CTIBench | 2,495 MCQs + tasks | ✗ | CTI extraction/classification, không executable output |
| CyberSecEval 1–4 | Multi-suite | ✓ (AutoPatchBench: fuzzing) | Safety/risk focus; CyberSOCEval v4 gần nhất nhưng focus malware analysis QA, không YARA/Sigma/STIX generation |
| AutoPatchBench (CSE v4) | ~136 bugs | ✓ (sanitizer oracles) | Code patching, không security-specific formal languages |
| Cybench | 40 CTF tasks | ✓ (flag-based) | CTF challenge solving, không artifact generation |
| SEC-bench (NeurIPS 2025) | 136 bugs | ✓ (sanitizer + differential testing) | Vulnerability PoC/patching, không detection rule generation |
| **LLMCloudHunter** | **12 reports only** | ✓ (Sigma→SPL conversion) | **Closest competitor** nhưng tiny scale (12 vs 600), chỉ Sigma + GPT-4o, không benchmark mở, không multi-model evaluation |
| SecVulEval | 25,440 functions | ✗ | Code vulnerability detection (23.83% F1), không generation |

### Differentiation từ structured output benchmarks:
| Benchmark | Khác biệt |
|-----------|----------|
| Spider / BIRD (text-to-SQL) | SQL is a general-purpose query language; YARA/Sigma/STIX are domain-specific formal languages with unique semantics |
| HumanEval / MBPP (code gen) | General programming; security artifacts have additional operational safety requirements |
| SLOT / SLOTBENCH | JSON schema conformance; we evaluate both schema AND functional correctness |

### Methodological learnings từ existing work:
- **SEC-bench:** Sanitizer-based oracle approach validates chiến lược synthetic sample testing của chúng tôi (YARA VER Tier 2)
- **CyberSecEval 4:** False Refusal Rate (FRR) concept → chúng tôi thêm Refusal Rate metric
- **Cybench:** Subtask decomposition → chúng tôi report per-difficulty-level results

**CyberOutputBench fills the gap** at the intersection of:
(a) Security-domain evaluation (from CyberMetric/CTIBench family)
(b) Executable structured output evaluation (from text-to-SQL/code-gen family)
(c) Operational safety assessment (from CyberSecEval family)

No existing benchmark combines all three. LLMCloudHunter là closest nhưng nhỏ hơn **50x** (12 vs 600 instances) và chỉ cover 1 artifact type.
