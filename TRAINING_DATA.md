# Local training data preparation

```bash
python -m pip install pyarrow
python manage.py download_dlp_datasets --confirm-download
python manage.py generate_synthetic_dlp_examples --count 5000
python manage.py prepare_dlp_training_data
```

The output is `dlp/data/processed/train.jsonl`, `validation.jsonl`, `test.jsonl` and `preparation_report.json`. No networking occurs in generation or preparation. Supported raw formats are manifest-listed parquet, CSV, JSON/JSONL and corresponding data files inside downloaded ZIPs. Checksums are verified. PyArrow is required only for parquet. Run `python -u manage.py prepare_dlp_training_data --chunk-rows 1000` to see parquet row chunks, throughput and ETA; ZIP/CSV conversion reports at completion.

Each output line contains `text`, one label, `source`, a normalized-text SHA-256, `provenance` (file, source/row split, group ID and upstream record metadata), and `contains_real_secret` (false for our synthetic generator, otherwise unknown/null). These files deliberately contain training text, unlike runtime audit data; restrict filesystem access and never feed production prompt/audit data into this pipeline.

Only these labels are accepted:

```text
allowed
blocked_prompt_injection
blocked_jailbreak
blocked_pii
blocked_credential
blocked_confidential_data
blocked_data_exfiltration
```

Binary labelled injection sources map 0/benign to allowed and 1/injection to blocked_prompt_injection. Named jailbreak/exfiltration labels retain their category. PII span/BIO annotations map positive rows to blocked_pii, empty/O-only rows to allowed; unrecognized integer tag mappings are rejected. PII-TRACE conversations concatenate their turns and preserve annotations/grouping; Kiji uses `privacy_mask`, Nemotron uses Python-literal `spans` (parsed without execution), and PII Bench uses string BIO `labels`. Unrecognized schemas or labels increment `unmapped_rows` and `unmapped_by_source`; they never become assumed-safe training records. Review these counts and source coverage before training; upstream schema drift may require adapter changes. Invalid files cause a nonzero exit with a report.

Normalized exact duplicates merge provenance. Conflicting labels are excluded. Official test files always remain in test even if row metadata claims training. PII Bench's official validation split is used for calibration; a deterministic 10% of its official train split enters training for domain coverage, and the remaining 90% stays in test. Its official test split never enters training. PII-TRACE, BIPIA and stef41 remain test-only. Explicit validation remains out of train. Otherwise SHA-256-based buckets assign 80/10/10 deterministically. Duplicate-linked conversation groups are moved to their strictest holdout transitively, preventing cross-split duplication. Never concatenate official test data into train to compensate for class imbalance.

Synthetic data uses seven transparent template families and numbered fictional scenarios. Scenario grouping keeps related examples together. It is suitable for smoke testing pipeline mechanics, not as evidence of classifier quality; template overlap makes synthetic evaluation optimistic. Add diverse, independently authored fake client examples, version their provenance, and evaluate against untouched benchmark and client-authored challenge sets. Never use real staff, customer, credentials, medical or financial records.

Public injection datasets' benign labels describe their original injection task, not this gateway's full PII/confidentiality policy. A public benign row may still trigger a deterministic corporate rule. The classifier is an additional blocking signal, never authorization to override hard rules. Validate taxonomy and per-category precision/recall on client-approved synthetic cases before enabling it.

BIPIA's archive is not a flat classification dataset. The adapter pairs benchmark contexts with attack payloads in deterministic order, inserts the payload inside a retrieved-document wrapper, and labels the composite as blocked_prompt_injection. Both source files/category and context grouping are retained. This is an adapted indirect-injection evaluation set, not a reproduction of the full upstream benchmark protocol. Every composite stays in test.
