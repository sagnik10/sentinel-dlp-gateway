# Data sources and licence record

Checked 2026-09-27. Source terms can change; preserve the downloaded manifest and review the precise revision before redistribution or model deployment. Public accessibility is not a blanket licence. This table is a source inventory, not legal advice.

| Command source | Source / data card and licence reference | Use and restrictions |
|---|---|---|
| `deepset` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0; initial binary injection training. Preserve licence/notice obligations. Official test stays test. |
| `s-labs` | [S-Labs/prompt-injection-dataset](https://huggingface.co/datasets/S-Labs/prompt-injection-dataset) | MIT; additional direct injection training. Preserve notices and official validation/test separation. |
| `injection-attack` | [Injection Attack Detection](https://huggingface.co/datasets/PromptInjectionDataset/Injection-Attack-Detection-Dataset) | Card declares GPL-3.0 and requires contact-sharing acceptance. Anonymous direct CSV may fail. Review copyleft, underlying source rights and access conditions; downloader does not accept terms or supply credentials. |
| `bipia` | [Microsoft BIPIA](https://github.com/microsoft/BIPIA), [licence](https://github.com/microsoft/BIPIA/blob/main/LICENSE) | Evaluation only here. Code MIT; benchmark exceptions include CC BY-SA 4.0 for WikiTableQuestions and Stack Exchange, and MIT invoice data. Preserve attribution/share-alike requirements where applicable. Repository archived September 2026. |
| `mirzaakhi` | [Prompt Injection Detection Dataset](https://github.com/mirzaakhi/prompt-injection-detection-dataset), [licence](https://github.com/mirzaakhi/prompt-injection-detection-dataset/blob/main/LICENSE) | CC BY 4.0; preserve attribution, indicate modifications, and retain its held-out split and unseen attacks. |
| `stef41` | [Prompt Injection Benchmark](https://github.com/stef41/prompt-injection-benchmark) | README declares MIT; all records reserved for evaluation here. Preserve notices. |
| `pii-trace` | [PII-TRACE](https://huggingface.co/datasets/perplexity-ai/PII-TRACE) | MIT, synthetic multi-turn annotated conversations. All reserved for evaluation here; conversation grouping preserved. |
| `nemotron` | [NVIDIA Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) | CC BY 4.0; attribution and indication of modifications required. Synthetic enterprise/finance/health/legal documents, not proof of absence of identifying strings. Official test held out. |
| `kiji` | [Dataiku Kiji](https://huggingface.co/datasets/DataikuNLP/kiji-pii-training-data) | Apache-2.0; multilingual synthetic PII annotations. Official test held out. |
| `pii-bench` | [PII Bench](https://huggingface.co/datasets/Pritesh-2711/pii-bench) | Multiple upstream licences; card requires compliance with constituent datasets. No single blanket licence. Official test and validation are evaluation-only; 10% of official train is used for domain coverage, with 90% held out. |
| `presidio` | [Presidio docs](https://microsoft.github.io/presidio/), [repository](https://github.com/microsoft/presidio) | Detection/anonymization software, not labelled training data. Review repository licence and separately installed NLP model terms. Downloaded code is not executed. |
| `presidio-research` | [Synthetic data generator](https://github.com/microsoft/presidio-research/blob/main/docs/data_generation.md) | Tool/documentation archive only, excluded from dataset conversion. Upstream currently redirects to data-privacy-stack; review current licence/dependencies. Useful for independently generating fabricated client examples. |

The downloader requests public Hugging Face parquet exports (all configurations/splits), the specified Injection Attack Detection CSV, and GitHub source ZIP archives. All downloaded files and manifests are confined to `dlp/data/raw/`. ZIP files are read without extraction and no remote code runs. Tool repositories are archived but never treated as examples. Every successful file prints its source URL, card/licence URL, local path and SHA-256. Each source has `manifest.json` containing checksums, split provenance and completion status. Failed/gated/oversized sources produce a nonzero exit and retain successful files; no model is downloaded. The default per-file limit is 2048 MB; large datasets also require sufficient disk and preparation memory. `--max-file-mb` adjusts the limit. `--chunk-size-mb` sets the streaming chunk size (1–64 MiB); interactive output refreshes with percentage, chunk count, transfer speed and ETA. If a server omits content length, ETA is unknown.

Example public subset verification:

```bash
python manage.py download_dlp_datasets --confirm-download --source deepset --source s-labs
```

Raw/processed datasets and downloaded licence files are intentionally git-ignored. Keep source notices with any permitted redistribution. Generated synthetic examples contain only reserved fake domains, numbered fictional scenarios and placeholder policy requests, never real client records.
