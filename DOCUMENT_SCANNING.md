# Local document inspection

Install `requirements-documents.txt`, migrate the database and run
`python manage.py seed_dlp_policies`. There are now 58 configurable policies.
The existing `.venv` in this copy references another computer and must be
recreated for normal use. A workspace-local validation runtime is available at
`.runtime/python/python.exe`; substitute that path for `python` below on this machine.

```powershell
python -m pip install -r requirements-documents.txt
python manage.py migrate
python manage.py seed_dlp_policies
python scan_document.py "document.pdf" --output reports/document
python scan_document.py "document.docx" --output reports/word
python scan_document.py "Prompts_DLP.xlsx" --output reports/workbook_document
python manage.py evaluate_prompt_workbook Prompts_DLP.xlsx --rules-only --output reports/prompt_evaluation
python manage.py evaluate_prompt_workbook Prompts_DLP.xlsx --output reports/prompt_evaluation_with_model
```

The scanner detects file content rather than trusting its extension. XLSX,
DOCX and text-based PDF are supported. Convert legacy `.xls` and `.doc` first.
It writes standalone HTML and JSON with document SHA-256, timestamp, overall
decision, extraction status, location, policy codes, severity and safe reasons.
Exit code 0 means ALLOWED; 2 means BLOCKED. Reports omit document text and
matched secret values. File hashes and locations still need appropriate access
controls. Existing reports at the selected output prefix are replaced.

A document is ALLOWED only if all inspected chunks pass and extraction has no
known coverage failures. Empty, unsupported, corrupt, encrypted, over-limit,
image-bearing or embedded-object files fail closed. Formula source is inspected
but formula results are not calculated, so formulas require review. No OCR is
implemented. ALLOWED covers extractable text, not every possible hidden channel.
Limits: 20 MB input, 80 MB expanded Office package, 500 PDF pages, 10,000 text
units and two million extracted characters. Overlapping chunks and a separate
cross-unit pass inspect long documents and content split between adjacent units.

The web home page also provides staff-only document uploads with a downloadable
JSON report. CSRF protection applies. Configure the reverse proxy to allow up
to 21 MB **only** on `/documents/check/`; retain the existing 70 KB limit on
`/check/`. Use a request timeout and concurrency limit for document parsing.
Django may spool larger uploads to its temporary directory and removes them
when the request closes. Document scans do not create prompt-audit database rows;
save the generated report as the scan record. Nothing is forwarded externally.

## Workbook evaluation

Evaluation is separate from document inspection: each prompt cell is evaluated
alone, so a category or expected-label cell cannot make the prompt block.
The evaluator recognizes `Prompt_Text`/`Expected_Action`, `prompt`/`expected_action`
and headerless two-column prompt/decision layouts. It inspects all sheets.
`Block / Anonymize` and `BLOCK/REDACT` map to BLOCKED because this gateway has no
automatic redaction-and-release state. Missing/ambiguous labels are excluded
from accuracy, and conflicting labels and detector failures are reported.
Repeated prompts are scored once per run but retain a result for every row.
Row accuracy therefore weights duplicates; unique-prompt counts are supplied.

The supplied workbook includes contradictory labels and truncated prompts.
It also asks to block some apparently harmless encoded strings and incomplete
fragments. The gateway does not use an exact-prompt lookup table to force these
labels. Review mismatches by their sheet/row locations in the source workbook.
This is an evaluation against a development fixture, not an independent safety
benchmark or a guarantee that all sensitive content will be caught.

## Additional open-source model adapters

Two optional local sequence-classification adapters augment the existing
custom classifier and Presidio/spaCy support:

| Adapter | Model | License | Scope |
| --- | --- | --- | --- |
| `deepset` | [deepset/deberta-v3-base-injection](https://huggingface.co/deepset/deberta-v3-base-injection) | MIT | English/German injection classification |
| `protectai` | [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache-2.0 | English injection classification; upstream archived |

These are optional integrations, not preinstalled new model weights. Install
`requirements-models.txt`, review a model repository revision and download it:

```powershell
python -m pip install -r requirements-models.txt
python manage.py download_guard_model deepset --revision FULL_40_CHARACTER_COMMIT_SHA --output local-model-deepset
```

Set this JSON in `.env`, using your absolute local path:

```dotenv
DLP_GUARD_MODELS='[{"name":"deepset","path":"C:/models/deepset","threshold":0.9}]'
```

Both models may be configured as separate list entries. The 0.9 threshold is
a starting setting, not a calibrated accuracy claim. Evaluate each model on
representative allowed and blocked prompts before enabling it. The download
command fetches reviewed artifacts only when invoked; inference is local-only,
requires safetensors and forbids remote model code. Token windows overlap and
cover the entire input. Any configured guard may add an injection block;
no model can overturn a deterministic block. Loading/scoring failures block.
Neither injection model is a general PII or confidential-business classifier.
Real inference of these two new adapters still requires their downloaded weights.

The existing custom classifier path in this workspace's `.env` was repaired to
point at the existing `local-model-reviewed` directory. Its weights were not
retrained on the supplied workbook. `--rules-only` explicitly disables all
optional models for comparison; normal scanning honors the configured models.
