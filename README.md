# Sentinel corporate DLP gateway

One custom Django application, `dlp`, performs local prompt inspection before a guarded integration stub. The only decisions are **ALLOWED** and **BLOCKED**. No external LLM API is implemented. The stub returns `forwarded: false`, so audits truthfully record that no forwarding occurred.

## Setup (Python 3.12+)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; from pathlib import Path; p=Path('.env'); p.write_text(p.read_text().replace('replace-with-a-long-random-secret-before-deployment', secrets.token_urlsafe(64)))"
python manage.py migrate
python manage.py createcachetable
python manage.py seed_dlp_policies
python manage.py createsuperuser
python manage.py collectstatic --noinput
python manage.py runserver --insecure
```

Linux: use `python3 -m venv .venv`, `source .venv/bin/activate`, and `cp .env.example .env`. The remaining Python commands are identical. `--insecure` serves local CSS during development with DEBUG disabled; do not use the development server in production.

If the local prompt page appears as plain HTML, the stylesheet is not being served. Stop the existing `runserver` process and restart it with `python manage.py runserver --insecure 127.0.0.1:8000`, then refresh the browser. With `DEBUG=False`, a plain `python manage.py runserver` returns 404 for `/static/dlp/style.css`. Production deployments must serve collected static files through the client's reverse proxy.

Open `/` for the form; `/check/` accepts CSRF-protected POST form data; `/audit/` requires an authenticated Django staff account; `/health/` returns only `ok`/`unavailable`. Log in through `/admin/`. Staff with policy permissions configure rules there. Seeding creates 58 initial codes and does not overwrite subsequent policy changes. Django's built-in authentication/admin apps are used; `dlp` is the only project application.

## Detection and data handling

Detection starts in `dlp/utils.py`, with additional policies in `dlp/extended_rules.py` and optional model adapters in `dlp/model_registry.py`: Unicode/whitespace normalization, bounded URL/HTML/base64/escaped-Unicode decoding, regex timeouts, Luhn checks, IP validation, entropy, configurable internal domains/keywords, injection patterns, optional local Presidio and Hugging Face classification. Rules are conservative and configurable; contextual identifiers and confidential subject terms can block ordinary discussion. This is not a proof that every allowed prompt is safe. Test client-specific vocabulary, languages, false positives and evasions before deployment.

Any matching enabled policy blocks. Specialized validators are selected by seeded policy codes; administrators can disable a code or extend its keyword/regex lists. Never put actual secrets in policy names, descriptions, codes or examples. Safe responses use fixed category strings, never matching text or administrator descriptions. Empty policy configuration, invalid rules, detector timeout, cache/audit failure, and enabled optional detector failures block safely. Deterministic blocks are final and do not depend on ML.

The local detector also blocks requests to extract, document, copy, or preserve sensitive information from referenced customer, employee, patient, configuration, financial, and infrastructure material even when the prompt contains no literal secret value. It also recognizes common authority and policy-override claims. This intent check is tied to enabled seeded policy codes and does not require the optional classifier. General educational and clearly fictional requests without real source material remain eligible for ALLOWED. Configure `DLP_INTERNAL_KEYWORDS` with distinctive client identifiers such as private project names; generic words such as `confidential` can block harmless discussion.

The prompt endpoint inspects text submitted to `/check/`. Staff can also scan uploaded XLSX, DOCX and PDF files at `/documents/check/`; the local `scan_document.py` script produces HTML and JSON reports. See [DOCUMENT_SCANNING.md](DOCUMENT_SCANNING.md) for supported content, limits, workbook evaluation and additional local model adapters. A named but absent attachment, URL, retrieved page, tool response, or conversation history cannot be examined by this gateway. Any future integration that supplies those materials must pass their actual contents through the same local decision boundary before external forwarding. OWASP's [Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/) guidance supports layered input filtering, restricted data access, and treating external content as untrusted; phrase rules and a local classifier alone cannot guarantee detection of every paraphrase.

Short, general concept questions such as “What is a medical record?” are allowed by the built-in topic rules when they contain no client ownership or substantive content. Actual records, identifiers, requests to reveal information, and administrator-added keywords/regexes remain blocking. This keeps ordinary educational prompts usable without weakening configured client-specific rules.

The prompt exists transiently in request memory only. Audit fields contain its exact UTF-8 SHA-256 hash, optional keyed user-ID hash, decision, severity, policy codes, fixed safe summary, timing, UUID and forwarding status. Submitted forms are not echoed. No raw-prompt storage option exists. Hashes can reveal repeated prompts and permit guessing low-entropy text; protect audit access and backups. Operational rejects (CSRF, invalid/oversized requests, rate limit) are not accepted prompts and do not create prompt audit rows. HTTP 400/403/405/413/429/503 are transport errors, not additional DLP states.

The optional classifier uses balanced, bounded local training samples and a threshold calibrated on held-out allowed examples. Its threshold cannot overturn a deterministic block. Keep it disabled until held-out evaluation shows acceptable ordinary-prompt false blocks and blocked recall; the base configuration leaves it off.

When a reviewed local model is enabled, `/health/` also checks that the configured model can load. Run `python -u manage.py evaluate_dlp_gateway --model-dir /absolute/path/to/local-model --max-allowed 300 --max-blocked-per-label 30` for a local aggregate evaluation of rules plus model; the command never prints prompt content. A model that fails broader evaluation should remain disabled even if a small sample looked good.

## Client server deployment

Set a persistent random `DJANGO_SECRET_KEY`, explicit allowed hosts and `DLP_REQUIRE_HTTPS=true`. Development without a key uses an ephemeral key; this must not be used across workers or server restarts in production. Run a local WSGI server, for example:

```bash
waitress-serve --listen=127.0.0.1:8000 dlp.wsgi:application
```

Terminate TLS at the client's reverse proxy, serve collected `/static/` there, enforce a 70 KB body limit, and restrict the WSGI listener to the proxy. Set the WSGI URL scheme to HTTPS using trusted proxy configuration; never blindly trust client-supplied forwarding headers. Secure redirects require the correct scheme. The application uses `REMOTE_ADDR` for a shared database-cache rate limit, so deployments preserving only the proxy address share a quota. Preserve the client address only through a trusted proxy configuration. Apply proxy connection/body-read timeouts and disable request-body/query capture in proxy, APM, error-reporting and WSGI logs. Do not expose DEBUG, core dumps, or unrestricted admin access. SQLite and its database cache support a modest single-server deployment; monitor contention and apply database file/backup access controls. Rate-limit contention denies conservatively. Cache eviction can reset quotas, so use a dedicated cache and an upstream rate limit for hostile high-cardinality traffic.

To enforce inspection of **every** outbound LLM prompt, client firewall/proxy policy must block direct user egress to LLM providers and make this gateway the only approved integration path. A Django page alone cannot intercept other applications' network traffic. When replacing the stub, keep the server-side decision boundary, persist audit intent before sending, use a fixed approved destination, and define idempotent delivery accounting.

## Datasets and optional training

```bash
python -m pip install pyarrow
python manage.py download_dlp_datasets --confirm-download
python manage.py generate_synthetic_dlp_examples --count 5000
python manage.py prepare_dlp_training_data
python -m pip install "transformers>=4.46,<5" "torch>=2.6" "accelerate>=1.0" safetensors
python train_dlp_classifier.py --base-model /absolute/path/to/base-model --output /absolute/path/to/local-model
```

Downloads can be selected with repeated `--source deepset --source s-labs`; see `--help`. Downloading does not imply permission to deploy derivative data/models. See [DATA_SOURCES.md](DATA_SOURCES.md), [TRAINING_DATA.md](TRAINING_DATA.md), and [MODEL_TRAINING.md](MODEL_TRAINING.md). No model is automatically downloaded. Use `python -u manage.py download_dlp_datasets --confirm-download --chunk-size-mb 4` for live file/chunk counts, MiB, throughput and ETA in a terminal. `python -u manage.py prepare_dlp_training_data --chunk-rows 1000` shows parquet conversion progress by row chunk and ETA. Training displays batch progress and ETA with logging every 25 steps.

## Verification

```bash
python manage.py migrate
python manage.py seed_dlp_policies
python manage.py test
python manage.py check
python manage.py makemigrations --check --dry-run
```

Tests cover the requested blocked categories, obfuscation, audit privacy, forwarding authorization, detector failures, CSRF, request size, rate limits, staff access, seeding, source schemas, and holdout preservation. Optional model inference/training requires separately installed dependencies and local model artifacts; unit tests use controlled substitutes.

## Files

`manage.py`, `train_dlp_classifier.py`, requirements and documentation are root entry points. All application implementation, project settings/WSGI, models, migrations, forms, views, URLs, templates, CSS, tests, management commands and ignored raw/processed data are inside `dlp/`. There are no extra custom applications, containers, workers or frontend frameworks.
