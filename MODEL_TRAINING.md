# Optional local Hugging Face classifier

The gateway works without model dependencies. To train, provision a trusted local sequence-classification-compatible base model and tokenizer with safetensors weights, review its licence, then:

```bash
python -m pip install "transformers>=4.46,<5" "torch>=2.6" "accelerate>=1.0" safetensors
python train_dlp_classifier.py --base-model /absolute/path/to/base-model --output /absolute/path/to/local-model --epochs 3
```

Training reads only local `dlp/data/processed/{train,validation,test}.jsonl`. `--data-dir` selects another local directory. All splits must be nonempty and training must cover all seven labels. Duplicate/leaked benchmark data is rejected. Seed 42 controls sampling, data split is already deterministic, validation runs each epoch, and untouched test is sampled once after training. The trainer scans and hashes every local record, then retains a stable hash-selected maximum per label. It balances training to the smallest available class, preventing the PII-heavy sources from overwhelming ordinary allowed prompts. Defaults are 2,000 training, 1,000 validation and 1,000 test examples **per label**, with 256-token truncation; CLI options adjust these caps. The test sample is not the complete official benchmark, and full benchmark scoring should be a separate offline evaluation. A JSON manifest records source checksums, scanned and selected counts, per-class top-label metrics, calibrated false-block rate and blocked recall. CPU training can be slow; no remote tracking is enabled. Longer records need separate evaluation. Output must be empty to avoid overwriting a model. The JSONL scan displays row/chunk progress and ETA; Hugging Face then displays a live batch progress bar with ETA and metrics every 25 steps. Run with `python -u` in an interactive terminal to see updates promptly.

After training, the model's blocking threshold is calibrated on held-out allowed validation examples (`--max-allowed-false-block-rate`, default 0.01). Runtime applies a model block only if its highest blocked-class score exceeds both the allowed score and this threshold. Deterministic rules still block regardless of classifier confidence. Inspect `training_manifest.json` for both allowed false-block rate and blocked recall before setting `DLP_ENABLE_LOCAL_CLASSIFIER=true`; a model with poor recall must remain disabled.

If the validation source mix changes but the training JSONL hash is unchanged, recalibrate an existing local model without retraining its weights:

```bash
python manage.py calibrate_dlp_classifier --model-dir /absolute/path/to/local-model-candidate --output /absolute/path/to/local-model-tuned
```

This reads a bounded, hash-selected validation and test sample, never trains on either, and saves a separate local model directory. Compare both validation and test `allowed_false_block_rate` and `blocked_recall` before enabling it. Recalibration refuses to proceed if training data changed.

For a larger validation sample and optional per-class thresholds, use `python -u manage.py calibrate_dlp_classifier --model-dir ./local-model-reviewed --output ./local-model-candidate --per-class-thresholds --max-validation-per-label 500 --max-validation-allowed 2000 --max-test-per-label 500 --max-test-allowed 1000`. A per-class candidate must still be checked on held-out test data; category thresholds can overfit validation, so keep the prior model active if false blocks or recall deteriorate. To measure the complete policy-plus-model gateway without printing prompts, run `python -u manage.py evaluate_dlp_gateway --model-dir ./local-model-reviewed --max-allowed 300 --max-blocked-per-label 30`. This evaluation reports safe aggregate counts and policy codes only. Dataset labels can differ from client policy, especially when an allowed-labelled row contains a card-like number or finance content; review policy matches before treating every disagreement as a rule error.

Training stops early if the preparation report excludes more than 1% of records and over 1,000 rows as unmapped. Re-run preparation and inspect `unmapped_by_source` after adapter changes. JSONL is read by physical LF-delimited lines, preserving Unicode separators inside prompt text.

Offline is the default (`local_files_only`, offline environment flags, no remote code, safetensors only). A missing local model fails before any model download. To explicitly authorize a base-model download:

```bash
python train_dlp_classifier.py --base-model distilbert/distilbert-base-uncased --output ./local-model --allow-download
```

Only this explicit flag permits Hugging Face model download; model files are saved locally. No dataset download occurs during training.

Enable inference in `.env` only after validating the saved model:

```dotenv
DLP_ENABLE_LOCAL_CLASSIFIER=true
DLP_LOCAL_MODEL_PATH=/absolute/path/to/local-model
```

On Windows use an absolute path such as `C:/Models/dlp`. Restart workers after deploying a model; per-process model objects are cached. Runtime accepts only a local directory and the exact seven label names, disables remote custom code, and loads safetensors. It inspects overlapping text chunks and treats every blocked label as a blocking signal for enabled policies in that category. Disabled categories remain disabled. Critical deterministic matches short-circuit optional inference. Missing dependencies/model, invalid output, or inference errors emit only a fixed safe log code and return BLOCKED; hard rules remain active.

## Optional Presidio

Install the optional Python packages with `.\.venv\Scripts\python.exe -m pip install -r requirements-presidio.txt`. Install a trusted compatible spaCy English model separately under the client's model-download policy. Set `DLP_ENABLE_PRESIDIO=true` and `DLP_SPACY_MODEL` to its installed package or local directory only after that model is available. The gateway verifies local availability before initializing Presidio, so it does not download missing spaCy models. Span detections map to enabled personal-data policies; raw spans never leave the detector. The optional in-memory anonymization helper can mask detected text for local experiments; there is no REDACT outcome and no masked prompt is forwarded. This integration is optional and not installed by the base requirements.

No trained model is bundled. Passing rule/unit tests does not establish classifier accuracy or guarantee comprehensive DLP detection.
