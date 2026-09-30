import argparse
import hashlib
import heapq
import json
import math
import os
import sys
import time
from pathlib import Path
from django.core.management.base import BaseCommand

LABELS = ['allowed','blocked_credential','blocked_pii','blocked_confidential_data','blocked_prompt_injection','blocked_jailbreak','blocked_data_exfiltration']

def provenance_allowed(split, provenance):
    """Only official train data may move to a stricter holdout split."""
    if split == 'test': return True
    source = provenance.get('source')
    original = str(provenance.get('original_split', '')).lower()
    row_split = str(provenance.get('row_split', original)).lower()
    if any(marker in value for value in (original, row_split) for marker in ('test', 'benchmark', 'eval')):
        return False
    if source in ('pii-trace', 'bipia', 'stef41'):
        return False
    if source == 'pii-bench':
        if split == 'train': return 'train' in original and 'train' in row_split
        return any(marker in original for marker in ('train', 'valid', 'dev'))
    if split == 'train' and any(marker in value for value in (original, row_split) for marker in ('valid', 'dev')):
        return False
    return True

def select_bounded(heap, rank, row, limit):
    """Keep a stable, hash-selected sample without retaining the full benchmark."""
    entry = (-rank, row)
    if len(heap) < limit: heapq.heappush(heap, entry)
    elif rank < -heap[0][0]: heapq.heapreplace(heap, entry)

def calibrate_threshold(probabilities, labels, max_allowed_false_block_rate):
    """Require confidence above the observed allowed-prompt tail."""
    allowed_scores = []
    for scores, label in zip(probabilities, labels):
        if label != 'allowed': continue
        allowed = scores[LABELS.index('allowed')]
        blocked = max(scores[1:])
        if blocked > allowed: allowed_scores.append(blocked)
    allowed_scores.sort(reverse=True)
    budget = math.floor(sum(label == 'allowed' for label in labels) * max_allowed_false_block_rate)
    threshold = allowed_scores[budget] + 1e-6 if len(allowed_scores) > budget else .5
    return min(1.0, max(.5, threshold))

def calibrated_metrics(probabilities, labels, threshold):
    allowed_total = allowed_blocked = blocked_total = blocked_caught = 0
    for scores,label in zip(probabilities,labels):
        allowed = scores[0]
        blocked = max(scores[1:])
        winning_label = LABELS[1 + scores[1:].index(blocked)]
        bar = threshold[winning_label] if isinstance(threshold, dict) else threshold
        prediction_blocked = blocked > allowed and blocked > bar
        if label == 'allowed':
            allowed_total += 1
            allowed_blocked += prediction_blocked
        else:
            blocked_total += 1
            blocked_caught += prediction_blocked
    return {'allowed_false_block_rate':allowed_blocked/max(allowed_total,1), 'blocked_recall':blocked_caught/max(blocked_total,1), 'allowed_count':allowed_total, 'blocked_count':blocked_total}

def calibrate_class_thresholds(probabilities, labels, max_allowed_false_block_rate, floor=.9):
    """Maximize macro blocked recall within a validation-only false-block budget."""
    classes = LABELS[1:]
    budget = math.floor(sum(label == 'allowed' for label in labels) * max_allowed_false_block_rate)
    positives = {label: sum(value == label for value in labels) for label in classes}
    choices = {}
    for blocked_label in classes:
        observations = []
        for scores, truth in zip(probabilities, labels):
            winning_score = max(scores[1:])
            winner = LABELS[1 + scores[1:].index(winning_score)]
            if winner == blocked_label and winning_score > scores[0] and winning_score > floor:
                observations.append((winning_score, truth == blocked_label, truth == 'allowed'))
        observations.sort(reverse=True)
        candidates = {0: (0.0, 1.0)}
        true_positives = false_positives = 0
        for index, (score, is_positive, is_allowed) in enumerate(observations):
            true_positives += is_positive
            false_positives += is_allowed
            if false_positives > budget: break
            if index + 1 < len(observations) and observations[index + 1][0] == score: continue
            bar = math.nextafter(score, -math.inf)
            value = true_positives / max(positives[blocked_label], 1)
            previous = candidates.get(false_positives)
            if previous is None or value > previous[0]: candidates[false_positives] = (value, bar)
        choices[blocked_label] = [(cost, value, bar) for cost, (value, bar) in candidates.items()]
    states = {0: (0.0, {})}
    for blocked_label in classes:
        updated = {}
        for spent, (value, thresholds) in states.items():
            for cost, gain, bar in choices[blocked_label]:
                total = spent + cost
                if total > budget: continue
                candidate = (value + gain, {**thresholds, blocked_label: bar})
                if total not in updated or candidate[0] > updated[total][0]: updated[total] = candidate
        states = updated
    spent, (_, selected) = max(states.items(), key=lambda item: (item[1][0], -item[0]))
    return selected

def iter_jsonl(path, show_progress=False):
    """A JSONL record ends at LF, not at every Unicode line-separator character."""
    total_bytes = path.stat().st_size
    started = last_display = time.monotonic()
    consumed = count = 0
    with path.open('r', encoding='utf-8', newline='') as stream:
        for number, line in enumerate(stream, 1):
            consumed += len(line.encode('utf-8'))
            count += 1
            now = time.monotonic()
            if show_progress and (now-last_display >= (0.2 if sys.stderr.isatty() else 10) or consumed >= total_bytes):
                fraction = min(consumed/max(total_bytes, 1), 1)
                rate = consumed/max(now-started, .001)
                eta = int((total_bytes-consumed)/rate) if rate else 0
                filled = int(20*fraction)
                status = (f'{path.stem}: [' + '#' * filled + '-' * (20-filled) +
                          f'] {count} rows chunk {(count+999)//1000} (1000 rows) ETA {eta}s')
                sys.stderr.write(('\r' if sys.stderr.isatty() else '') + status + ('' if sys.stderr.isatty() else '\n'))
                sys.stderr.flush()
                last_display = now
            if not line.strip(): continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f'Invalid JSONL record in {path.name} at physical line {number}') from None
    if show_progress and sys.stderr.isatty(): sys.stderr.write('\n')

def main(argv=None):
    parser = argparse.ArgumentParser(description='Train using local JSONL; offline unless explicitly authorized.')
    parser.add_argument('--base-model', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--data-dir', default=str(Path(__file__).resolve().parents[2] / 'data/processed'))
    parser.add_argument('--allow-download', action='store_true')
    parser.add_argument('--epochs', type=int, default=3)
    parser.add_argument('--max-train-per-label', type=int, default=2000)
    parser.add_argument('--max-validation-per-label', type=int, default=1000)
    parser.add_argument('--max-test-per-label', type=int, default=1000)
    parser.add_argument('--max-length', type=int, default=256)
    parser.add_argument('--max-allowed-false-block-rate', type=float, default=.01)
    args = parser.parse_args(argv)
    if not args.allow_download:
        os.environ['HF_HUB_OFFLINE'] = '1'
        os.environ['TRANSFORMERS_OFFLINE'] = '1'
        if not Path(args.base_model).is_dir(): parser.error('Offline training requires a local base-model directory.')
    os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
    os.environ['WANDB_DISABLED'] = 'true'
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()): parser.error('Output must be empty; existing models will not be overwritten.')
    if args.epochs < 1: parser.error('epochs must be positive')
    if any(v < 1 for v in (args.max_train_per_label,args.max_validation_per_label,args.max_test_per_label)): parser.error('Per-label limits must be positive.')
    if not 16 <= args.max_length <= 512: parser.error('max-length must be 16..512')
    if not 0 <= args.max_allowed_false_block_rate <= .1: parser.error('max-allowed-false-block-rate must be 0..0.1')
    report_path = Path(args.data_dir) / 'preparation_report.json'
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding='utf-8'))
        counts = report.get('counts', {})
        total = sum(int(counts.get(split, 0)) for split in ('train','validation','test'))
        unmapped = int(counts.get('unmapped_rows', 0))
        if unmapped > 1000 and unmapped > .01 * max(total, 1):
            parser.error('Preparation excluded too many unmapped rows. Re-run prepare_dlp_training_data and inspect unmapped_by_source before training.')
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments, set_seed
    set_seed(42)
    seen, rows, checksums, source_counts = set(), {}, {}, {}
    for split in ('train','validation','test'):
        path = Path(args.data_dir) / (split + '.jsonl')
        digest_file = hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest_file.update(chunk)
        checksums[split] = digest_file.hexdigest()
        limits = {'train':args.max_train_per_label,'validation':args.max_validation_per_label,'test':args.max_test_per_label}
        heaps = {label:[] for label in LABELS}
        counts = {label:0 for label in LABELS}
        for item in iter_jsonl(path, show_progress=True):
            if item.get('label') not in LABELS or not isinstance(item.get('text'),str): parser.error('Invalid training record')
            digest = hashlib.sha256(' '.join(item['text'].casefold().split()).encode()).hexdigest()
            if digest in seen: parser.error('Duplicate or split leakage detected')
            seen.add(digest)
            counts[item['label']] += 1
            if split != 'test':
                for provenance in item.get('provenance',[]):
                    if not provenance_allowed(split, provenance):
                        parser.error('Evaluation data found outside test set')
            select_bounded(heaps[item['label']],int(digest,16),item,limits[split])
        source_counts[split] = counts
        if split == 'train':
            minority = min(len(heaps[label]) for label in LABELS)
            if minority == 0: parser.error('Training split must include all seven labels.')
            rows[split] = [entry[1] for label in LABELS for entry in sorted(heaps[label], reverse=True)[:minority]]
        else:
            rows[split] = [entry[1] for label in LABELS for entry in heaps[label]]
        if not rows[split]: parser.error(f'{split} must not be empty')
        print(f'{split}: scanned {sum(counts.values())} records; selected {len(rows[split])} across labels', flush=True)
    if {r['label'] for r in rows['train']} != set(LABELS): parser.error('Training split must include all seven labels.')
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, local_files_only=not args.allow_download, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, local_files_only=not args.allow_download, trust_remote_code=False, use_safetensors=True, num_labels=len(LABELS), id2label=dict(enumerate(LABELS)), label2id={v:i for i,v in enumerate(LABELS)}, ignore_mismatched_sizes=True)
    class LocalDataset(torch.utils.data.Dataset):
        def __init__(self, records): self.records = records
        def __len__(self): return len(self.records)
        def __getitem__(self, index):
            row = self.records[index]
            encoded = tokenizer(row['text'], truncation=True, padding='max_length', max_length=args.max_length)
            return {**{k:torch.tensor(v) for k,v in encoded.items()}, 'labels':torch.tensor(LABELS.index(row['label']))}
    def metrics(prediction):
        predicted = prediction.predictions.argmax(axis=-1)
        truth = prediction.label_ids
        result = {'accuracy':float((predicted == truth).mean())}
        for i,label in enumerate(LABELS):
            positives = truth == i
            result['recall_' + label] = float(((predicted == i) & positives).sum() / max(1, positives.sum()))
        return result
    training = TrainingArguments(output_dir=str(output), num_train_epochs=args.epochs, per_device_train_batch_size=8, per_device_eval_batch_size=8, eval_strategy='epoch', save_strategy='no', report_to=[], seed=42, data_seed=42, logging_strategy='steps', logging_steps=25, disable_tqdm=False, use_cpu=True)
    trainer = Trainer(model=model,args=training,train_dataset=LocalDataset(rows['train']),eval_dataset=LocalDataset(rows['validation']),compute_metrics=metrics)
    trainer.train()
    validation_predictions = trainer.predict(LocalDataset(rows['validation']))
    validation_probs = torch.softmax(torch.as_tensor(validation_predictions.predictions), dim=-1).tolist()
    threshold = calibrate_threshold(validation_probs,[row['label'] for row in rows['validation']],args.max_allowed_false_block_rate)
    validation_calibrated = calibrated_metrics(validation_probs,[row['label'] for row in rows['validation']],threshold)
    # Held-out test is used once, after training; never for checkpoint selection.
    test_predictions = trainer.predict(LocalDataset(rows['test']), metric_key_prefix='test')
    test_probs = torch.softmax(torch.as_tensor(test_predictions.predictions), dim=-1).tolist()
    evaluation = {**test_predictions.metrics, **calibrated_metrics(test_probs,[row['label'] for row in rows['test']],threshold)}
    trainer.save_model(str(output))
    tokenizer.save_pretrained(str(output))
    (output / 'training_manifest.json').write_text(json.dumps({'seed':42,'source_sha256':checksums,'labels':LABELS,'source_counts':source_counts,'selected_counts':{split:len(value) for split,value in rows.items()},'max_length':args.max_length,'decision_threshold':threshold,'max_allowed_false_block_rate':args.max_allowed_false_block_rate,'validation_calibrated':validation_calibrated,'metrics':evaluation,'base_model':args.base_model,'download_authorized':args.allow_download},indent=2),encoding='utf-8')
    print(f'Local model saved: {output}')

class Command(BaseCommand):
    help = 'Use the root train_dlp_classifier.py CLI for local training.'
    def handle(self, *args, **options): self.stdout.write('Run python train_dlp_classifier.py --help')
