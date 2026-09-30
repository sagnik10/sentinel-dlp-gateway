"""Evaluate the complete local decision path without printing prompt content."""
import json
import time
from collections import Counter
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from django.test import override_settings
from dlp.management.commands.calibrate_dlp_classifier import file_sha256, select_split
from dlp.management.commands.train_dlp_classifier import LABELS
from dlp.models import DLPPolicy
from dlp.utils import analyze_prompt


class Command(BaseCommand):
    help = 'Evaluate deterministic rules plus a saved classifier on a bounded held-out sample.'

    def add_arguments(self, parser):
        parser.add_argument('--model-dir', required=True)
        parser.add_argument('--data-dir', default=str(Path(__file__).resolve().parents[2] / 'data/processed'))
        parser.add_argument('--max-allowed', type=int, default=1000)
        parser.add_argument('--max-blocked-per-label', type=int, default=200)

    def handle(self, *args, **opts):
        model_dir = Path(opts['model_dir']).resolve()
        data_path = Path(opts['data_dir']).resolve() / 'test.jsonl'
        if not (model_dir / 'training_manifest.json').is_file(): raise CommandError('Saved local model required')
        if min(opts['max_allowed'], opts['max_blocked_per_label']) < 1: raise CommandError('Sample limits must be positive')
        manifest = json.loads((model_dir / 'training_manifest.json').read_text(encoding='utf-8'))
        if file_sha256(data_path) != manifest['source_sha256']['test']: raise CommandError('Test data checksum differs from model manifest')
        if not DLPPolicy.objects.filter(enabled=True).exists(): raise CommandError('Seed enabled policies first')
        rows, _ = select_split(data_path, opts['max_blocked_per_label'], opts['max_allowed'])
        counts = {'allowed': 0, 'blocked': 0, 'deterministic_false_blocks': 0,
                  'model_added_false_blocks': 0, 'deterministic_caught': 0,
                  'model_added_caught': 0}
        by_label = {label: {'total': 0, 'deterministic_caught': 0, 'model_added_caught': 0} for label in LABELS[1:]}
        false_block_codes = Counter()
        false_block_sources = Counter()
        started = time.monotonic()
        for number, row in enumerate(rows, 1):
            truth = row['label']
            with override_settings(DLP_ENABLE_LOCAL_CLASSIFIER=False):
                baseline = analyze_prompt(row['text'])
            if baseline['safe_detection_summary'] == ['Security validation unavailable']:
                raise CommandError('Deterministic detector unavailable')
            if truth == 'allowed': counts['allowed'] += 1
            else:
                counts['blocked'] += 1
                by_label[truth]['total'] += 1
            if baseline['decision'] == 'BLOCKED':
                key = 'deterministic_false_blocks' if truth == 'allowed' else 'deterministic_caught'
                counts[key] += 1
                if truth != 'allowed': by_label[truth]['deterministic_caught'] += 1
                else:
                    false_block_codes.update(baseline['matched_policy_codes'])
                    false_block_sources.update({p['source'] for p in row.get('provenance', [])})
            else:
                with override_settings(DLP_ENABLE_LOCAL_CLASSIFIER=True, DLP_LOCAL_MODEL_PATH=str(model_dir)):
                    combined = analyze_prompt(row['text'])
                if combined['safe_detection_summary'] == ['Security validation unavailable']:
                    raise CommandError('Configured classifier unavailable')
                if combined['decision'] == 'BLOCKED':
                    key = 'model_added_false_blocks' if truth == 'allowed' else 'model_added_caught'
                    counts[key] += 1
                    if truth != 'allowed': by_label[truth]['model_added_caught'] += 1
            if number % 100 == 0 or number == len(rows):
                elapsed = max(time.monotonic() - started, .001)
                eta = int((len(rows)-number) * elapsed / number)
                self.stdout.write(f'evaluated {number}/{len(rows)} prompts; ETA {eta}s')
        result = {
            'sample_counts': counts,
            'deterministic_allowed_false_block_rate': counts['deterministic_false_blocks'] / max(counts['allowed'], 1),
            'combined_allowed_false_block_rate': (counts['deterministic_false_blocks'] + counts['model_added_false_blocks']) / max(counts['allowed'], 1),
            'deterministic_blocked_recall': counts['deterministic_caught'] / max(counts['blocked'], 1),
            'combined_blocked_recall': (counts['deterministic_caught'] + counts['model_added_caught']) / max(counts['blocked'], 1),
            'by_label': by_label,
            'allowed_false_block_policy_codes': dict(false_block_codes),
            'allowed_false_block_sources': dict(false_block_sources),
        }
        self.stdout.write(json.dumps(result, indent=2))
