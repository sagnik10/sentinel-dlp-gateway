"""Recalibrate an existing local model using held-out validation data only."""
import hashlib
import json
import shutil
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from dlp.management.commands.train_dlp_classifier import LABELS, iter_jsonl, select_bounded, calibrate_threshold, calibrate_class_thresholds, calibrated_metrics

def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def select_split(path, cap, allowed_cap=None):
    heaps = {label: [] for label in LABELS}
    counts = {label: 0 for label in LABELS}
    for row in iter_jsonl(path):
        label = row.get('label')
        if label not in LABELS or not isinstance(row.get('text'), str): raise CommandError('Invalid processed record')
        if path.stem == 'validation':
            for p in row.get('provenance', []):
                original = p.get('original_split', '').lower()
                if 'test' in original or 'benchmark' in original: raise CommandError('Test provenance in validation')
        digest = hashlib.sha256(' '.join(row['text'].casefold().split()).encode()).hexdigest()
        counts[label] += 1
        select_bounded(heaps[label], int(digest, 16), row, allowed_cap if label == 'allowed' and allowed_cap else cap)
    selected = [entry[1] for label in LABELS for entry in heaps[label]]
    if not selected or not any(row['label'] == 'allowed' for row in selected): raise CommandError('Allowed examples required')
    return selected, counts

class Command(BaseCommand):
    help = 'Calibrate a saved local model with validation; evaluate a bounded held-out test sample.'
    def add_arguments(self, parser):
        parser.add_argument('--model-dir', required=True)
        parser.add_argument('--output', required=True)
        parser.add_argument('--data-dir', default=str(Path(__file__).resolve().parents[2] / 'data/processed'))
        parser.add_argument('--max-validation-per-label', type=int, default=200)
        parser.add_argument('--max-test-per-label', type=int, default=200)
        parser.add_argument('--max-validation-allowed', type=int)
        parser.add_argument('--max-test-allowed', type=int)
        parser.add_argument('--max-allowed-false-block-rate', type=float, default=.01)
        parser.add_argument('--per-class-thresholds', action='store_true')
        parser.add_argument('--batch-size', type=int, default=8)
    def handle(self, *args, **opts):
        source = Path(opts['model_dir']).resolve()
        output = Path(opts['output']).resolve()
        data = Path(opts['data_dir']).resolve()
        if not source.is_dir() or not (source/'training_manifest.json').is_file(): raise CommandError('Local trained model and manifest required')
        if output == source or (output.exists() and any(output.iterdir())): raise CommandError('Output must be a distinct empty directory')
        if any(opts[k] < 1 for k in ('max_validation_per_label','max_test_per_label','batch_size')): raise CommandError('Limits must be positive')
        if any(opts[k] is not None and opts[k] < 1 for k in ('max_validation_allowed','max_test_allowed')): raise CommandError('Allowed limits must be positive')
        if not 0 <= opts['max_allowed_false_block_rate'] <= .1: raise CommandError('Invalid allowed false-block rate')
        manifest = json.loads((source/'training_manifest.json').read_text(encoding='utf-8'))
        if manifest.get('labels') != LABELS: raise CommandError('Model label mapping mismatch')
        paths = {split: data/(split+'.jsonl') for split in ('train','validation','test')}
        if file_sha256(paths['train']) != manifest['source_sha256']['train']: raise CommandError('Training data changed; retrain weights before recalibration')
        validation, validation_counts = select_split(paths['validation'], opts['max_validation_per_label'], opts['max_validation_allowed'])
        test, test_counts = select_split(paths['test'], opts['max_test_per_label'], opts['max_test_allowed'])
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
        tokenizer = AutoTokenizer.from_pretrained(str(source), local_files_only=True, trust_remote_code=False)
        model = AutoModelForSequenceClassification.from_pretrained(str(source), local_files_only=True, trust_remote_code=False, use_safetensors=True)
        classifier = pipeline('text-classification', model=model, tokenizer=tokenizer, device=-1)
        def scores(rows, name):
            values = []
            for start in range(0, len(rows), opts['batch_size']):
                batch = rows[start:start+opts['batch_size']]
                predictions = classifier([r['text'] for r in batch], truncation=True, max_length=manifest['max_length'], top_k=None, batch_size=opts['batch_size'])
                for result in predictions:
                    mapped = {item['label']:item['score'] for item in result}
                    if set(mapped) != set(LABELS): raise CommandError('Classifier labels changed')
                    values.append([mapped[label] for label in LABELS])
                if start % (opts['batch_size']*20) == 0 or start + opts['batch_size'] >= len(rows):
                    self.stdout.write(f'{name}: {min(start+opts["batch_size"],len(rows))}/{len(rows)} examples')
            return values
        validation_scores = scores(validation, 'validation')
        threshold = (calibrate_class_thresholds(validation_scores,[r['label'] for r in validation],opts['max_allowed_false_block_rate'])
                     if opts['per_class_thresholds'] else calibrate_threshold(validation_scores,[r['label'] for r in validation],opts['max_allowed_false_block_rate']))
        validation_metrics = calibrated_metrics(validation_scores,[r['label'] for r in validation],threshold)
        test_scores = scores(test, 'test')
        test_metrics = calibrated_metrics(test_scores,[r['label'] for r in test],threshold)
        output.mkdir(parents=True, exist_ok=True)
        for file in source.iterdir():
            if file.is_file() and file.name != 'training_manifest.json': shutil.copy2(file, output/file.name)
        manifest.update({'calibrated_from': str(source), 'source_sha256': {split:file_sha256(path) for split,path in paths.items()}, 'decision_thresholds':threshold if isinstance(threshold,dict) else None, 'decision_threshold':threshold if isinstance(threshold,float) else manifest['decision_threshold'], 'max_allowed_false_block_rate':opts['max_allowed_false_block_rate'], 'validation_calibrated':validation_metrics, 'metrics':test_metrics, 'calibration_source_counts': {'validation':validation_counts,'test':test_counts}, 'calibration_selected_counts':{'validation':len(validation),'test':len(test)}})
        (output/'training_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
        self.stdout.write(json.dumps({'model':str(output),'threshold':threshold,'validation':validation_metrics,'test':test_metrics},indent=2))
