"""Conservative adapters: unknown labels are rejected, never guessed benign."""
import csv
import ast
import hashlib
import io
import json
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from dlp.utils import LABELS, normalize

EVALUATION_ONLY = {'pii-bench','pii-trace','bipia','stef41'}
PII_SOURCES = {'nemotron','kiji','pii-bench','pii-trace'}

def rows_from_bytes(blob, suffix):
    text = blob.decode('utf-8-sig')
    if suffix == '.csv': yield from csv.DictReader(io.StringIO(text))
    elif suffix == '.jsonl':
        for line in io.StringIO(text, newline='\n'):
            if line.strip(): yield json.loads(line)
    elif suffix == '.json':
        value = json.loads(text)
        if isinstance(value, list): yield from value
        elif isinstance(value, dict):
            for key in ('data','records','examples'):
                if isinstance(value.get(key), list):
                    yield from value[key]
                    break

def adapt(row, source):
    if not isinstance(row, dict): return None
    text = next((row[k] for k in ('text','prompt','content','input','sentence','document','full_text') if isinstance(row.get(k),str) and row[k].strip()), None)
    if text is None and isinstance(row.get('tokens'), list): text = ' '.join(str(t) for t in row['tokens'])
    if text is None and isinstance(row.get('messages'), list):
        text = '\n'.join(str(m.get('content','')) for m in row['messages'] if isinstance(m,dict))
    if text is None and isinstance(row.get('turns'), list):
        text = '\n'.join(str(m.get(role,'')) for m in row['turns'] if isinstance(m,dict) for role in ('user','assistant'))
    if not text: return None
    label = row.get('label', row.get('is_injection', row.get('is_prompt_injection', row.get('attack_type'))))
    if isinstance(label, str) and label in LABELS: return text, label
    if source in PII_SOURCES:
        annotations = next((row[k] for k in ('entities','annotations','spans','privacy_mask','pii_spans','ner_tags','labels','tags') if k in row), None)
        if isinstance(annotations, str):
            if len(annotations) > 100000: return None
            try: annotations = json.loads(annotations)
            except ValueError:
                try: annotations = ast.literal_eval(annotations)
                except (ValueError, SyntaxError, TypeError, RecursionError): return None
        if isinstance(annotations, list):
            if any(isinstance(a, int) for a in annotations): return None # integer tag mapping requires source metadata
            positive = any(a not in ('O','',None) for a in annotations)
            return text, 'blocked_pii' if positive else 'allowed'
        return None
    mapping = {'0':'allowed','false':'allowed','benign':'allowed','safe':'allowed','normal':'allowed','1':'blocked_prompt_injection','true':'blocked_prompt_injection','injection':'blocked_prompt_injection','prompt_injection':'blocked_prompt_injection','malicious':'blocked_prompt_injection','jailbreak':'blocked_jailbreak','data_exfiltration':'blocked_data_exfiltration'}
    value = mapping.get(str(label).strip().lower())
    if value == 'blocked_prompt_injection' and row.get('category') in ('jailbreak','data_exfiltration'):
        value = 'blocked_' + row['category']
    return (text,value) if value else None

def split_for(source, split, digest):
    split = split.casefold()
    if source == 'pii-bench':
        if any(v in split for v in ('valid','dev')): return 'validation'
        # Use a stable fraction of the official train split for domain coverage.
        # Most rows, and every official test row, remain evaluation-only.
        if 'train' in split: return 'train' if int(digest[:8],16) % 10 == 0 else 'test'
        return 'test'
    if source in EVALUATION_ONLY or any(v in split for v in ('test','benchmark','eval')): return 'test'
    if any(v in split for v in ('valid','dev')): return 'validation'
    bucket = int(digest[:8],16) % 100
    return 'train' if bucket < 80 else 'validation' if bucket < 90 else 'test'

class Command(BaseCommand):
    help = 'Convert local downloads to deduplicated JSONL; hold out official tests.'
    def add_arguments(self, parser): parser.add_argument('--chunk-rows', type=int, default=1000, help='Parquet rows per preparation chunk (default: 1000).')
    def handle(self, *args, **options):
        if not 100 <= options['chunk_rows'] <= 100000: raise CommandError('chunk-rows must be 100..100000')
        root = settings.BASE_DIR / 'dlp/data/raw'
        output = settings.BASE_DIR / 'dlp/data/processed'
        records, counts, unmapped_by_source, errors, skipped = {}, Counter(), Counter(), [], []
        def consume(rows, source, original_split, filename):
            for row in rows:
                adapted = adapt(row,source)
                if adapted is None:
                    counts['unmapped_rows'] += 1
                    unmapped_by_source[source] += 1
                    continue
                text, label = adapted
                digest = hashlib.sha256(normalize(text).encode()).hexdigest()
                split = str(row.get('split',original_split))
                group = str(row.get('conversation_id', row.get('group_id', digest)))
                # Do not let row metadata move a file-level official test into training.
                target = split_for(source, original_split, hashlib.sha256(group.encode()).hexdigest())
                row_target = split_for(source, split, hashlib.sha256(group.encode()).hexdigest())
                target = max((target,row_target), key={'train':0,'validation':1,'test':2}.get)
                metadata = {'source':source,'file':filename,'original_split':original_split,'row_split':split,'group_id':group}
                metadata['upstream_source'] = row.get('source')
                metadata['source_record_id'] = row.get('id',row.get('uid'))
                if digest in records:
                    old = records[digest]
                    old['provenance'].append(metadata)
                    old['_split'] = max((old['_split'],target),key={'train':0,'validation':1,'test':2}.get)
                    if old['label'] != label: old['_conflict'] = True
                    counts['duplicates'] += 1
                else:
                    records[digest] = {'text':text,'label':label,'source':source,'provenance':[metadata],'text_sha256':digest,'_split':target,'contains_real_secret':False if source == 'synthetic_client_policy' else None}
        for directory in sorted(root.glob('*')):
            if not directory.is_dir() or directory.name in ('presidio','presidio-research'): continue
            source = directory.name
            manifest_path = directory / 'manifest.json'
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
                files = manifest['files']
                if manifest.get('status') != 'complete': skipped.append(f'{source}: download incomplete or gated')
            elif source == 'synthetic_client_policy': files = [{'path':'examples.jsonl','split':'unspecified'}]
            else:
                errors.append(f'{source}: missing manifest')
                continue
            for entry in files:
                path = (directory / entry['path']).resolve()
                if not path.is_relative_to(directory.resolve()): raise CommandError('Unsafe manifest path')
                split = entry.get('split','unspecified')
                try:
                    if entry.get('sha256') and hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']: raise ValueError('Checksum mismatch')
                    if path.suffix == '.parquet':
                        import pyarrow.parquet as pq
                        parquet = pq.ParquetFile(path)
                        total = parquet.metadata.num_rows
                        seen = 0
                        started = time.monotonic()
                        last_display = started
                        for index,batch in enumerate(parquet.iter_batches(batch_size=options['chunk_rows']),1):
                            consume(batch.to_pylist(), source,split,path.name)
                            seen += batch.num_rows
                            now = time.monotonic()
                            if now-last_display >= (.2 if sys.stdout.isatty() else 10) or seen == total:
                                speed = seen/max(now-started,.001)
                                eta = int((total-seen)/speed) if speed else 0
                                filled = min(20,int(20*seen/total)) if total else 0
                                line = (f'[{source}/{path.name}] ['+'#'*filled+'-'*(20-filled)+'] '
                                        f'{seen}/{total} rows chunk {index} ({options["chunk_rows"]} rows) '
                                        f'{speed:.0f} rows/s ETA {eta}s')
                                if sys.stdout.isatty():
                                    sys.stdout.write('\r'+line.ljust(120)); sys.stdout.flush()
                                else: self.stdout.write(line)
                                last_display = now
                        if sys.stdout.isatty(): sys.stdout.write('\r'+' '*120+'\r')
                    elif path.suffix == '.zip':
                        with zipfile.ZipFile(path) as archive:
                            if source == 'bipia':
                                attacks = []
                                for item in archive.infolist():
                                    if '_attack_' in item.filename and item.filename.endswith('.json'):
                                        payloads = json.loads(archive.read(item))
                                        for category, values in payloads.items():
                                            for value in values:
                                                if isinstance(value,str): attacks.append((value,item.filename,category))
                                contexts = []
                                for item in archive.infolist():
                                    if '/benchmark/' in item.filename and item.filename.endswith('.jsonl'):
                                        for i,row in enumerate(rows_from_bytes(archive.read(item),'.jsonl')):
                                            if isinstance(row.get('context'),str): contexts.append((row['context'],item.filename,i))
                                for i in range(max(len(attacks),len(contexts))):
                                    if not attacks or not contexts: break
                                    attack,attack_file,category = attacks[i % len(attacks)]
                                    context,context_file,index = contexts[i % len(contexts)]
                                    consume([{'text':'Summarize this retrieved document:\n<document>\n'+context+'\n'+attack+'\n</document>', 'label':'blocked_prompt_injection','group_id':context_file+':'+str(index),'source':attack_file+':'+category}],source,'test',context_file)
                                counts['bipia_composed'] += max(len(attacks),len(contexts)) if attacks and contexts else 0
                                continue
                            for item in archive.infolist():
                                suffix = Path(item.filename).suffix
                                if suffix in ('.json','.jsonl','.csv') and item.file_size <= 100*1024*1024:
                                    consume(rows_from_bytes(archive.read(item),suffix), source, split + '/' + item.filename, item.filename)
                    else: consume(rows_from_bytes(path.read_bytes(),path.suffix),source,split,path.name)
                except Exception:
                    errors.append(f'{source}/{path.name}: unreadable or unsupported; verify checksum/schema/dependencies')
        if not records: raise CommandError('No supported records. Download data or generate synthetic examples first; install pyarrow for parquet.')
        # Propagate strictest split through duplicate-linked conversation groups.
        priorities = {'train':0,'validation':1,'test':2}
        changed = True
        while changed:
            changed = False
            groups = {}
            for record in records.values():
                for p in record['provenance']:
                    key = (p['source'],p['group_id'])
                    groups[key] = max(groups.get(key,0),priorities[record['_split']])
            for record in records.values():
                rank = max(groups[(p['source'],p['group_id'])] for p in record['provenance'])
                target = ('train','validation','test')[rank]
                if target != record['_split']: record['_split'] = target; changed = True
        output.mkdir(parents=True,exist_ok=True)
        for split in ('train','validation','test'):
            temporary = output / (split + '.jsonl.tmp')
            with temporary.open('w',encoding='utf-8') as stream:
                for digest, record in sorted(records.items()):
                    if record.get('_conflict'):
                        continue
                    if record['_split'] == split:
                        stream.write(json.dumps({k:v for k,v in record.items() if not k.startswith('_')},ensure_ascii=False)+'\n')
                        counts[split] += 1
            temporary.replace(output / (split + '.jsonl'))
        counts['conflicting_records_excluded'] = sum(bool(r.get('_conflict')) for r in records.values())
        report = {'counts':dict(counts),'unmapped_by_source':dict(unmapped_by_source),'file_errors':errors,'skipped_sources':skipped,'note':'Unknown schemas/labels are excluded; inspect coverage before training.'}
        (output / 'preparation_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        self.stdout.write(json.dumps(report,indent=2))
        if errors: raise CommandError('Preparation incomplete; inspect preparation_report.json.')
