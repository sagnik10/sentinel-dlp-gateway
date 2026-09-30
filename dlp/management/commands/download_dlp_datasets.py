"""Explicit, anonymous public downloads; no dataset scripts or models executed."""
import hashlib
import json
import sys
import time
from pathlib import Path
import requests
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

HF = [('deepset','deepset/prompt-injections'), ('s-labs','S-Labs/prompt-injection-dataset'), ('injection-attack','PromptInjectionDataset/Injection-Attack-Detection-Dataset'), ('pii-trace','perplexity-ai/PII-TRACE'), ('nemotron','nvidia/Nemotron-PII'), ('kiji','DataikuNLP/kiji-pii-training-data'), ('pii-bench','Pritesh-2711/pii-bench')]
GITHUB = [('bipia','microsoft/BIPIA'), ('mirzaakhi','mirzaakhi/prompt-injection-detection-dataset'), ('stef41','stef41/prompt-injection-benchmark'), ('presidio','microsoft/presidio'), ('presidio-research','microsoft/presidio-research')]
SOURCES = {key: {'repo':repo,'kind':'hf','card':f'https://huggingface.co/datasets/{repo}'} for key,repo in HF}
SOURCES.update({key: {'repo':repo,'kind':'github','card':f'https://github.com/{repo}'} for key,repo in GITHUB})

class Command(BaseCommand):
    help = 'Download public datasets and tool source archives under dlp/data/raw only.'
    def add_arguments(self, parser):
        parser.add_argument('--confirm-download', action='store_true')
        parser.add_argument('--source', action='append', choices=sorted(SOURCES))
        parser.add_argument('--max-file-mb', type=int, default=2048)
        parser.add_argument('--chunk-size-mb', type=int, default=4, help='Streaming chunk size in MiB (default: 4).')
    def handle(self, *args, **options):
        if not options['confirm_download']: raise CommandError('Pass --confirm-download after reviewing DATA_SOURCES.md.')
        if options['max_file_mb'] < 1: raise CommandError('max-file-mb must be positive')
        if not 1 <= options['chunk_size_mb'] <= 64: raise CommandError('chunk-size-mb must be 1..64')
        root = settings.BASE_DIR / 'dlp/data/raw'
        root.mkdir(parents=True, exist_ok=True)
        failures = 0
        selected = options['source'] or list(SOURCES)
        for source_index, key in enumerate(selected, 1):
            source = SOURCES[key]
            dest = root / key
            dest.mkdir(exist_ok=True)
            manifest = {'source':key, 'source_url':source['card'], 'data_card_license_url':source['card'], 'files':[], 'status':'pending'}
            self.stdout.write(f"Source: {source['card']}\nData-card/licence: {source['card']}\nDestination: {dest}")
            try:
                if source['kind'] == 'hf':
                    if key == 'injection-attack':
                        files = [('dataset.csv', source['card'] + '/resolve/main/Injection-Attack-Detection-Dataset.csv?download=true', 'unspecified')]
                    else:
                        response = requests.get('https://datasets-server.huggingface.co/parquet', params={'dataset':source['repo']}, timeout=60)
                        response.raise_for_status()
                        files = [(f'{i:05d}.parquet', f['url'], f['split']) for i,f in enumerate(response.json()['parquet_files'])]
                        if not files: raise ValueError('No parquet exports')
                else:
                    files = [('source.zip', f"https://api.github.com/repos/{source['repo']}/zipball", 'test' if key in ('bipia','stef41') else 'unspecified')]
                for file_index, (name, url, split) in enumerate(files, 1):
                    target = dest / name
                    partial = dest / (name + '.part')
                    digest = hashlib.sha256()
                    size = 0
                    chunks = 0
                    started = time.monotonic()
                    last_display = started
                    try:
                        with requests.get(url, stream=True, timeout=(20,120)) as response:
                            response.raise_for_status()
                            total = int(response.headers.get('Content-Length') or 0)
                            if total > options['max_file_mb'] * 1024*1024: raise ValueError('Size limit')
                            with partial.open('wb') as output:
                                for chunk in response.iter_content(options['chunk_size_mb']*1024*1024):
                                    if not chunk: continue
                                    size += len(chunk)
                                    chunks += 1
                                    if size > options['max_file_mb'] * 1024*1024: raise ValueError('Size limit')
                                    output.write(chunk)
                                    digest.update(chunk)
                                    now = time.monotonic()
                                    interval = .2 if sys.stdout.isatty() else 10
                                    if now - last_display >= interval:
                                        elapsed = max(now-started,.001)
                                        speed = size/elapsed
                                        eta = f'{int((total-size)/speed)}s' if total and speed > 0 else 'unknown'
                                        percent = f'{size/total:6.1%}' if total else '   ?  '
                                        filled = min(20, int(20*size/total)) if total else 0
                                        bar = '[' + '#'*filled + '-'*(20-filled) + ']'
                                        total_display = f'{total/1048576:.1f}' if total else '?'
                                        line = (f'[{source_index}/{len(selected)} {key} file {file_index}/{len(files)}] '
                                                f'{bar} {percent} {size/1048576:.1f}/{total_display} MiB '
                                                f'chunk {chunks} (up to {options["chunk_size_mb"]} MiB) '
                                                f'{speed/1048576:.1f} MiB/s ETA {eta}')
                                        if sys.stdout.isatty():
                                            sys.stdout.write('\r'+line.ljust(140))
                                            sys.stdout.flush()
                                        else: self.stdout.write(line)
                                        last_display = now
                        if sys.stdout.isatty(): sys.stdout.write('\r'+' '*140+'\r')
                        partial.replace(target)
                    finally:
                        partial.unlink(missing_ok=True)
                    record = {'path':name,'url':url,'split':split,'sha256':digest.hexdigest(),'bytes':size}
                    manifest['files'].append(record)
                    self.stdout.write(f"URL: {url}\nLocal: {target}\nSHA-256: {digest.hexdigest()}")
                manifest['status'] = 'complete'
            except Exception:
                failures += 1
                manifest['status'] = 'incomplete'
                self.stderr.write(f'{key}: download unavailable, gated, or size-limited. Review source access/licence; no credentials were supplied.')
            (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        if failures: raise CommandError(f'{failures} sources incomplete; inspect manifests. Successful downloads are retained.')
