from pathlib import Path
import re
from django.core.management.base import BaseCommand, CommandError
from dlp.model_registry import MODEL_CATALOG


class Command(BaseCommand):
    help = 'Download an explicitly selected open-source guard at an immutable revision.'

    def add_arguments(self, parser):
        parser.add_argument('model', choices=MODEL_CATALOG)
        parser.add_argument('--revision', required=True, help='Reviewed 40-character commit SHA')
        parser.add_argument('--output', type=Path, required=True)

    def handle(self, *args, **options):
        if not re.fullmatch(r'[0-9a-f]{40}', options['revision']):
            raise CommandError('Use a full immutable commit SHA, not main or a tag')
        try:
            from huggingface_hub import snapshot_download
            snapshot_download(repo_id=MODEL_CATALOG[options['model']]['repository'],
                              revision=options['revision'], local_dir=str(options['output'].resolve()),
                              allow_patterns=['*.json', '*.safetensors', '*.model', 'LICENSE*', 'README.md'])
        except Exception:
            raise CommandError('Model download failed; verify revision, disk space and network access') from None
        self.stdout.write('Downloaded local artifacts. Calibrate and evaluate before enabling the guard.')
