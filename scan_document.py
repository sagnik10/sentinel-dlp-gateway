"""CLI: python scan_document.py document.pdf --output reports/document"""
import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Inspect XLSX, DOCX or PDF locally; write JSON and HTML reports.')
    parser.add_argument('document', type=Path)
    parser.add_argument('--output', type=Path, default=Path('reports/document'))
    args = parser.parse_args()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dlp.settings')
    import django
    django.setup()
    from dlp.documents import MAX_BYTES, inspect_document, write_reports
    if args.document.resolve() in {args.output.with_suffix('.json').resolve(), args.output.with_suffix('.html').resolve()}:
        parser.error('Output must not overwrite the input document')
    try:
        with args.document.open('rb') as stream:
            report = inspect_document(stream.read(MAX_BYTES + 1))
    except OSError:
        parser.error('Cannot read input document')
    write_reports(report, args.output)
    print(f"{report['decision']}: {args.output.with_suffix('.html')}")
    return 0 if report['decision'] == 'ALLOWED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
