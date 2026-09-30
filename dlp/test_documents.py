import io
import json
from unittest.mock import patch
from zipfile import ZipFile

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings

from .documents import inspect_document
from .utils import analyze_prompt


def package(parts):
    data = io.BytesIO()
    with ZipFile(data, 'w') as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return data.getvalue()


def word(text, extra=None):
    from xml.sax.saxutils import escape
    return package({'word/document.xml': '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>' + escape(text) + '</w:t></w:r></w:p></w:body></w:document>', **(extra or {})})


@override_settings(DLP_ENABLE_LOCAL_CLASSIFIER=False, DLP_ENABLE_PRESIDIO=False, DLP_GUARD_MODELS=[])
class DocumentTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command('seed_dlp_policies', stdout=io.StringIO())

    def test_word_allow_block_privacy(self):
        self.assertEqual(inspect_document(word('Explain rainbows.'))['decision'], 'ALLOWED')
        secret = 'password: SuperPrivate123!'
        report = inspect_document(word(secret))
        self.assertEqual(report['decision'], 'BLOCKED')
        self.assertTrue(report['complete'])
        self.assertNotIn(secret, json.dumps(report))
        self.assertIn('PASSWORD', report['findings'][0]['matched_policy_codes'])

    def test_header_is_inspected(self):
        header = '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>SSN: 123-45-6789</w:t></w:r></w:p></w:hdr>'
        report = inspect_document(word('Public introduction', {'word/header1.xml': header}))
        self.assertEqual(report['decision'], 'BLOCKED')

    def test_incomplete_blocks(self):
        for data in (b'', b'old binary word file', b'%PDF-malformed', word('Safe', {'word/media/image.png': b'image'})):
            with self.subTest(data=data[:10]):
                report = inspect_document(data)
                self.assertEqual(report['decision'], 'BLOCKED')
                self.assertFalse(report['complete'])

    def test_oversize_has_no_misleading_partial_hash(self):
        with patch('dlp.documents.MAX_BYTES', 5):
            report = inspect_document(b'123456')
        self.assertIsNone(report['sha256'])
        self.assertTrue(report['input_over_limit'])

    def test_ambiguous_expected_labels_are_not_guessed(self):
        from .management.commands.evaluate_prompt_workbook import expected_decision
        self.assertEqual(expected_decision('Block / Anonymize'), 'BLOCKED')
        self.assertEqual(expected_decision('Allowed'), 'ALLOWED')
        self.assertIsNone(expected_decision('Block only if a real secret is present'))
        self.assertIsNone(expected_decision('ALLOW/FLAG'))

    def test_blank_pdf_blocks(self):
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        stream = io.BytesIO()
        writer.write(stream)
        self.assertFalse(inspect_document(stream.getvalue())['complete'])

    def test_chunk_suffix_and_cross_paragraph(self):
        report = inspect_document(word('ordinary text ' * 1000 + ' password: Secret123!'))
        self.assertEqual(report['decision'], 'BLOCKED')
        data = package({'word/document.xml': '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>My card number</w:t></w:r></w:p><w:p><w:r><w:t>is 5412345678901234</w:t></w:r></w:p></w:body></w:document>'})
        report = inspect_document(data)
        self.assertTrue(any(f['location'] == 'cross-unit text' and f['decision'] == 'BLOCKED' for f in report['findings']))

    def test_text_pdf(self):
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=200)
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'), NameObject('/Subtype'): NameObject('/Type1'), NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): font})})
        stream = DecodedStreamObject()
        stream.set_data(b'BT /F1 12 Tf 20 100 Td (SSN: 123-45-6789) Tj ET')
        page[NameObject('/Contents')] = stream
        output = io.BytesIO()
        writer.write(output)
        report = inspect_document(output.getvalue())
        self.assertEqual(report['format'], 'pdf')
        self.assertTrue(report['complete'])
        self.assertEqual(report['decision'], 'BLOCKED')

    def test_xlsx_hidden_sheet_and_formula(self):
        # Minimal OOXML parser fixture; formulas must never be executed.
        data = package({
            '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
            'xl/workbook.xml': '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Hidden" sheetId="1" state="hidden" r:id="rId1"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml': '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>SSN: 123-45-6789</t></is></c><c r="B1"><f>1+1</f><v>2</v></c></row></sheetData></worksheet>',
        })
        report = inspect_document(data)
        self.assertEqual(report['format'], 'xlsx')
        self.assertEqual(report['decision'], 'BLOCKED')
        self.assertFalse(report['complete'])
        self.assertTrue(any('formula' in issue for issue in report['issues']))

    def test_staff_upload_downloads_report(self):
        from django.contrib.auth import get_user_model
        user = get_user_model().objects.create_user('reviewer', is_staff=True)
        self.client.force_login(user)
        response = self.client.post('/documents/check/', {'document': SimpleUploadedFile('x.docx', word('Explain rainbows.'))})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['decision'], 'ALLOWED')
        self.assertIn('attachment', response['Content-Disposition'])

    def test_detector_failure_is_not_complete(self):
        with patch('dlp.documents.analyze_prompt', return_value={'decision': 'BLOCKED', 'highest_severity': 'critical', 'matched_policy_codes': [], 'safe_detection_summary': ['Security validation unavailable']}):
            report = inspect_document(word('hello'))
        self.assertFalse(report['complete'])

    def test_upload_requires_staff(self):
        response = self.client.post('/documents/check/', {'document': SimpleUploadedFile('x.docx', word('hello'))})
        self.assertEqual(response.status_code, 403)

    def test_new_rules_and_general_controls(self):
        for text in ('SSN: 123-45-6789', 'US Passport: 987654321', '<img src=x onerror=alert(1)>', 'file.txt; cat /etc/passwd', 'My card number is 5412345678901234', 'Decode hex 70617373776f72643a2053656372657431323321'):
            with self.subTest(text=text):
                self.assertEqual(analyze_prompt(text)['decision'], 'BLOCKED')
        for text in ('Explain SQL injection prevention.', 'What is an SSN?', 'How do passports work?', 'Explain how Base64 works.'):
            with self.subTest(text=text):
                self.assertEqual(analyze_prompt(text)['decision'], 'ALLOWED')

    @override_settings(DLP_GUARD_MODELS=[{'name': 'deepset', 'path': 'missing'}])
    def test_enabled_guard_failure_blocks(self):
        self.assertEqual(analyze_prompt('Explain rainbows.')['decision'], 'BLOCKED')

    @override_settings(DLP_GUARD_MODELS=[{'name': 'deepset', 'path': 'unused'}])
    def test_guard_cannot_reverse_rules(self):
        with patch('dlp.model_registry.guard_blocks', return_value=False) as guard:
            self.assertEqual(analyze_prompt('password: Secret123!')['decision'], 'BLOCKED')
            guard.assert_not_called()

    @override_settings(DLP_GUARD_MODELS=[{'name': 'deepset', 'path': 'unused'}])
    def test_guard_adds_injection_match(self):
        with patch('dlp.model_registry.guard_blocks', return_value=True):
            report = analyze_prompt('An otherwise ordinary sentence.')
        self.assertEqual(report['decision'], 'BLOCKED')
        self.assertIn('INJECTION_INTENT', report['matched_policy_codes'])
