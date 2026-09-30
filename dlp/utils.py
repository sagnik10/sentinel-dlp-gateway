"""Local detection only. Never return matching spans or log input/exceptions."""
import base64
import codecs
import hashlib
import html
import ipaddress
import json
import logging
import math
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit
import regex as re
from django.conf import settings

logger = logging.getLogger('dlp.safe')
SAFE_REASONS = {'credential': 'Credential or secret detected', 'pii': 'Personal data detected', 'confidential_data': 'Internal confidential information detected', 'prompt_injection': 'Prompt injection attempt detected', 'jailbreak': 'Prompt injection attempt detected', 'data_exfiltration': 'Data-exfiltration attempt detected'}
LABELS = ['allowed'] + ['blocked_' + c for c in SAFE_REASONS]

# These 50 codes also select specialized validators below. All are configurable.
RULES = [
 ('PASSWORD','credential',r'\b(?:password|passwd|pwd)\b\s*(?:[:=]|is\b)|\b(?:send|show|reveal|print|share|export|paste|tell|give|fetch|dump)\b.{0,60}\b(?:passwords?|passwd|pwd)\b'),
 ('API_KEY','credential',r'\b(?:api[ _-]?key)\s*(?:[:=]|is\b)|\b(?:send|show|reveal|print|share|export|paste|give)\b.{0,60}\bapi[ _-]?keys?\b|\b(?:sk-(?:proj-)?[a-z0-9_-]{16,}|AIza[a-z0-9_-]{20,}|[rs]k_(?:live|test)_[a-z0-9]{16,}|xox[baprs]-[a-z0-9-]{12,}|SG\.[a-z0-9_-]{16,}\.[a-z0-9_-]{16,})'),
 ('TOKEN','credential',r'\b(?:access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|token)\s*[:=]|\b(?:send|show|reveal|print|share|export|paste|give)\b.{0,60}\b(?:access|refresh|auth|bearer)[ _-]?tokens?\b'),
 ('BEARER','credential',r'\bbearer\s+(?!token\b)[a-z0-9._~-]{8,}'),
 ('JWT','credential',r'\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+'),
 ('AWS_KEY','credential',r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|aws[_ -]secret'),
 ('GITHUB_TOKEN','credential',r'\b(?:gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})'),
 ('PRIVATE_KEY','credential',r'-{2,}\s*BEGIN\s+(?:[A-Z0-9]+\s+)?PRIVATE KEY'),
 ('SSH_KEY','credential',r'\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+[a-z0-9+/=]{20,}'),
 ('CONNECTION_STRING','credential',r'\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://|\b(?:server|data source)\s*=.*(?:user|uid|password|pwd)\s*='),
 ('ENV_CONTENT','credential',r'\b(?:[A-Z][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)|DATABASE_URL)\s*=|\b(?:show|reveal|share|print|send|paste)\b.{0,40}\.env\b|\.env\b.{0,15}\b(?:contents|values)\b'),
 ('CREDIT_CARD','pii',''),
 ('CVV','pii',r'\b(?:cvv|cvc|card verification)\b\s*[:=]?\s*\d{3,4}\b'),
 ('BANK_ACCOUNT','pii',r'\b(?:bank account|account number|iban|routing number)\b\s*(?:is\s*|[:=]\s*)?[a-z0-9 -]{6,}\d{4,}|\b(?:send|show|reveal|share|export|paste|give)\b.{0,60}\b(?:bank accounts?|account numbers?|iban|routing numbers?)\b'),
 ('IFSC','pii',r'\b[A-Z]{4}0[A-Z0-9]{6}\b|\b(?:show|reveal|share|send|print|give)\b.{0,40}\bifsc\b'),
 ('PAN','pii',r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
 ('AADHAAR','pii',r'(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)|\b(?:show|reveal|share|send|print|give)\b.{0,40}\baadhaar\b'),
 ('PASSPORT','pii',r'\b(?:show|reveal|share|send|print|give)\b.{0,40}\bpassport\b|\b[A-Z][0-9]{7}\b'),
 ('DRIVING_LICENCE','pii',r'\b(?:show|reveal|share|send|print|give)\b.{0,40}\b(?:driving licen[cs]e|driver.?s licen[cs]e)\b|\b[A-Z]{2}[ -]?\d{2}[ -]?\d{11}\b'),
 ('EMAIL','pii',r'\b[a-z0-9.!#$%&*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b'),
 ('PHONE','pii',r'(?<!\w)(?:\+91[ .-]?)?[6-9]\d{4}[ .-]?\d{5}(?!\d)|(?<!\w)(?:\+1[ .-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[ .-][2-9]\d{2}[ .-]\d{4}(?!\d)|\b(?:phone|mobile|tel(?:ephone)?|call|contact)\b.{0,30}\b[2-9]\d{9}\b|(?<!\w)\+\d{1,3}[ .-](?:\d[ .-]?){8,12}(?!\d)'),
 ('ADDRESS','pii',r'\b(?:show|reveal|share|send|print|give)\b.{0,40}\b(?:home address|postal address|residential address)\b|\b(?:home|postal|residential) address\s*[:=]\s*[a-z0-9][^\n]{3,}|\b\d{1,5}\s+(?:[a-z]+\s+){1,4}(?:street|road|avenue|lane|drive|st\b|rd\b)'),
 ('DOB','pii',r'\b(?:date of birth|birthdate|dob)\b\s*(?:[:=]|is\b)\s*\d{1,2}[-/]\d{1,2}[-/]\d{4}\b|\b(?:show|reveal|share|send|print|give)\b.{0,40}\b(?:date of birth|birthdate|dob)\b'),
 ('EMPLOYEE_ID','pii',r'\bemployee[ _-]?(?:id|number)\s*[:=]?\s*[a-z]{1,6}[ _-]?\d{3,}\b|\bemp[ _-]?\d{3,}\b|\b(?:show|reveal|share|send|print|give)\b.{0,40}\bemployee[ _-]?(?:id|number)\b'),
 ('CUSTOMER_ID','pii',r'\bcustomer[ _-]?(?:id|number)\s*[:=]?\s*[a-z]{1,6}[ _-]?\d{3,}\b|\bcust[ _-]?\d{3,}\b|\b(?:show|reveal|share|send|print|give)\b.{0,40}\bcustomer[ _-]?(?:id|number)\b'),
 ('HEALTH','confidential_data',r'\b(?:patient (?:record|data|history|details)|medical (?:record|data|report|history)|diagnosis\s*[:=]|health record|prescription\s*[:=]|clinical report)\b'),
 ('PAYROLL','confidential_data',r'\b(?:payroll (?:data|report|records?|file|spreadsheet|details)|salary (?:data|list|records?|details)|payslip|compensation record)\b'),
 ('HR','confidential_data',r'\b(?:human resources (?:records?|data|report)|hr (?:records?|data|report)|performance review|disciplinary (?:record|action))\b'),
 ('LEGAL','confidential_data',r'\b(?:legal (?:memo|report|case|opinion)|(?:our|internal|private|company|client) legal documents?|litigation (?:report|file|details)|privileged (?:document|information|communication)|attorney.client)\b'),
 ('CONTRACT','confidential_data',r'\b(?:contracts? (?:text|terms|details|document|draft|with|for)|nda|non-disclosure agreement)\b'),
 ('TENDER','confidential_data',r'\b(?:tender (?:document|bid|details|submission|pricing)|bid pricing|procurement (?:plan|data|records?))\b'),
 ('FINANCE','confidential_data',r'\b(?:financial (?:report|records?|data|statement|forecast)|finance (?:report|records?|data)|revenue forecast|balance sheet|ledger|invoice)\b'),
 ('CUSTOMER_DATA','confidential_data',r'\b(?:customer (?:information|data|records?|list)|client (?:information|data|records?|list))\b'),
 ('INTERNAL_KEYWORD','confidential_data',''),
 ('INTERNAL_DOMAIN','confidential_data',''),
 ('INTERNAL_REPORT','confidential_data',r'\b(?:internal report|private report|board report|unpublished report)\b'),
 ('IP_ADDRESS','confidential_data',''),
 ('PRIVATE_HOST','confidential_data',r'\b[a-z0-9-]+\.(?:local|internal|intranet|corp)\b|\b(?:hostname|private host)\b'),
 ('SCHEMA','confidential_data',r'\b(?:our|internal|company|private|production)\s+database schema\b|\b(?:create table|alter table|select\s+.+\s+from)\b'),
 ('SOURCE_CODE','confidential_data',r'```|\bdef\s+\w+\s*\(|\b(?:function|class)\s+\w+\s*[({:]|\b(?:our|internal|company|private|production)\s+source code\b'),
 ('INFRASTRUCTURE','confidential_data',r'\b(?:kubeconfig|terraform (?:state|plan|config)|infrastructure (?:diagram|credentials|details|configuration)|kubernetes (?:config|secrets)|network topology|security group)\b'),
 ('VULNERABILITY','confidential_data',r'\bCVE-\d{4}-\d+\b|\b(?:our|internal|company|private|production)\s+(?:vulnerability|exploit|zero.day)\b|\b(?:vulnerability|exploit)\s+(?:details|report|proof.of.concept)\b'),
 ('INCIDENT','confidential_data',r'\b(?:incident report|breach report|forensic report|incident.response (?:log|document|details|report))\b'),
 ('AUTH_BYPASS','jailbreak',r'\b(?:bypass|disable|evade)\b.{0,60}\b(?:authentication|authorization|login|mfa|access control)\b'),
 ('EXFILTRATION','data_exfiltration',r'\b(?:exfiltrat\w*|steal|leak)\b.{0,80}\b(?:our|company|internal|private|customer|secrets?|data|records?|database)\b|\b(?:send|upload|export|transmit)\b.{0,100}\b(?:secrets?|credentials?|database|private|internal|records?)\b'),
 ('IGNORE_INSTRUCTIONS','prompt_injection',r'\b(?:ignore|disregard|forget)\b.{0,50}\b(?:previous|prior|above|all|preceding)\b.{0,35}\b(?:instructions?|rules?|tasks?|orders?|prompts?)\b'),
 ('PROMPT_EXTRACTION','prompt_injection',r'\b(?:show|reveal|print|repeat|output|dump|extract|expose)\b.{0,60}\b(?:your|the|hidden|full|original|initial|secret)\b.{0,30}\b(?:system[ -]?prompt|developer[ -]?(?:message|instructions?)|hidden instructions?|prompts?|instructions?)\b'),
 ('POLICY_OVERRIDE','prompt_injection',r'\b(?:override|bypass|disable|ignore)\b.{0,45}\b(?:policy|policies|safety|guardrails|filters|restrictions)\b|\[/?(?:system|inst)\]|<\|(?:im_start|system|im_end)\|>'),
 ('JAILBREAK','jailbreak',r'\b(?:enable|enter|activate|use|switch to)\b.{0,20}\b(?:developer mode|unrestricted mode)\b|\b(?:jailbreak (?:this|the|your)|do anything now|act as dan|you are dan)\b'),
 ('ENTROPY','credential',''),
]
from .extended_rules import EXTRA_RULES
RULES += EXTRA_RULES
SEEDED_PATTERNS = {code:pattern for code,_,pattern in RULES}
PREVIOUS_SEEDED_PATTERNS = {
    'PHONE': r'(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\d)',
}
CONCEPT_ONLY_CODES = {'HEALTH','PAYROLL','HR','LEGAL','CONTRACT','TENDER','FINANCE','CUSTOMER_DATA','INTERNAL_REPORT','PRIVATE_HOST','INFRASTRUCTURE','VULNERABILITY','INCIDENT'}

def is_general_concept_question(value):
    """Recognize short topic questions without identifiers, content or client ownership."""
    if re.search(r'\b(?:our|my|company|client|this|these|attached|below|following|specific|actual)\b', value):
        return False
    prefix = (r'(?:what (?:is|are)(?: the basics of)?|can you explain|'
              r'tell me about|teach me about|give (?:me )?(?:a )?(?:general )?overview of|'
              r'how (?:do|does)|why (?:do|does)|explain|define|describe)')
    return re.fullmatch(prefix + r'\s+(?:(?:an?|the)\s+)?[a-z][a-z -]{2,100}[?.]?', value) is not None

def normalize(text):
    text = unicodedata.normalize('NFKC', html.unescape(unquote(text)))
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    return re.sub(r'\s+', ' ', text).strip().casefold()

def variants(text):
    values = [normalize(text)]
    # Bounded common transport encodings, never arbitrary execution.
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})', lambda m: chr(int(m[1] or m[2], 16)), text)
    values.append(normalize(decoded))
    for token in re.findall(r'\b(?:[0-9a-fA-F]{2}){8,}\b', text)[:20]:
        try:
            values.append(normalize(bytes.fromhex(token).decode('utf-8')))
        except (ValueError, UnicodeError):
            pass
    if re.search(r'\brot13\b', text, re.I):
        values.append(normalize(codecs.decode(text, 'rot_13')))
    if re.search(r'\breverse\b', text, re.I):
        values.append(normalize(text[::-1]))
    # Reconstruct explicitly separated identifiers without executing content.
    values.append(normalize(re.sub(r'(?<=\b[a-zA-Z0-9])[ ._-]+(?=[a-zA-Z0-9]\b)', '', text)))
    for token in re.findall(r'(?<!\w)[A-Za-z0-9+/]{24,}={0,2}(?!\w)', text)[:20]:
        try:
            values.append(normalize(base64.b64decode(token, validate=True).decode('utf-8')))
        except (ValueError, UnicodeError):
            pass
    return list(dict.fromkeys(values))

def luhn(value):
    digits = [int(c) for c in value if c.isdigit() and c.isascii()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1: return False
    return sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d for i, d in enumerate(reversed(digits))) % 10 == 0

def special_match(code, text):
    if code == 'CREDIT_CARD':
        return any(luhn(m) for m in re.findall(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)', text))
    if code == 'IP_ADDRESS':
        for token in re.findall(r'[0-9a-f:.]+', text):
            try:
                ipaddress.ip_address(token.strip('.'))
                return True
            except ValueError: pass
    if code == 'INTERNAL_KEYWORD': return any(normalize(k) in text for k in settings.DLP_INTERNAL_KEYWORDS)
    if code == 'INTERNAL_DOMAIN':
        if any(normalize(k) in text for k in settings.DLP_INTERNAL_DOMAINS): return True
        for url in re.findall(r'https?://[^\s<>]+', text):
            host = urlsplit(url).hostname or ''
            if host.endswith(('.local','.internal','.corp')): return True
    if code == 'CONNECTION_STRING':
        return any(urlsplit(url).username is not None for url in re.findall(r'https?://[^\s<>]+',text))
    if code == 'ENTROPY':
        for token in re.findall(r'\b[a-zA-Z0-9_+/=-]{24,}\b', text):
            entropy = -sum((n / len(token)) * math.log2(n / len(token)) for n in Counter(token).values())
            if entropy >= 4.1 and any(c.isdigit() for c in token): return True
    return False

def sensitive_intent_codes(text):
    """Match requests to expose referenced sensitive material, even without values."""
    def has(pattern):
        return re.search(pattern, text, re.I, timeout=0.025) is not None

    matched = set()
    if has(r'\b(?:treat|interpret)\b.{0,100}\b(?:instructions?|content)\b.{0,100}\b(?:higher priority|trusted system)\b') or \
       has(r'\b(?:administrator|admin)\b.{0,80}\bauthori[sz]\w*\b.{0,70}\bunrestricted\b') or \
       has(r'\bignore\b.{0,50}\b(?:existing|current)\b.{0,40}\bsecurity restrictions?\b') or \
       has(r'\b(?:pretend|assume)\b.{0,60}\b(?:policy|rules?|restrictions?)\b.{0,40}\b(?:suspended|disabled|inactive)\b') or \
       has(r'\bobey\b.{0,40}\b(?:embedded|hidden|new)\b.{0,30}\bsystem instructions?\b') or \
       has(r'\b(?:suspend|switch off|turn off)\b.{0,40}\b(?:safety checks?|security checks?|polic(?:y|ies)|guardrails?)\b') or \
       has(r'\b(?:safety|security)\s+polic(?:y|ies)\b.{0,30}\b(?:disabled|inactive|suspended)\b'):
        matched.add('POLICY_OVERRIDE')

    action = has(r'\b(?:create|review|extract|prepare|identify|analy[sz]e|summari[sz]e|convert|turn|determine|explain|preserv\w*|provide|disclose|reveal|expose|compile|build|assemble|list|pull|collect|generate|write|draft|make|document|map|retain\w*|copy|tabulate|catalog(?:ue)?|enumerate|surface|output)\b')
    # A requested transformation of referenced material is materially different
    # from a general question about a sensitive topic.
    referenced = has(r'\b(?:this|these|our|provided|following|containing|contained|based on|from this|person.s|attached|supplied|uploaded|shared|enclosed|given|embedded|retrieved|client.s|customer.s|company.s)\b')
    if not action or not referenced:
        return matched

    identity = has(r'\b(?:full names?|legal names?|residential locations?|home (?:addresses|locations?)|birth dates?|dates? of birth|dob|government identification|identit\w*|identifiers?|identifying details|private contacts?|contact details|family information|personal information|private details|phone numbers?|employee numbers?|staff roster|employee director(?:y|ies))\b')
    if identity:
        if has(r'\b(?:employee|staff|worker|personnel)\b'): matched.add('EMPLOYEE_ID')
        if has(r'\b(?:customer|client|crm|person|profile)\b'): matched.add('CUSTOMER_ID')
        if has(r'\b(?:home address|residential location)\b'): matched.add('ADDRESS')
        if has(r'\b(?:birth date|date of birth|dob)\b'): matched.add('DOB')
        if has(r'\bgovernment identification\b'): matched.add('PASSPORT')
        if has(r'\bphone numbers?\b'): matched.add('PHONE')
    if has(r'\b(?:patient|clinical|medical|health)\b') and \
       has(r'\b(?:history|diagnos(?:is|es)|treatment(?: plans?)?|medications?|notes|profile|information|details|identity|charts?|records?)\b'):
        matched.add('HEALTH')

    if has(r'\b(?:authentication information|authenticate against|access to (?:our )?internal (?:services|systems)|access our internal systems|access (?:details|information|data)|production database|credentials?|secrets?|connection (?:configuration|values?|details?|strings?)|log in)\b') and \
       has(r'\b(?:configuration|settings|notes|database|server|access|values|information|deployment|file|manifest|connection|credentials?|secrets?)\b'):
        matched.add('TOKEN')
    if has(r'\b(?:revenue|profit margins?|financial plans?|pricing decisions?|sales forecasts?|unpublished pricing)\b') and \
       has(r'\b(?:unreleased|future|confidential|company|management|internal|board|unpublished|next.quarter)\b'):
        matched.add('FINANCE')
    if has(r'\b(?:internal application architecture|internal system details|internal infrastructure|internal authentication system|internal services|production database|private network|service endpoints?|architecture diagrams?)\b') and \
       has(r'\b(?:notes|document|discussion|deployment|engineering|developer|configuration|provided|settings|architecture|system|diagrams?|network|endpoints?)\b'):
        matched.add('INFRASTRUCTURE')
    if has(r'\b(?:confidential information|internal strategy|non.public business information|unreleased (?:products?|plans?)|upcoming products?|sensitive company information|product roadmap|pricing plans?|board deck|unpublished pricing)\b') and \
       has(r'\b(?:company|management|strategy|business|document|conversation|meeting|notes|competitors|products?|roadmap|pricing|board|deck|sales forecasts?)\b'):
        matched.add('INTERNAL_REPORT')
    if has(r'\b(?:customer|crm|sales profile|customer.support)\b') and \
       has(r'\b(?:purchasing history|preferences|account (?:information|history)|private details|commercially sensitive|confidential information|customer conversation|vendor.facing)\b'):
        matched.add('CUSTOMER_DATA')
    if has(r'\b(?:third.party ai provider|external systems|public logs)\b') and \
       has(r'\b(?:information|data|details|document|message|conversation)\b'):
        matched.add('EXFILTRATION')
    return matched

@lru_cache(maxsize=2)
def load_classifier(path):
    if not Path(path).is_absolute() or not Path(path).is_dir(): raise ValueError('Local model unavailable')
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(path, local_files_only=True, trust_remote_code=False, use_safetensors=True)
    if set(model.config.id2label.values()) != set(LABELS): raise ValueError('Invalid labels')
    manifest = json.loads((Path(path) / 'training_manifest.json').read_text(encoding='utf-8'))
    threshold = manifest.get('decision_thresholds') or manifest.get('decision_threshold')
    if isinstance(threshold, dict):
        if set(threshold) != set(LABELS[1:]) or any(not isinstance(value,(int,float)) or not math.isfinite(value) or not .5 <= value <= 1 for value in threshold.values()):
            raise ValueError('Invalid thresholds')
    elif not isinstance(threshold,(int,float)) or not math.isfinite(threshold) or not .5 <= threshold <= 1:
        raise ValueError('Invalid threshold')
    max_length = manifest['max_length']
    if not isinstance(max_length,int) or not 16 <= max_length <= 512: raise ValueError('Invalid model length')
    return pipeline('text-classification', model=model, tokenizer=tokenizer, device=-1), threshold, max_length

def model_block_label(scores, threshold):
    """The optional model contributes a policy match only above its calibrated bar."""
    values = {item['label']:item['score'] for item in scores}
    if set(values) != set(LABELS): raise ValueError('Invalid classifier output')
    if any(not isinstance(v,(int,float)) or not math.isfinite(v) or not 0 <= v <= 1 for v in values.values()): raise ValueError('Invalid classifier score')
    label = max((label for label in LABELS if label != 'allowed'), key=values.get)
    bar = threshold[label] if isinstance(threshold, dict) else threshold
    return label if values[label] > values['allowed'] and values[label] > bar else None

@lru_cache(maxsize=2)
def load_presidio(model):
    import spacy
    if not spacy.util.is_package(model) and not Path(model).is_dir(): raise ValueError('Local NLP model unavailable')
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    engine = NlpEngineProvider(nlp_configuration={'nlp_engine_name': 'spacy', 'models': [{'lang_code': 'en', 'model_name': model}]}).create_engine()
    return AnalyzerEngine(nlp_engine=engine, supported_languages=['en'])

def mask_pii_locally(text):
    """Optional local helper, never a gateway decision or forwarding path."""
    try:
        from presidio_anonymizer import AnonymizerEngine
        results = load_presidio(settings.DLP_SPACY_MODEL).analyze(text=text, language='en')
        return AnonymizerEngine().anonymize(text=text, analyzer_results=results).text
    except Exception:
        logger.warning('presidio_masking_unavailable')
        raise RuntimeError('Local masking unavailable') from None

def blocked_unavailable():
    return {'decision': 'BLOCKED', 'highest_severity': 'critical', 'matched_policy_codes': [], 'safe_detection_summary': ['Security validation unavailable']}

def analyze_prompt(text):
    from .models import DLPPolicy
    try:
        policies = list(DLPPolicy.objects.filter(enabled=True))
        if not policies: return blocked_unavailable()
        representations = variants(text)
        intent_matches = {value: sensitive_intent_codes(value) for value in representations}
        matches = {}
        for p in policies:
            p.full_clean()
            hit = False
            for value in representations:
                hit |= special_match(p.code, value)
                hit |= p.code in intent_matches[value]
                hit |= any(normalize(k) in value for k in p.keywords)
                for pattern in p.regex_patterns:
                    if p.code in CONCEPT_ONLY_CODES and pattern == SEEDED_PATTERNS.get(p.code) and is_general_concept_question(value):
                        continue
                    hit |= re.search(pattern, value, re.I, timeout=0.025) is not None
                if p.category in ('prompt_injection', 'jailbreak'):
                    compact = re.sub(r'[^a-z0-9]', '', value.translate(str.maketrans({'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t'})))
                    phrases = {'IGNORE_INSTRUCTIONS': ['ignorepreviousinstructions','ignoreallpreviousinstructions','disregardpreviousinstructions'], 'PROMPT_EXTRACTION': ['revealyoursystemprompt','showyoursystemprompt','printthesystemprompt','revealdevelopermessage','showhiddeninstructions'], 'POLICY_OVERRIDE': ['overridepolicy','bypasssafety'], 'JAILBREAK': ['doanythingnow','enabledevelopermode','actasdan','youaredan']}.get(p.code, [])
                    hit |= any(phrase in compact for phrase in phrases)
                if hit: break
            if hit: matches[p.code] = p
        # Critical deterministic matches are final; an optional model cannot reverse them.
        if not matches:
            from .model_registry import guard_blocks
            for config in settings.DLP_GUARD_MODELS:
                if guard_blocks(config, text):
                    selected = {p.code:p for p in policies if p.category == 'prompt_injection'}
                    if not selected:
                        return blocked_unavailable()
                    matches.update(selected)
            if settings.DLP_ENABLE_PRESIDIO:
                try:
                    entities = load_presidio(settings.DLP_SPACY_MODEL).analyze(text=text, language='en')
                    if entities:
                        matches.update({p.code:p for p in policies if p.category == 'pii'})
                except Exception:
                    logger.warning('presidio_unavailable')
                    return blocked_unavailable()
            if settings.DLP_ENABLE_LOCAL_CLASSIFIER:
                try:
                    classifier, threshold, max_length = load_classifier(settings.DLP_LOCAL_MODEL_PATH)
                    # Process every bounded chunk, instead of silently ignoring a long suffix.
                    width = min(800, max(64, max_length * 2))
                    for start in range(0, len(text), width // 2):
                        scores = classifier(text[start:start+width], truncation=True, max_length=max_length, top_k=None)
                        label = model_block_label(scores, threshold)
                        if label:
                            matches.update({p.code:p for p in policies if p.category == label.removeprefix('blocked_')})
                except Exception:
                    logger.warning('classifier_unavailable')
                    return blocked_unavailable()
        ranked = {'low':0,'medium':1,'high':2,'critical':3}
        return {'decision': 'BLOCKED' if matches else 'ALLOWED', 'highest_severity': max((p.severity for p in matches.values()), key=ranked.get, default=None), 'matched_policy_codes': sorted(matches), 'safe_detection_summary': sorted({SAFE_REASONS[p.category] for p in matches.values()})}
    except Exception:
        logger.warning('deterministic_validation_unavailable')
        return blocked_unavailable()

def prompt_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def forward_to_approved_llm(prompt, *, decision):
    """Integration boundary. No network operation exists; blocked calls are rejected."""
    if decision != 'ALLOWED': raise ValueError('Forwarding denied')
    return {'forwarded': False, 'message': 'Approved integration stub reached. No external request was made.'}
