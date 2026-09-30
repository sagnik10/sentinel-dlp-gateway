import uuid
from django.core.exceptions import ValidationError
from django.db import models
import regex

CATEGORIES = [('credential', 'Credential'), ('pii', 'Personal data'), ('confidential_data', 'Confidential data'), ('prompt_injection', 'Prompt injection'), ('jailbreak', 'Jailbreak'), ('data_exfiltration', 'Data exfiltration')]
SEVERITIES = [('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')]

class DLPPolicy(models.Model):
    name = models.CharField(max_length=120)
    code = models.SlugField(max_length=64, unique=True)
    category = models.CharField(max_length=32, choices=CATEGORIES)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITIES, default='high')
    enabled = models.BooleanField(default=True)
    keywords = models.JSONField(default=list, blank=True)
    regex_patterns = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        for field in ('keywords', 'regex_patterns'):
            values = getattr(self, field)
            if not isinstance(values, list) or len(values) > 100 or any(not isinstance(v, str) or not v.strip() or len(v) > 1000 for v in values):
                raise ValidationError({field: 'Use a list of at most 100 nonempty strings, each at most 1000 characters.'})
        try:
            for pattern in self.regex_patterns:
                regex.compile(pattern)
        except regex.error:
            raise ValidationError({'regex_patterns': 'Invalid regular expression.'}) from None

    def __str__(self):
        return self.code

class PromptAuditEvent(models.Model):
    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    user_identifier_hash = models.CharField(max_length=64, null=True, blank=True)
    prompt_hash = models.CharField(max_length=64)
    decision = models.CharField(max_length=7, choices=[('ALLOWED', 'ALLOWED'), ('BLOCKED', 'BLOCKED')])
    highest_severity = models.CharField(max_length=10, choices=SEVERITIES, null=True, blank=True)
    matched_policy_codes = models.JSONField(default=list)
    safe_detection_summary = models.JSONField(default=list)
    latency_ms = models.PositiveIntegerField()
    forwarded_to_llm = models.BooleanField(default=False)
    class Meta:
        ordering = ['-created_at']
