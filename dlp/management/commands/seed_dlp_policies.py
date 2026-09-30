from django.core.management.base import BaseCommand
from django.db import transaction
from dlp.models import DLPPolicy
from dlp.utils import RULES, PREVIOUS_SEEDED_PATTERNS

class Command(BaseCommand):
    help = 'Create built-in policies without overwriting administrator changes.'
    @transaction.atomic
    def handle(self, *args, **options):
        created = refreshed = 0
        for code, category, pattern in RULES:
            policy, new = DLPPolicy.objects.get_or_create(code=code, defaults={'name': code.replace('_', ' ').title(), 'category': category, 'description': 'Blocks configured ' + category.replace('_', ' ') + ' indicators.', 'severity': 'critical' if category in ('credential','prompt_injection','jailbreak','data_exfiltration') else 'high', 'regex_patterns': [pattern] if pattern else []})
            created += new
            if not new and code in PREVIOUS_SEEDED_PATTERNS and policy.regex_patterns == [PREVIOUS_SEEDED_PATTERNS[code]]:
                policy.regex_patterns = [pattern]
                policy.save(update_fields=['regex_patterns', 'updated_at'])
                refreshed += 1
        self.stdout.write(f'Created {created} policies; refreshed {refreshed} unchanged built-in patterns; {len(RULES)} seed codes available.')
