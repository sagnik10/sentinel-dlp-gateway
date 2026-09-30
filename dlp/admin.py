from django.contrib import admin
from .models import DLPPolicy, PromptAuditEvent

@admin.register(DLPPolicy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'category', 'severity', 'enabled')
    list_filter = ('enabled', 'category', 'severity')

@admin.register(PromptAuditEvent)
class AuditAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'created_at', 'decision', 'highest_severity', 'forwarded_to_llm')
    readonly_fields = tuple(f.name for f in PromptAuditEvent._meta.fields)
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
