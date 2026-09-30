import time
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import RequestDataTooBig, TooManyFieldsSent
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseForbidden, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.utils.crypto import salted_hmac
from .forms import PromptForm
from .models import PromptAuditEvent, DLPPolicy
from .utils import analyze_prompt, blocked_unavailable, forward_to_approved_llm, prompt_hash, load_classifier, load_presidio, logger

class GatewaySecurityMiddleware:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        try:
            limit = 20 * 1024 * 1024 + 65536 if request.path == '/documents/check/' else settings.DATA_UPLOAD_MAX_MEMORY_SIZE
            if request.path in ('/check/', '/documents/check/') and int(request.META.get('CONTENT_LENGTH') or 0) > limit:
                response = JsonResponse({'decision':'BLOCKED','reasons':['Request size limit exceeded']}, status=413)
            else: response = self.get_response(request)
        except (ValueError, RequestDataTooBig, TooManyFieldsSent):
            response = JsonResponse({'decision':'BLOCKED','reasons':['Invalid request']}, status=400)
        response['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'none'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response['Cache-Control'] = 'no-store'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        return response

@require_GET
def index(request):
    return render(request, 'dlp/index.html', {'form':PromptForm()})

def result_response(request, result, status=200, message=''):
    # Never bind a submitted form to a response or echo policy free text.
    return render(request, 'dlp/index.html', {'form':PromptForm(), 'result':result, 'message':message}, status=status)

def csrf_failure(request, reason=''):
    kind = 'origin' if reason.startswith('Origin') else 'cookie' if 'cookie' in reason.lower() else 'token'
    logger.warning('csrf_validation_failed_%s', kind)
    result = blocked_unavailable()
    result['safe_detection_summary'] = ['Request verification failed. Reload the prompt page and try again.']
    return result_response(request, result, 403)

@require_POST
@sensitive_post_parameters()
@sensitive_variables()
def check(request):
    started = time.perf_counter()
    try:
        # REMOTE_ADDR only: do not trust arbitrary X-Forwarded-For values.
        identity = salted_hmac('dlp-rate', request.META.get('REMOTE_ADDR','unknown')).hexdigest()
        key = f'dlp:rate:{identity}:{int(time.time()) // settings.DLP_RATE_WINDOW}'
        # DatabaseCache increment is not atomic. cache.add claims a short lock;
        # lock contention is denied conservatively rather than granting extra requests.
        lock = key + ':lock'
        if not cache.add(lock, True, timeout=5):
            return result_response(request, blocked_unavailable(), 429)
        try:
            count = cache.get(key, 0)
            cache.set(key, count + 1, timeout=settings.DLP_RATE_WINDOW * 2)
        finally: cache.delete(lock)
        if count >= settings.DLP_RATE_LIMIT:
            result = blocked_unavailable()
            result['safe_detection_summary'] = ['Request rate limit exceeded']
            response = result_response(request, result, 429)
            response['Retry-After'] = str(settings.DLP_RATE_WINDOW)
            return response
        form = PromptForm(request.POST)
        if not form.is_valid():
            result = blocked_unavailable()
            result['safe_detection_summary'] = ['Invalid or oversized prompt']
            return result_response(request, result, 400)
        prompt = form.cleaned_data['prompt']
        result = analyze_prompt(prompt)
        user_hash = salted_hmac('dlp-user', str(request.user.pk), algorithm='sha256').hexdigest() if request.user.is_authenticated else None
        # Audit persistence must succeed before the integration boundary is reached.
        event = PromptAuditEvent.objects.create(prompt_hash=prompt_hash(prompt), user_identifier_hash=user_hash, latency_ms=int((time.perf_counter()-started)*1000), **result)
        message = ''
        if result['decision'] == 'ALLOWED':
            outcome = forward_to_approved_llm(prompt, decision=result['decision'])
            event.forwarded_to_llm = outcome['forwarded']
            event.save(update_fields=['forwarded_to_llm'])
            message = outcome['message']
        return result_response(request, result, message=message)
    except Exception:
        logger.warning('gateway_request_failed')
        return result_response(request, blocked_unavailable(), 503)

@require_GET
def audit(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return HttpResponseForbidden('Staff access required.')
    page = Paginator(PromptAuditEvent.objects.all(), 50).get_page(request.GET.get('page'))
    return render(request, 'dlp/audit.html', {'page':page})

@require_GET
def health(request):
    try:
        ready = DLPPolicy.objects.filter(enabled=True).exists()
        cache.set('dlp-health', True, 5)
        ready = ready and cache.get('dlp-health') is True
        if ready and settings.DLP_ENABLE_LOCAL_CLASSIFIER:
            load_classifier(settings.DLP_LOCAL_MODEL_PATH)
        if ready and settings.DLP_ENABLE_PRESIDIO:
            load_presidio(settings.DLP_SPACY_MODEL)
        if ready and settings.DLP_GUARD_MODELS:
            from .model_registry import load_guard
            for config in settings.DLP_GUARD_MODELS:
                load_guard(config['name'], config['path'])
        return JsonResponse({'status':'ok' if ready else 'unavailable'}, status=200 if ready else 503)
    except Exception:
        return JsonResponse({'status':'unavailable'}, status=503)


@require_POST
@sensitive_post_parameters()
@sensitive_variables()
def inspect_upload(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return HttpResponseForbidden('Staff access required.')
    from .documents import MAX_BYTES, inspect_document
    import json
    if int(request.META.get('CONTENT_LENGTH') or 0) > MAX_BYTES + 65536:
        return JsonResponse({'decision': 'BLOCKED', 'reason': 'File size limit exceeded'}, status=413)
    upload = request.FILES.get('document')
    if upload is None or upload.size > MAX_BYTES:
        return JsonResponse({'decision': 'BLOCKED', 'reason': 'Missing or oversized file'}, status=400)
    report = inspect_document(upload.read(MAX_BYTES + 1))
    response = HttpResponse(json.dumps(report, indent=2), content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="dlp-document-report.json"'
    return response
