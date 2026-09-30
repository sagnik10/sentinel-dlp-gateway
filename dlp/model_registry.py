"""Optional open-source injection classifiers, loaded exclusively from disk."""
import math
from functools import lru_cache
from pathlib import Path

MODEL_CATALOG = {
    'protectai': {'repository': 'protectai/deberta-v3-base-prompt-injection-v2',
                 'license': 'Apache-2.0', 'labels': {'SAFE', 'INJECTION'},
                 'note': 'Upstream archived; English injection detection only.'},
    'deepset': {'repository': 'deepset/deberta-v3-base-injection',
                'license': 'MIT', 'labels': {'LEGIT', 'INJECTION'},
                'note': 'English/German injection classifier; calibrate on local data.'},
}


@lru_cache(maxsize=4)
def load_guard(name, path):
    if name not in MODEL_CATALOG or not Path(path).is_absolute() or not Path(path).is_dir():
        raise ValueError('Invalid local guard configuration')
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        path, local_files_only=True, trust_remote_code=False, use_safetensors=True)
    if set(model.config.id2label.values()) != MODEL_CATALOG[name]['labels']:
        raise ValueError('Guard label mismatch')
    model.eval()
    return tokenizer, model


def guard_blocks(config, text):
    import torch
    threshold = config.get('threshold', 0.9)
    if not isinstance(threshold, (float, int)) or not math.isfinite(threshold) or not 0.5 <= threshold <= 1:
        raise ValueError('Invalid guard threshold')
    tokenizer, model = load_guard(config['name'], config['path'])
    tokens = tokenizer.encode(text, add_special_tokens=False)
    width = 512 - tokenizer.num_special_tokens_to_add(pair=False)
    if width < 32:
        raise ValueError('Invalid tokenizer')
    injection_id = next(int(k) for k, v in model.config.id2label.items() if v == 'INJECTION')
    for start in range(0, len(tokens), width - 64):
        batch = tokenizer.prepare_for_model(tokens[start:start + width], return_tensors='pt')
        with torch.inference_mode():
            scores = model(**batch).logits.softmax(dim=-1)[0]
        values = scores.tolist()
        if any(not math.isfinite(v) or not 0 <= v <= 1 for v in values):
            raise ValueError('Invalid guard scores')
        if values[injection_id] >= threshold:
            return True
    return False
