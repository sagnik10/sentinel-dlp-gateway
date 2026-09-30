from django import forms
from django.conf import settings

class PromptForm(forms.Form):
    prompt = forms.CharField(strip=False, max_length=settings.DLP_MAX_PROMPT_LENGTH, widget=forms.Textarea(attrs={'rows': 9, 'placeholder': 'Enter a prompt for the approved AI gateway…', 'autocomplete': 'off', 'spellcheck': 'false'}))
    def clean_prompt(self):
        value = self.cleaned_data['prompt']
        if not value.strip():
            raise forms.ValidationError('Enter a nonempty prompt.')
        return value
