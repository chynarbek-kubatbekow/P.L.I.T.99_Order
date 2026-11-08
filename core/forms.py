from django import forms


class FeedbackForm(forms.Form):
    message = forms.CharField(
        label='Ваш отзыв', min_length=10, max_length=4000, strip=True,
        widget=forms.Textarea(attrs={
            'rows': 6, 'maxlength': 4000, 'minlength': 10,
            'autocomplete': 'off',
        }),
    )
    website = forms.CharField(required=False, max_length=200, widget=forms.HiddenInput)

    def clean_message(self):
        value = self.cleaned_data['message']
        if any(ord(c) < 32 and c not in '\n\r\t' for c in value):
            raise forms.ValidationError('Уберите управляющие символы из текста.')
        return value
