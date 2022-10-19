from django.forms import ModelForm
from .models import Category, Expense


class CategoryForm(ModelForm):
    class Meta:
        model = Category
        fields = ['name']


class ExpenseForm(ModelForm):
    class Meta:
        model = Expense
        fields = ['sum', 'description', 'category','created']