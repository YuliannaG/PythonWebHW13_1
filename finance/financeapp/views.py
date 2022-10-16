from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from .models import Category, Expense, User
from .forms import CategoryForm, ExpenseForm


# Create your views here.
def main(request):
    expenses = []
    if request.user.is_authenticated:
        expenses = Expense.objects.filter(user_id=request.user).all()
    return render(request, 'financeapp/index.html', {"expenses": expenses})


@login_required
def detail(request, expense_id):
    # expense = Expense.objects.get(pk=expense_id, user_id=request.user)
    expense = get_object_or_404(Expense, pk=expense_id, user_id=request.user)
    # expense.category_list = ', '.join([str(name) for name in expense.category.all()])
    return render(request, 'financeapp/detail.html', {"expense": expense})


@login_required
def category(request):
    if request.method == 'POST':
        try:
            form = CategoryForm(request.POST)
            category = form.save(commit=False)
            category.user_id = request.user
            category.save()
            return redirect(to='main')
        except ValueError as err:
            return render(request, 'financeapp/category.html', {'form': CategoryForm(), 'error': err})
        except IntegrityError as err:
            return render(request, 'financeapp/category.html', {'form': CategoryForm(), 'error': 'Category will be unique!'})
    return render(request, 'financeapp/category.html', {'form': CategoryForm()})


@login_required
def expense(request):
    categories = Category.objects.filter(user_id=request.user).all()

    if request.method == 'POST':
        try:
            # list_categories = request.POST.getlist('categories')
            form = ExpenseForm(request.POST)
            new_expense = form.save(commit=False)
            new_expense.user_id = request.user
            new_expense.save()
            # choice_categories = Category.objects.filter(name__in=list_categories, user_id=request.user)  # WHERE name in []
            # for category in choice_categories.iterator():
            #     new_expense.category.add(category)
            return redirect(to='main')
        except ValueError as err:
            return render(request, 'financeapp/expense.html', {'form': ExpenseForm(), 'error': err})

    return render(request, 'financeapp/expense.html', {'form': ExpenseForm()})


@login_required
def set_done(request, expense_id):
    Expense.objects.filter(pk=expense_id, user_id=request.user).update(done=True)
    return redirect('main')


@login_required
def delete_expense(request, expense_id):
    expense = Expense.objects.get(pk=expense_id, user_id=request.user)
    expense.delete()
    return redirect('main')


def signupuser(request):
    if request.method == 'GET':
        return render(request, 'financeapp/signup.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                return redirect('loginuser')
            except IntegrityError as err:
                return render(request, 'financeapp/signup.html',
                              {'form': UserCreationForm(), 'error': 'Username already exist!'})

        else:
            return render(request, 'financeapp/signup.html',
                          {'form': UserCreationForm(), 'error': 'Password did not match'})


def loginuser(request):
    if request.method == 'GET':
        return render(request, 'financeapp/login.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'financeapp/login.html',
                          {'form': AuthenticationForm(), 'error': 'Username or password didn\'t match'})
        login(request, user)
        return redirect('main')


@login_required
def logoutuser(request):
    logout(request)
    return redirect('main')