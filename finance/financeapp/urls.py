from django.urls import path
from . import views

urlpatterns = [
    path('', views.main, name='main'),
    path('category/', views.category, name='usercategory'),
    path('expense/', views.expense, name='expense'),
    path('detail/<int:expense_id>', views.detail, name='detail'),
    path('done/<int:expense_id>', views.set_done, name='set_done'),
    path('delete/<int:expense_id>', views.delete_expense, name='delete_expense'),
    path('signup/', views.signupuser, name='signupuser'),
    path('login/', views.loginuser, name='loginuser'),
    path('logout/', views.logoutuser, name='logoutuser'),
]