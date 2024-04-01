from django.urls import path
from . import views

urlpatterns = [
    path('', views.RedirectToProfileView.as_view()),
    path('profile/<username>/', views.ProfileView.as_view(), name='profile'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('test/', views.TestView.as_view(), name='test')
]