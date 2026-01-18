from django.urls import path

from . import views

urlpatterns = [
    # redirect user based on authentication and authorisation
    path('', views.RedirectUserView.as_view(), name="redirect-user"),
    # user login
    path('login/', views.LoginView.as_view(), name='login'),
    # user logout
    path('logout/', views.LogoutView.as_view(), name='logout'),
    # user registration
    path('register/', views.RegisterView.as_view(), name='signup'),

]
