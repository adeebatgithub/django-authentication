from django.urls import path
from . import views

urlpatterns = [
    path('', views.RedirectUserView.as_view(), name="redirect-user"),
    path('profile/<username>/', views.ProfileView.as_view(), name='profile'),

    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('register/', views.RegisterView.as_view(), name='signup'),
    path('register/add-to-example-group/', views.AddToExampleGroup.as_view(), name='add-to-example-group'),


    path('test/', views.test),
]
