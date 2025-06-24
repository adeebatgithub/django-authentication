from django.urls import path

from . import views

urlpatterns = [
    # redirect user based on authentication and authorisation
    path('', views.RedirectUserView.as_view(), name="redirect-user"),
    # profile page
    path('profile/<username>/', views.ProfileView.as_view(), name='profile'),

    # user login
    path('login/', views.LoginView.as_view(), name='login'),
    # user logout
    path('logout/', views.LogoutView.as_view(), name='logout'),

    # user registration
    path('register/', views.RegisterView.as_view(), name='signup'),

    # user update
    # change username
    path('username/<username>', views.ChangeUsername.as_view(), name='change-username'),
    # change fullname
    path('fullname/<username>', views.ChangeFullname.as_view(), name='change-fullname'),
    # change email
    path('email/<username>', views.ChangeEmail.as_view(), name='change-email'),

]
