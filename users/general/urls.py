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
    # add a role to the registered user
    path('register/add-example-role', views.AddExampleRole.as_view(), name='add-example-role'),
    # add the registered user to a group
    path('register/add-to-example-group/', views.AddToExampleGroup.as_view(), name='add-to-example-group'),

    # user deletion
    # send confirmation mail
    path('delete/send-mail/', views.DeleteUserSendMail.as_view(), name='delete-send-mail'),
    # success message
    path('delete/send-mail/done/', views.MailSendDoneView.as_view(), name='delete-mail-done'),
    # delete confirmation page
    path('delete/confirm/', views.DeleteUserConfirmation.as_view(), name='delete-user-confirm'),
    # delete declined
    path('delete/decline/<token>', views.DeleteUseDecline.as_view(), name='delete-user-decline'),
    # delete confirmed
    path('delete/confirm/<token>/', views.DeleteUser.as_view(), name='delete-user'),

    # user update
    # change username
    path('username/<username>', views.ChangeUsername.as_view(), name='change-username'),
    # change fullname
    path('fullname/<username>', views.ChangeFullname.as_view(), name='change-fullname'),
    # change email
    path('email/<username>', views.ChangeEmail.as_view(), name='change-email'),

]
