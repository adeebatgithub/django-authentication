from django.urls import path

from . import views

urlpatterns = [
    # user deletion
    # send confirmation mail
    path('send-mail/', views.DeleteUserSendMail.as_view(), name='delete-send-mail'),
    # success message
    path('send-mail/done/', views.MailSendDoneView.as_view(), name='delete-mail-done'),

    # delete confirmation page
    path('confirm/<token>', views.DeleteUserConfirmation.as_view(), name='delete-user-confirm'),

    # delete declined
    path('decline/<token>', views.DeleteUseDecline.as_view(), name='delete-user-decline'),
    # delete confirmed
    path('accept/<token>/', views.DeleteUser.as_view(), name='delete-user'),
]
