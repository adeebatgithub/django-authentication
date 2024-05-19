from django.urls import path

from . import views

urlpatterns = [
    # change the role and group of a user
    # an email will pass to the settings.EMAIL_HOST_USER to verify and change role
    path('send-mail/<role>/', views.RoleSendChangeMail.as_view(), name='role-send-mail'),
    # show success message
    path('send-mail/done/', views.RoleChangeMailSendDone.as_view(), name='role-send-mail-done'),
    # change role and group
    path('done/<uidb64>/<token>', views.RoleChangeToStaff.as_view(), name='role-change'),
    path('done/mail/', views.RoleChangeDoneMail.as_view(), name='change-role-done-mail'),
    path('fail/<uidb64>/<token>/<role>/', views.RoleChangeDecline.as_view(), name='change-role-fail'),
    path('fail/mail/', views.RoleChangeFailMail.as_view(), name='change-role-fail-mail'),
    # show success message
    path('done/', views.RoleChangeDone.as_view(), name='role-change-done'),
    path('fail/', views.RoleChangeDeclined.as_view(), name='role-change-fail'),
]
