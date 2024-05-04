from django.urls import path

from . import views

role_urlpatterns = [
    # change the role and grouo of an user
    # an email will pass to the settings.EMAIL_HOST_USER to verify and change role
    path('change/role/send-mail/<role>/', views.RoleSendChangeMail.as_view(), name='role-send-mail'),
    # show success message
    path('change/role/send-mail/done/', views.RoleChangeMailSendDone.as_view(), name='role-send-mail-done'),
    # change role and group
    path('change/role/done/<uidb64>/<token>', views.RoleChangeToStaff.as_view(), name='role-change'),
    path('change/role/done/mail/', views.RoleChangeDoneMail.as_view(), name='change-role-done-mail'),
    path('change/role/fail/<uidb64>/<token>/<role>/', views.RoleChangeDecline.as_view(), name='change-role-fail'),
    path('change/role/fail/mail/', views.RoleChangeFailMail.as_view(), name='change-role-fail-mail'),
    # show success message
    path('role/change/done/', views.RoleChangeDone.as_view(), name='role-change-done'),
    path('role/change/fail/', views.RoleChangeDeclined.as_view(), name='role-change-fail'),
]