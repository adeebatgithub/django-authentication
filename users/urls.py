from django.urls import path
from users import views
from users.general.urls import general_urlpatterns
from users.reset_password.urls import reset_urlpatterns

urlpatterns = [
    # change the role and grouo of an user
    # an email will pass to the settings.EMAIL_HOST_USER to verify and change role
    path('send-role-change-mail/<role>', views.SendRoleChangeMail.as_view(), name='send-role-change-mail'),
    # show success message
    path('send-role-change-mail-done/', views.RoleChangeMailSendDone.as_view(), name='send-role-change-mail-done'),
    # change role and group
    path('change-role/<uidb64>/<token>', views.RoleChangeToStaff.as_view(), name='change-role'),
    path('change-role-done-mail/', views.RoleChangeDoneMail.as_view(), name='change-role-done-mail'),
    path('change-role-fail/<uidb64>/<token>/<role>/', views.RoleChangeDecline.as_view(), name='change-role-fail'),
    path('change-role-fail-mail/', views.RoleChangeFailMail.as_view(), name='change-role-fail-mail'),
    # show success message
    path('role-change-done/', views.RoleChangeDone.as_view(), name='role-change-done'),
    path('role-change-fail/', views.RoleChangeDeclined.as_view(), name='role-change-fail'),

    path('test/', views.test, name="test"),
]

urlpatterns += general_urlpatterns + reset_urlpatterns
