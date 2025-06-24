from django.urls import path

from . import views


urlpatterns = [
    # change the role and group of a user
    # an email will pass to the admins' email to verify and change role (user)
    path('send/mail/request/<role>/', views.RoleChangeRequestMail.as_view(), name='role-send-mail'),
    # show success message
    path('send/mail/done/', views.RoleChangeRequestSendDone.as_view(), name='role-send-mail-done'),

    # confirm the role change (admin)
    path("confirm/<username>/<role>/", views.RoleChangeConfirm.as_view(), name="role-change-confirm"),

    # change role and group (admin)
    path('accept/role/<uidb64>/<token>/', views.RoleChangeView.as_view(), name='role-change-accept'),
    # success mail
    path('accepted/mail/', views.RoleChangeDoneMail.as_view(), name='role-change-accept-mail'),
    # show messages
    path('done/', views.RoleChangeDone.as_view(), name='role-change-done'),

    # role change declined by admin sending mail to user
    path('declined/mail/', views.RoleChangeFailMail.as_view(), name='role-change-decline-mail'),
    # show messages
    path('fail/', views.RoleChangeDeclined.as_view(), name='role-change-fail'),
]
