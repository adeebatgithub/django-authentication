from users.change_password.urls import change_urlpatterns
from users.general.urls import general_urlpatterns
from users.reset_password.urls import reset_urlpatterns
from users.role_change.urls import role_urlpatterns

urlpatterns = [
    *general_urlpatterns,
    *reset_urlpatterns,
    *change_urlpatterns,
    *role_urlpatterns,
]
