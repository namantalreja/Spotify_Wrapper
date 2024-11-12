
from django.urls import path
from .views import home, generate_data, RegisterView, ResetPasswordView  # Import the view here
from django.contrib.auth import views as auth_views
from .views import profile
from . import views

urlpatterns = [
    path('', home, name='users-home'),
     path('generate/', generate_data, name='generate_data'),
    path('register/', RegisterView.as_view(), name='users-register'),  # This is what we added
    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'),
         name='password_reset_confirm'),
    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'),
         name='password_reset_complete'),
    path('profile/', profile, name='users-profile'),
     path('spotify/login/', views.spotify_login, name='spotify_login'),
    path('spotify/callback/', views.spotify_callback, name='spotify_callback'),
    path('wraps/', views.wraps_list, name='wraps_list'),  # New URL for listing wraps
    path('wraps/<int:wrap_id>/', views.wrap_detail, name='wrap_detail'),  # New URL for wrap details

]
