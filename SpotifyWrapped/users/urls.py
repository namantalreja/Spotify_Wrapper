# urls.py

from django.urls import path
from .views import home, RegisterView, ResetPasswordView, profile, wrapped_list, wrapped_history, wrapped_detail
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', home, name='users-home'),
    path('register/', RegisterView.as_view(), name='users-register'),
    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'),
         name='password_reset_confirm'),
    path('password-reset-complete/',
         auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'),
         name='password_reset_complete'),
    path('profile/', profile, name='users-profile'),
    path('spotify/auth/', views.spotify_auth, name='spotify_auth'),
    path('spotify/callback/', views.spotify_callback, name='spotify_callback'),
    path('generate_wrapped/', views.generate_wrapped, name='generate_wrapped'),
    path('wrapped_button/', views.wrapped_button, name='wrapped_button'),
    path('wrapped/', wrapped_list, name='wrapped_list'),
    path('wrapped_history/', wrapped_history, name='wrapped_history'),
    path('wrapped/<int:pk>/', wrapped_detail, name='wrapped_detail'),
]
