
from django.views import View
from django.contrib.auth.views import LoginView
from .forms import RegisterForm, LoginForm
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.messages.views import SuccessMessageMixin
from .forms import RegisterForm
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin

from .forms import UpdateUserForm, UpdateProfileForm

#ab 19-76
from django.conf import settings
from spotipy.oauth2 import SpotifyOAuth
from django.http import JsonResponse

from spotipy import Spotify

def spotify_auth(request):
    sp_oauth = SpotifyOAuth(
        client_id=settings.SPOTIFY_CLIENT_ID,
        client_secret=settings.SPOTIFY_CLIENT_SECRET,
        redirect_uri=settings.SPOTIFY_REDIRECT_URI,
        scope="user-top-read"
    )
    auth_url = sp_oauth.get_authorize_url()
    return redirect(auth_url)


def spotify_callback(request):
    code = request.GET.get('code')  # Get the authorization code from URL
    sp_oauth = SpotifyOAuth(
        client_id=settings.SPOTIFY_CLIENT_ID,
        client_secret=settings.SPOTIFY_CLIENT_SECRET,
        redirect_uri=settings.SPOTIFY_REDIRECT_URI,
        scope="user-top-read"
    )
    try:
        token_info = sp_oauth.get_access_token(code)
        request.session['token_info'] = token_info  # Store token in session
        request.session.modified = True  # Ensure the session is saved
        return redirect('wrapped_button')  # Redirect back to wrapped page
    except Exception as e:
        print("Error obtaining token:", e)
        return redirect('spotify_auth')

    # Exchange code for an access token
    token_info = sp_oauth.get_access_token(code)
    request.session['token_info'] = token_info  # Store token in session
    return redirect('generate_wrapped')  # Redirect to the Wrapped generation view

def wrapped_button(request):
    # Render the template with the button
    return render(request, 'wrapped_button.html')

def generate_wrapped(request):
    # Check if the token_info is in the session
    token_info = request.session.get('token_info')
    if token_info is None or 'access_token' not in token_info:
        # Redirect to Spotify authentication if token is missing
        return redirect('spotify_auth')
    
    # Initialize the Spotify client with the access token
    sp = Spotify(auth=token_info['access_token'])

    # Fetch top tracks and artists
    top_tracks = sp.current_user_top_tracks(limit=10, time_range='long_term')
    top_artists = sp.current_user_top_artists(limit=10, time_range='long_term')
    playlists = sp.current_user_playlists(limit=5)  # Fetch user playlists for example
    
    # Example data response (customize as needed)
    wrapped_data = {
        "top_tracks": [track['name'] for track in top_tracks['items']],
        "top_artists": [artist['name'] for artist in top_artists['items']],
        "playlists": [playlist['name'] for playlist in playlists['items']]
    }
    
    return JsonResponse(wrapped_data)

def home(request):
    return render(request, 'users/home.html')


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject.txt'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')


class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'users/register.html'

    def dispatch(self, request, *args, **kwargs):
        # will redirect to the home page if a user tries to access the register page while logged in
        if request.user.is_authenticated:
            return redirect(to='/')

        # else process dispatch as it otherwise normally would
        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)

        if form.is_valid():
            form.save()

            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}')

            return redirect(to='/')

        return render(request, self.template_name, {'form': form})

class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            # set session expiry to 0 seconds. So it will automatically close the session after the browser is closed.
            self.request.session.set_expiry(0)

            # Set session as modified to force data updates/cookie to be saved.
            self.request.session.modified = True

        # else browser session will be as long as the session cookie time "SESSION_COOKIE_AGE" defined in settings.py
        return super(CustomLoginView, self).form_valid(form)




@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})

class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('users-home')

