
from django.views import View
from django.contrib.auth.views import LoginView
from .forms import RegisterForm, LoginForm
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.messages.views import SuccessMessageMixin
from .forms import RegisterForm
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
import requests
import google.generativeai as genai
import os
from django.shortcuts import redirect, render
from django.conf import settings
from django.utils import timezone
from .models import SpotifyData
import base64
import urllib.parse
from .forms import UpdateUserForm, UpdateProfileForm
from .models import SpotifyData, DuoWrapInvitation, DuoSpotifyData
import markdown  # Import the markdown library
genai.configure(api_key=settings.GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")
def home(request):
    return render(request, 'users/home.html')
@login_required
def spotify_login(request):
    scopes = 'user-top-read playlist-read-private'
    auth_url = 'https://accounts.spotify.com/authorize'
    params = {
        'client_id': settings.SPOTIFY_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': settings.SPOTIFY_REDIRECT_URI,
        'scope': scopes,
    }
    url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    return redirect(url)

def spotify_callback(request):
    code = request.GET.get('code')
    error = request.GET.get('error')
    if error:
        return render(request, 'error.html', {'error': error})

    token_url = 'https://accounts.spotify.com/api/token'
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()).decode()
    }
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.SPOTIFY_REDIRECT_URI,
    }

    response = requests.post(token_url, data=data, headers=headers)
    if response.status_code != 200:
        return render(request, 'error.html', {'error': 'Failed to retrieve access token.'})

    tokens = response.json()
    access_token = tokens['access_token']
    refresh_token = tokens['refresh_token']
    expires_in = tokens.get('expires_in')  # in seconds

    # Save tokens in the user's profile
    profile = request.user.profile
    profile.spotify_access_token = access_token
    profile.spotify_refresh_token = refresh_token
    profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
    profile.save()

    return redirect('generate_data')

@login_required
def wraps_list(request):
    wraps = SpotifyData.objects.filter(user=request.user).order_by('-timestamp')
    duo_wraps = DuoSpotifyData.objects.filter(users=request.user).order_by('-timestamp')
    context = {'wraps': wraps, 'duo_wraps': duo_wraps}
    return render(request, 'users/wraps_list.html', context)



@login_required
def wrap_detail(request, wrap_id):
    wrap = get_object_or_404(SpotifyData, id=wrap_id, user=request.user)

    # Extract data from the wrap
    top_artists = wrap.top_artists.get('items', [])
    top_tracks = wrap.top_tracks.get('items', [])
    playlists = wrap.playlists.get('items', [])

    # Process artists to include image URLs
    processed_top_artists = []
    for artist in top_artists:
        image_url = artist['images'][0]['url'] if artist.get('images') else None
        processed_top_artists.append({
            'name': artist['name'],
            'image_url': image_url,
        })

    # Process tracks to include album image URLs
    processed_top_tracks = []
    for track in top_tracks:
        album_image_url = track['album']['images'][0]['url'] if track['album'].get('images') else None
        artists = [artist['name'] for artist in track['artists']]
        processed_top_tracks.append({
            'name': track['name'],
            'artists': artists,
            'album_image_url': album_image_url,
        })

    # Process playlists to include image URLs
    processed_playlists = []
    for playlist in playlists:
        image_url = playlist['images'][0]['url'] if playlist.get('images') else None
        processed_playlists.append({
            'name': playlist['name'],
            'image_url': image_url,
        })

    # Convert Markdown insights to HTML
    if wrap.insights:
        insights_html = markdown.markdown(wrap.insights)
    else:
        insights_html = None

    context = {
        'wrap': wrap,
        'insights_html': insights_html,  # Add insights_html to context
        'top_artists': processed_top_artists,
        'top_tracks': processed_top_tracks,
        'playlists': processed_playlists,
    }
    return render(request, 'users/wrap_detail.html', context)

@login_required
def generate_data(request):
    profile = request.user.profile
    access_token = profile.spotify_access_token
    refresh_token = profile.spotify_refresh_token
    token_expires = profile.spotify_token_expires

    # If access token is expired, refresh it
    if not access_token or not token_expires or token_expires <= timezone.now():
        # Refresh the token
        token_url = 'https://accounts.spotify.com/api/token'
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()).decode()
        }
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        response = requests.post(token_url, data=data, headers=headers)
        if response.status_code != 200:
            messages.error(request, 'Failed to refresh access token.')
            return redirect('spotify_login')  # Or handle as needed

        tokens = response.json()
        access_token = tokens['access_token']
        expires_in = tokens.get('expires_in')  # in seconds

        # Update the profile with the new token and expiry
        profile.spotify_access_token = access_token
        profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
        profile.save()

    if not access_token:
        return redirect('spotify_login')

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    # Fetch Top Artists
    top_artists_url = 'https://api.spotify.com/v1/me/top/artists'
    top_artists_response = requests.get(top_artists_url, headers=headers)
    if top_artists_response.status_code != 200:
        messages.error(request, 'Failed to fetch top artists.')
        return redirect('wraps_list')
    top_artists = top_artists_response.json()

    # Fetch Top Tracks
    top_tracks_url = 'https://api.spotify.com/v1/me/top/tracks'
    top_tracks_response = requests.get(top_tracks_url, headers=headers)
    if top_tracks_response.status_code != 200:
        messages.error(request, 'Failed to fetch top tracks.')
        return redirect('wraps_list')
    top_tracks = top_tracks_response.json()

    # Fetch Playlists
    playlists_url = 'https://api.spotify.com/v1/me/playlists'
    playlists_response = requests.get(playlists_url, headers=headers)
    if playlists_response.status_code != 200:
        messages.error(request, 'Failed to fetch playlists.')
        return redirect('wraps_list')
    playlists = playlists_response.json()

    # Process data to include image URLs
    processed_top_artists = []
    for artist in top_artists.get('items', []):
        image_url = artist['images'][0]['url'] if artist.get('images') else None
        processed_top_artists.append({
            'name': artist['name'],
            'image_url': image_url,
        })

    processed_top_tracks = []
    for track in top_tracks.get('items', []):
        album_image_url = track['album']['images'][0]['url'] if track['album'].get('images') else None
        artists = [artist['name'] for artist in track['artists']]
        processed_top_tracks.append({
            'name': track['name'],
            'artists': artists,
            'album_image_url': album_image_url,
        })

    processed_playlists = []
    for playlist in playlists.get('items', []):
        image_url = playlist['images'][0]['url'] if playlist.get('images') else None
        processed_playlists.append({
            'name': playlist['name'],
            'image_url': image_url,
        })

    # Generate insights using Gemini
    try:
        prompt = (
            "Based on the following Spotify data:\n"
            f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
            f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n"
            f"Playlists: {[playlist['name'] for playlist in processed_playlists]}\n\n"
            "Provide insights on how someone who listens to this kind of music tends to act, think, and dress."
        )
        response = model.generate_content(prompt)
        insights = response.text.strip()
    except Exception as e:
        insights = "Insights could not be generated at this time."
        # Optionally, log the error for debugging
        print(f"Error generating insights: {e}")

    insights_html = markdown.markdown(insights)

    # Save data with timestamp and insights
    SpotifyData.objects.create(
        user=request.user,
        top_artists=top_artists,
        top_tracks=top_tracks,
        playlists=playlists,
        insights=insights,  # Store the raw insights
        timestamp=timezone.now()
    )

    context = {
        'insights_html': insights_html,  # Pass the converted HTML
        'top_artists': processed_top_artists,
        'top_tracks': processed_top_tracks,
        'playlists': processed_playlists,
    }
    return render(request, 'users/generate.html', context)


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



def process_artists(artists_data):
    processed_artists = []
    for artist in artists_data.get('items', []):
        image_url = artist['images'][0]['url'] if artist.get('images') else None
        processed_artists.append({'name': artist['name'], 'image_url': image_url})
    return processed_artists

def process_tracks(tracks_data):
    processed_tracks = []
    for track in tracks_data.get('items', []):
        album_image_url = track['album']['images'][0]['url'] if track['album'].get('images') else None
        artists = [artist['name'] for artist in track['artists']]
        processed_tracks.append({
            'name': track['name'],
            'artists': artists,
            'album_image_url': album_image_url,
        })
    return processed_tracks

def process_playlists(playlists_data):
    processed_playlists = []
    for playlist in playlists_data.get('items', []):
        image_url = playlist['images'][0]['url'] if playlist.get('images') else None
        processed_playlists.append({'name': playlist['name'], 'image_url': image_url})
    return processed_playlists

@login_required
def send_duo_invitation(request):
    if request.method == 'POST':
        receiver_username = request.POST.get('receiver_username')
        try:
            receiver = User.objects.get(username=receiver_username)
            if receiver == request.user:
                messages.error(request, 'You cannot invite yourself.')
                return redirect('send_duo_invitation')
            existing_invitation = DuoWrapInvitation.objects.filter(
                sender=request.user, receiver=receiver, status='pending').first()
            if existing_invitation:
                messages.info(request, 'An invitation has already been sent to this user.')
                return redirect('send_duo_invitation')
            DuoWrapInvitation.objects.create(sender=request.user, receiver=receiver)
            messages.success(request, f'Invitation sent to {receiver.username}.')
            return redirect('wraps_list')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('send_duo_invitation')
    else:
        users = User.objects.exclude(username=request.user.username)
        context = {'users': users}
        return render(request, 'users/send_duo_invitation.html', context)

@login_required
def invitations_received(request):
    invitations = DuoWrapInvitation.objects.filter(receiver=request.user, status='pending')
    context = {'invitations': invitations}
    return render(request, 'users/invitations_received.html', context)

@login_required
@login_required
def accept_duo_invitation(request, invitation_id):
    invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, receiver=request.user, status='pending')
    invitation.status = 'accepted'
    invitation.save()
    messages.success(request, f'You have accepted the duo wrap invitation from {invitation.sender.username}.')
    return redirect('generate_duo_wrap', invitation.id)

@login_required
def decline_duo_invitation(request, invitation_id):
    invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, receiver=request.user, status='pending')
    invitation.status = 'declined'
    invitation.save()
    messages.success(request, f'You have declined the duo wrap invitation from {invitation.sender.username}.')
    return redirect('invitations_received')

def merge_spotify_data(data1, data2):
    items1 = data1.get('items', [])
    items2 = data2.get('items', [])
    combined_items = items1 + items2
    unique_items = {item['id']: item for item in combined_items}.values()
    return {'items': list(unique_items)}

def extract_names_from_items(items):
    return [item['name'] for item in items]

@login_required
def generate_duo_wrap(request, invitation_id):
    invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, status='accepted')
    users = [invitation.sender, invitation.receiver]

    # Fetch the latest wraps
    sender_wrap = SpotifyData.objects.filter(user=invitation.sender).order_by('-timestamp').first()
    receiver_wrap = SpotifyData.objects.filter(user=invitation.receiver).order_by('-timestamp').first()

    if not sender_wrap or not receiver_wrap:
        messages.error(request, 'Both users must have at least one wrap to generate a duo wrap.')
        return redirect('wraps_list')

    # Combine data
    combined_top_artists = merge_spotify_data(sender_wrap.top_artists, receiver_wrap.top_artists)
    combined_top_tracks = merge_spotify_data(sender_wrap.top_tracks, receiver_wrap.top_tracks)
    combined_playlists = merge_spotify_data(sender_wrap.playlists, receiver_wrap.playlists)

    # Generate insights using Gemini
    try:
        prompt = (
            "Based on the combined Spotify data of two users:\n"
            f"Top Artists: {extract_names_from_items(combined_top_artists.get('items', []))}\n"
            f"Top Tracks: {extract_names_from_items(combined_top_tracks.get('items', []))}\n"
            f"Playlists: {extract_names_from_items(combined_playlists.get('items', []))}\n\n"
            "Provide insights on how these two users' music tastes overlap and complement each other."
        )
        response = model.generate_content(prompt)
        insights = response.text.strip()
    except Exception as e:
        insights = "Insights could not be generated at this time."
        print(f"Error generating insights: {e}")

    # Save duo wrap
    duo_wrap = DuoSpotifyData.objects.create(
        combined_top_artists=combined_top_artists,
        combined_top_tracks=combined_top_tracks,
        combined_playlists=combined_playlists,
        insights=insights,
        timestamp=timezone.now()
    )
    duo_wrap.users.set(users)
    duo_wrap.save()

    # Process data
    context = {
        'duo_wrap': duo_wrap,
        'top_artists': process_artists(duo_wrap.combined_top_artists),
        'top_tracks': process_tracks(duo_wrap.combined_top_tracks),
        'playlists': process_playlists(duo_wrap.combined_playlists),
        'insights_html': markdown.markdown(insights) if insights else None,
    }

    return render(request, 'users/duo_wrap_detail.html', context)

@login_required
def duo_wrap_detail(request, duo_wrap_id):
    duo_wrap = get_object_or_404(DuoSpotifyData, id=duo_wrap_id, users=request.user)
    context = {
        'duo_wrap': duo_wrap,
        'top_artists': process_artists(duo_wrap.combined_top_artists),
        'top_tracks': process_tracks(duo_wrap.combined_top_tracks),
        'playlists': process_playlists(duo_wrap.combined_playlists),
        'insights_html': markdown.markdown(duo_wrap.insights) if duo_wrap.insights else None,
    }
    return render(request, 'users/duo_wrap_detail.html', context)
