# from django.views import View
# from django.contrib.auth.views import LoginView
# from .forms import RegisterForm, LoginForm
# from django.urls import reverse_lazy
# from django.contrib.auth.views import PasswordResetView
# from django.contrib.messages.views import SuccessMessageMixin
# from .forms import RegisterForm
# from django.contrib.auth.models import User
# from django.shortcuts import render, redirect, get_object_or_404
# from django.contrib import messages
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth.views import PasswordChangeView
# import requests
# import google.generativeai as genai
# from django.conf import settings
# from django.utils import timezone
# from .models import SpotifyData, DuoWrapInvitation, DuoSpotifyData
# import base64
# import urllib.parse
# from .forms import UpdateUserForm, UpdateProfileForm
# import markdown  # Import the markdown library
# from datetime import datetime

# genai.configure(api_key=settings.GEMINI_API_KEY)
# model = genai.GenerativeModel("gemini-1.5-flash")

# def home(request):
#     return render(request, 'users/home.html')

# @login_required
# def spotify_login(request):
#     scopes = 'user-top-read playlist-read-private'
#     auth_url = 'https://accounts.spotify.com/authorize'
#     params = {
#         'client_id': settings.SPOTIFY_CLIENT_ID,
#         'response_type': 'code',
#         'redirect_uri': settings.SPOTIFY_REDIRECT_URI,
#         'scope': scopes,
#     }
#     url = f"{auth_url}?{urllib.parse.urlencode(params)}"
#     return redirect(url)

# @login_required
# def spotify_callback(request):
#     code = request.GET.get('code')
#     error = request.GET.get('error')
#     if error:
#         return render(request, 'error.html', {'error': error})

#     token_url = 'https://accounts.spotify.com/api/token'
#     headers = {
#         'Authorization': 'Basic ' + base64.b64encode(f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()).decode()
#     }
#     data = {
#         'grant_type': 'authorization_code',
#         'code': code,
#         'redirect_uri': settings.SPOTIFY_REDIRECT_URI,
#     }

#     response = requests.post(token_url, data=data, headers=headers)
#     if response.status_code != 200:
#         return render(request, 'error.html', {'error': 'Failed to retrieve access token.'})

#     tokens = response.json()
#     access_token = tokens['access_token']
#     refresh_token = tokens['refresh_token']
#     expires_in = tokens.get('expires_in')  # in seconds

#     # Save tokens in the user's profile
#     profile = request.user.profile
#     profile.spotify_access_token = access_token
#     profile.spotify_refresh_token = refresh_token
#     profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
#     profile.save()

#     return redirect('generate_data')

# @login_required
# def wraps_list(request):
#     wraps = SpotifyData.objects.filter(user=request.user).order_by('-timestamp')
#     duo_wraps = DuoSpotifyData.objects.filter(users=request.user).order_by('-timestamp')
#     context = {'wraps': wraps, 'duo_wraps': duo_wraps}
#     return render(request, 'users/wraps_list.html', context)

# @login_required
# def wrap_detail(request, wrap_id):
#     wrap = get_object_or_404(SpotifyData, id=wrap_id, user=request.user)

#     # Extract data from the wrap
#     top_artists = wrap.top_artists.get('items', [])
#     top_tracks = wrap.top_tracks.get('items', [])
#     playlists = wrap.playlists.get('items', [])

#     # Process artists to include image URLs
#     processed_top_artists = []
#     for artist in top_artists:
#         image_url = artist.get('images', [{}])[0].get('url') if artist.get('images') else None
#         processed_top_artists.append({
#             'name': artist.get('name', 'Unknown Artist'),
#             'image_url': image_url,
#         })

#     # Process tracks to include album image URLs
#     processed_top_tracks = []
#     for track in top_tracks:
#         album_image_url = track.get('album', {}).get('images', [{}])[0].get('url') if track.get('album') else None
#         artists = [artist.get('name', 'Unknown Artist') for artist in track.get('artists', [])]
#         # preview_url = track.get('preview_url', None)  # Safely get the preview_url
#         processed_top_tracks.append({
#             'name': track.get('name', 'Unknown Track'),
#             'artists': artists,
#             'album_image_url': album_image_url,
#             # 'preview_url': preview_url,  # Include preview_url in processed tracks
#         })

#     # Process playlists to include image URLs
#     processed_playlists = []
#     for playlist in playlists:
#         if playlist:  # Ensure playlist is not None
#             image_url = playlist.get('images', [{}])[0].get('url') if playlist.get('images') else None
#             processed_playlists.append({
#                 'name': playlist.get('name', 'Unknown Playlist'),
#                 'image_url': image_url,
#             })

#     # Convert Markdown insights to HTML
#     insights_html = markdown.markdown(wrap.insights) if wrap.insights else None

#     context = {
#         'wrap': wrap,
#         'insights_html': insights_html,  # Add insights_html to context
#         'top_artists': processed_top_artists,
#         'top_tracks': processed_top_tracks,
#         'playlists': processed_playlists,
#     }

#     return render(request, 'users/wrap_detail.html', context)

# def get_current_holiday():
#     today = timezone.now().date()
#     if today.month == 10 and today.day == 31:
#         return 'Halloween'
#     elif today.month == 12 and today.day == 25:
#         return 'Christmas'
#     else:
#         return None

# @login_required
# def generate_data(request):
#     profile = request.user.profile
#     access_token = profile.spotify_access_token
#     refresh_token = profile.spotify_refresh_token
#     token_expires = profile.spotify_token_expires

#     # If access token is expired, refresh it
#     if not access_token or not token_expires or token_expires <= timezone.now():
#         # Refresh the token
#         token_url = 'https://accounts.spotify.com/api/token'
#         headers = {
#             'Authorization': 'Basic ' + base64.b64encode(
#                 f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()
#             ).decode()
#         }
#         data = {
#             'grant_type': 'refresh_token',
#             'refresh_token': refresh_token,
#         }

#         response = requests.post(token_url, data=data, headers=headers)
#         if response.status_code != 200:
#             messages.error(request, 'Failed to refresh access token.')
#             return redirect('spotify_login')  # Or handle as needed

#         tokens = response.json()
#         access_token = tokens['access_token']
#         expires_in = tokens.get('expires_in')  # in seconds

#         # Update the profile with the new token and expiry
#         profile.spotify_access_token = access_token
#         profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
#         profile.save()

#     if not access_token:
#         return redirect('spotify_login')

#     headers = {
#         'Authorization': f'Bearer {access_token}'
#     }

#     # Fetch Top Artists
#     top_artists_url = 'https://api.spotify.com/v1/me/top/artists'
#     top_artists_response = requests.get(top_artists_url, headers=headers)
#     if top_artists_response.status_code != 200:
#         messages.error(request, 'Failed to fetch top artists.')
#         return redirect('wraps_list')
#     top_artists = top_artists_response.json()

#     # Fetch Top Tracks
#     top_tracks_url = 'https://api.spotify.com/v1/me/top/tracks'
#     top_tracks_response = requests.get(top_tracks_url, headers=headers)
#     if top_tracks_response.status_code != 200:
#         messages.error(request, 'Failed to fetch top tracks.')
#         return redirect('wraps_list')
#     top_tracks = top_tracks_response.json()

#     # Fetch Playlists
#     playlists_url = 'https://api.spotify.com/v1/me/playlists'
#     playlists_response = requests.get(playlists_url, headers=headers)
#     if playlists_response.status_code != 200:
#         messages.error(request, 'Failed to fetch playlists.')
#         return redirect('wraps_list')
#     playlists = playlists_response.json()

#     # Process data
#     processed_top_artists = process_artists(top_artists)
#     processed_top_tracks = process_tracks(top_tracks)
#     processed_playlists = process_playlists(playlists)

#     # Limit to Top 5 Tracks
#     processed_top_tracks = processed_top_tracks[:5]

#     # Determine if today is a holiday
#     holiday = get_current_holiday()

#     # Generate insights using your model (e.g., OpenAI)
#     try:
#         if holiday:
#             prompt = (
#                 f"Today is {holiday}! Based on the following Spotify data:\n"
#                 f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
#                 f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n"
#                 f"Playlists: {[playlist['name'] for playlist in processed_playlists]}\n\n"
#                 f"Provide {holiday}-themed insights on how someone who listens to this kind of music might celebrate {holiday}."
#             )
#         else:
#             prompt = (
#                 "Based on the following Spotify data:\n"
#                 f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
#                 f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n"
#                 f"Playlists: {[playlist['name'] for playlist in processed_playlists]}\n\n"
#                 "Provide insights on how someone who listens to this kind of music tends to act, think, and dress."
#             )
#         response = model.generate_content(prompt)
#         insights = response.text.strip()
#     except Exception as e:
#         insights = "Insights could not be generated at this time."
#         print(f"Error generating insights: {e}")  # Log the error for debugging

#     insights_html = markdown.markdown(insights)

#     # Save data with timestamp, insights, and holiday
#     wrap = SpotifyData.objects.create(
#         user=request.user,
#         top_artists=top_artists,
#         top_tracks=top_tracks,
#         playlists=playlists,
#         insights=insights,
#         timestamp=timezone.now(),
#         holiday=holiday
#     )

#     # Prepare context for the template
#     context = {
#         'wrap': wrap,
#         'insights_html': insights_html,
#         'top_artists': processed_top_artists,
#         'top_tracks': processed_top_tracks,
#         'playlists': processed_playlists,
#         'holiday': holiday,
#     }

#     # Render the 'wrap_detail.html' template
#     return render(request, 'users/wrap_detail.html', context)

# class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
#     template_name = 'users/password_reset.html'
#     email_template_name = 'users/password_reset_email.html'
#     subject_template_name = 'users/password_reset_subject.txt'
#     success_message = "We've emailed you instructions for setting your password, " \
#                       "if an account exists with the email you entered. You should receive them shortly." \
#                       " If you don't receive an email, " \
#                       "please make sure you've entered the address you registered with, and check your spam folder."
#     success_url = reverse_lazy('users-home')

# class RegisterView(View):
#     form_class = RegisterForm
#     initial = {'key': 'value'}
#     template_name = 'users/register.html'

#     def dispatch(self, request, *args, **kwargs):
#         if request.user.is_authenticated:
#             return redirect(to='/')
#         return super(RegisterView, self).dispatch(request, *args, **kwargs)

#     def get(self, request, *args, **kwargs):
#         form = self.form_class(initial=self.initial)
#         return render(request, self.template_name, {'form': form})

#     def post(self, request, *args, **kwargs):
#         form = self.form_class(request.POST)

#         if form.is_valid():
#             form.save()
#             username = form.cleaned_data.get('username')
#             messages.success(request, f'Account created for {username}')
#             return redirect(to='/')

#         return render(request, self.template_name, {'form': form})

# class CustomLoginView(LoginView):
#     form_class = LoginForm

#     def form_valid(self, form):
#         remember_me = form.cleaned_data.get('remember_me')

#         if not remember_me:
#             self.request.session.set_expiry(0)
#             self.request.session.modified = True

#         return super(CustomLoginView, self).form_valid(form)

# @login_required
# def profile(request):
#     if request.method == 'POST':
#         user_form = UpdateUserForm(request.POST, instance=request.user)
#         profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

#         if user_form.is_valid() and profile_form.is_valid():
#             user_form.save()
#             profile_form.save()
#             messages.success(request, 'Your profile is updated successfully')
#             return redirect(to='users-profile')
#     else:
#         user_form = UpdateUserForm(instance=request.user)
#         profile_form = UpdateProfileForm(instance=request.user.profile)

#     return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})

# class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
#     template_name = 'users/change_password.html'
#     success_message = "Successfully Changed Your Password"
#     success_url = reverse_lazy('users-home')

# def process_artists(artists_data):
#     processed_artists = []
#     for artist in artists_data.get('items', []):
#         image_url = artist['images'][0]['url'] if artist.get('images') else None
#         processed_artists.append({'name': artist['name'], 'image_url': image_url})
#     return processed_artists

# def process_tracks(tracks_data):
#     processed_tracks = []
#     for track in tracks_data.get('items', []):
#         album_image_url = track['album']['images'][0]['url'] if track['album'].get('images') else None
#         artists = [artist['name'] for artist in track['artists']]
#         # preview_url = track.get('preview_url', '').strip()  # Fetch the preview URL
#         processed_tracks.append({
#             'name': track['name'],
#             'artists': artists,
#             'album_image_url': album_image_url,
#             # 'preview_url': preview_url,  # Include the preview URL
#         })
#     return processed_tracks

# def process_playlists(playlists_data):
#     processed_playlists = []
#     for playlist in playlists_data.get('items', []):
#         if playlist:  # Ensure playlist is not None
#             image_url = playlist.get('images', [{}])[0].get('url') if playlist.get('images') else None
#             processed_playlists.append({'name': playlist.get('name', 'Unknown Playlist'), 'image_url': image_url})
#     return processed_playlists


# @login_required
# def send_duo_invitation(request):
#     if request.method == 'POST':
#         receiver_username = request.POST.get('receiver_username')
#         try:
#             receiver = User.objects.get(username=receiver_username)
#             if receiver == request.user:
#                 messages.error(request, 'You cannot invite yourself.')
#                 return redirect('send_duo_invitation')
#             existing_invitation = DuoWrapInvitation.objects.filter(
#                 sender=request.user, receiver=receiver, status='pending').first()
#             if existing_invitation:
#                 messages.info(request, 'An invitation has already been sent to this user.')
#                 return redirect('send_duo_invitation')
#             DuoWrapInvitation.objects.create(sender=request.user, receiver=receiver)
#             messages.success(request, f'Invitation sent to {receiver.username}.')
#             return redirect('wraps_list')
#         except User.DoesNotExist:
#             messages.error(request, 'User not found.')
#             return redirect('send_duo_invitation')
#     else:
#         users = User.objects.exclude(username=request.user.username)
#         context = {'users': users}
#         return render(request, 'users/send_duo_invitation.html', context)

# @login_required
# def invitations_received(request):
#     invitations = DuoWrapInvitation.objects.filter(receiver=request.user, status='pending')
#     context = {'invitations': invitations}
#     return render(request, 'users/invitations_received.html', context)

# @login_required
# def accept_duo_invitation(request, invitation_id):
#     invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, receiver=request.user, status='pending')
#     invitation.status = 'accepted'
#     invitation.save()
#     messages.success(request, f'You have accepted the duo wrap invitation from {invitation.sender.username}.')
#     return redirect('generate_duo_wrap', invitation.id)

# @login_required
# def decline_duo_invitation(request, invitation_id):
#     invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, receiver=request.user, status='pending')
#     invitation.status = 'declined'
#     invitation.save()
#     messages.success(request, f'You have declined the duo wrap invitation from {invitation.sender.username}.')
#     return redirect('invitations_received')

# def merge_spotify_data(data1, data2):
#     items1 = data1.get('items', [])
#     items2 = data2.get('items', [])
#     combined_items = items1 + items2
#     unique_items = {item['id']: item for item in combined_items}.values()
#     return {'items': list(unique_items)}

# def extract_names_from_items(items):
#     return [item['name'] for item in items]

# @login_required
# def generate_duo_wrap(request, invitation_id):
#     invitation = get_object_or_404(DuoWrapInvitation, id=invitation_id, status='accepted')
#     users = [invitation.sender, invitation.receiver]

#     # Fetch the latest wraps
#     sender_wrap = SpotifyData.objects.filter(user=invitation.sender).order_by('-timestamp').first()
#     receiver_wrap = SpotifyData.objects.filter(user=invitation.receiver).order_by('-timestamp').first()

#     if not sender_wrap or not receiver_wrap:
#         messages.error(request, 'Both users must have at least one wrap to generate a duo wrap.')
#         return redirect('wraps_list')

#     # Combine data
#     combined_top_artists = merge_spotify_data(sender_wrap.top_artists, receiver_wrap.top_artists)
#     combined_top_tracks = merge_spotify_data(sender_wrap.top_tracks, receiver_wrap.top_tracks)
#     combined_playlists = merge_spotify_data(sender_wrap.playlists, receiver_wrap.playlists)

#     # Process combined top tracks and limit to top 5
#     processed_top_tracks = process_tracks(combined_top_tracks)
#     processed_top_tracks = processed_top_tracks[:5]  # Get top 5 tracks

#     # Process other combined data
#     processed_top_artists = process_artists(combined_top_artists)
#     processed_playlists = process_playlists(combined_playlists)

#     # Generate insights using Gemini
#     try:
#         prompt = (
#             "Based on the combined Spotify data of two users:\n"
#             f"Top Artists: {extract_names_from_items(combined_top_artists.get('items', []))}\n"
#             f"Top Tracks: {extract_names_from_items(combined_top_tracks.get('items', []))}\n"
#             f"Playlists: {extract_names_from_items(combined_playlists.get('items', []))}\n\n"
#             "Provide insights on how these two users' music tastes overlap and complement each other."
#         )
#         response = model.generate_content(prompt)
#         insights = response.text.strip()
#     except Exception as e:
#         insights = "Insights could not be generated at this time."
#         print(f"Error generating insights: {e}")

#     # Save duo wrap
#     duo_wrap = DuoSpotifyData.objects.create(
#         combined_top_artists=combined_top_artists,
#         combined_top_tracks=combined_top_tracks,
#         combined_playlists=combined_playlists,
#         insights=insights,
#         timestamp=timezone.now()
#     )
#     duo_wrap.users.set(users)
#     duo_wrap.save()

#     # Process data for rendering
#     context = {
#         'duo_wrap': duo_wrap,
#         'top_artists': processed_top_artists,
#         'top_tracks': processed_top_tracks,
#         'playlists': processed_playlists,
#         'insights_html': markdown.markdown(insights) if insights else None,
#     }

#     return render(request, 'users/duo_wrap_detail.html', context)

# @login_required
# def duo_wrap_detail(request, duo_wrap_id):
#     duo_wrap = get_object_or_404(DuoSpotifyData, id=duo_wrap_id, users=request.user)
#     context = {
#         'duo_wrap': duo_wrap,
#         'top_artists': process_artists(duo_wrap.combined_top_artists),
#         'top_tracks': process_tracks(duo_wrap.combined_top_tracks),
#         'playlists': process_playlists(duo_wrap.combined_playlists),
#         'insights_html': markdown.markdown(duo_wrap.insights) if duo_wrap.insights else None,
#     }
#     return render(request, 'users/duo_wrap_detail.html', context)


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
from datetime import datetime
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

@login_required
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

    # Process tracks to include album image URLs and preview URLs
    processed_top_tracks = []
    for track in top_tracks:
        album_image_url = track['album']['images'][0]['url'] if track['album'].get('images') else None
        artists = [artist['name'] for artist in track['artists']]
        #preview_url = track.get('preview_url', None)  # Safely get the preview_url
        processed_top_tracks.append({
            'name': track['name'],
            'artists': artists,
            'album_image_url': album_image_url,
            '#preview_url': preview_url,  # Include preview_url in processed tracks
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
    insights_html = markdown.markdown(wrap.insights) if wrap.insights else None



    context = {
        'wrap': wrap,
        'insights_html': insights_html,  # Add insights_html to context
        'top_artists': processed_top_artists,
        'top_tracks': processed_top_tracks,
        'playlists': processed_playlists,
    }

    return render(request, 'users/wrap_detail.html', context)


def get_current_holiday():
    today = timezone.now().date()
    
    if today.month == 10 and today.day == 31:
        return 'Halloween'
    elif today.month == 12 and today.day == 25:
        return 'Christmas'
    else:
        return None
    
import urllib.parse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
import requests
import markdown
import base64

@login_required
def generate_data(request):
    profile = request.user.profile
    access_token = profile.spotify_access_token
    refresh_token = profile.spotify_refresh_token
    token_expires = profile.spotify_token_expires

    # Refresh Spotify token if expired
    if not access_token or not token_expires or token_expires <= timezone.now():
        token_url = 'https://accounts.spotify.com/api/token'
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(
                f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()
            ).decode()
        }
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        response = requests.post(token_url, data=data, headers=headers)
        if response.status_code != 200:
            messages.error(request, 'Failed to refresh access token.')
            return redirect('spotify_login')

        tokens = response.json()
        access_token = tokens['access_token']
        expires_in = tokens.get('expires_in')

        profile.spotify_access_token = access_token
        profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
        profile.save()

    headers = {'Authorization': f'Bearer {access_token}'}

    # Fetch Top Artists
    top_artists_url = 'https://api.spotify.com/v1/me/top/artists?limit=50'
    top_artists_response = requests.get(top_artists_url, headers=headers)
    if top_artists_response.status_code != 200:
        messages.error(request, 'Failed to fetch top artists.')
        return redirect('wraps_list')
    top_artists = top_artists_response.json()

    # Fetch Top Tracks
    top_tracks_url = 'https://api.spotify.com/v1/me/top/tracks?limit=50'
    top_tracks_response = requests.get(top_tracks_url, headers=headers)
    if top_tracks_response.status_code != 200:
        messages.error(request, 'Failed to fetch top tracks.')
        return redirect('wraps_list')
    top_tracks = top_tracks_response.json()

    # Fetch Playlists
    playlists_url = 'https://api.spotify.com/v1/me/playlists?limit=50'
    playlists_response = requests.get(playlists_url, headers=headers)
    if playlists_response.status_code != 200:
        messages.error(request, 'Failed to fetch playlists.')
        return redirect('wraps_list')
    playlists = playlists_response.json()

    # Process data
    processed_top_artists = process_artists(top_artists)
    processed_top_tracks = process_tracks(top_tracks)
    processed_playlists = process_playlists(playlists)

    # Limit to Top 5 Tracks
    processed_top_tracks_for_display = processed_top_tracks[:5]

    # Determine if today is a holiday
    holiday = get_current_holiday()

    # Generate insights using your model
    try:
        if holiday:
            prompt = (
                f"Today is {holiday}! Based on your listening history:\n"
                f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
                f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n\n"
                f"Provide {holiday}-themed insights on how someone who listens to this kind of music might celebrate {holiday}."
            )
        else:
            prompt = (
                f"Based on your listening history:\n"
                f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
                f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n\n"
                "Provide insights on how someone who listens to this kind of music tends to act, think, and dress."
            )
        response = model.generate_content(prompt)
        insights = response.text.strip()
    except Exception as e:
        insights = "Insights could not be generated at this time."
        print(f"Error generating insights: {e}")

    insights_html = markdown.markdown(insights)

    # Save data with timestamp, insights, and holiday
    wrap = SpotifyData.objects.create(
        user=request.user,
        top_artists=top_artists,
        top_tracks=top_tracks,
        playlists=playlists,
        insights=insights,
        timestamp=timezone.now(),
        holiday=holiday,
    )

    # Prepare data for sharing
    # Ensure there are at least 3 top artists and tracks
    top_artists_names = [artist['name'] for artist in processed_top_artists][:3]
    top_tracks_names = [track['name'] for track in processed_top_tracks][:3]

    # Construct the share message
    tweet_message = (
        f"I just created my Spotify Wrapped! 🎶\n"
        f"Top Artists: {', '.join(top_artists_names)}\n"
        f"Top Tracks: {', '.join(top_tracks_names)}\n"
        "Check out your own at http://127.0.0.1:8000/generate/! #SpotifyWrapped"
    )

    # URL-encode the message
    encoded_tweet_message = urllib.parse.quote(tweet_message)

    # Construct Twitter share URL
    twitter_url = f"https://twitter.com/intent/tweet?text={encoded_tweet_message}"

    # Construct LinkedIn share link
    linkedin_message = tweet_message.replace("\n", " ")

    linkedin_url = (
        f"https://www.linkedin.com/sharing/share-offsite/?"
        f"url={urllib.parse.quote('http://127.0.0.1:8000/generate/')}&"
        f"summary={urllib.parse.quote(linkedin_message)}"
    )

    # Prepare context for the template
    context = {
        'wrap': wrap,
        'insights_html': insights_html,
        'top_artists': processed_top_artists,
        'top_tracks': processed_top_tracks_for_display,  # Use limited tracks for display
        'playlists': processed_playlists,
        'holiday': holiday,
        'twitter_url': twitter_url,
        'linkedin_url': linkedin_url,
    }

    # Render the 'wrap_detail.html' template
    return render(request, 'users/wrap_detail.html', context)


# @login_required
# def generate_data(request):
#     profile = request.user.profile
#     access_token = profile.spotify_access_token
#     refresh_token = profile.spotify_refresh_token
#     token_expires = profile.spotify_token_expires

#     # If access token is expired, refresh it
#     if not access_token or not token_expires or token_expires <= timezone.now():
#         # Refresh the token
#         token_url = 'https://accounts.spotify.com/api/token'
#         headers = {
#             'Authorization': 'Basic ' + base64.b64encode(
#                 f"{settings.SPOTIFY_CLIENT_ID}:{settings.SPOTIFY_CLIENT_SECRET}".encode()
#             ).decode()
#         }
#         data = {
#             'grant_type': 'refresh_token',
#             'refresh_token': refresh_token,
#         }

#         response = requests.post(token_url, data=data, headers=headers)
#         if response.status_code != 200:
#             messages.error(request, 'Failed to refresh access token.')
#             return redirect('spotify_login')  # Or handle as needed

#         tokens = response.json()
#         access_token = tokens['access_token']
#         expires_in = tokens.get('expires_in')  # in seconds

#         # Update the profile with the new token and expiry
#         profile.spotify_access_token = access_token
#         profile.spotify_token_expires = timezone.now() + timezone.timedelta(seconds=expires_in)
#         profile.save()

#     if not access_token:
#         return redirect('spotify_login')

#     headers = {
#         'Authorization': f'Bearer {access_token}'
#     }

#     if request.method == 'POST':
#         form = TimeRangeForm(request.POST)
#         if form.is_valid():
#             time_range = form.cleaned_data['time_range']

#             # Fetch Top Artists with time_range
#             top_artists_url = f'https://api.spotify.com/v1/me/top/artists?time_range={time_range}&limit=50'
#             top_artists_response = requests.get(top_artists_url, headers=headers)
#             if top_artists_response.status_code != 200:
#                 messages.error(request, 'Failed to fetch top artists.')
#                 return redirect('wraps_list')
#             top_artists = top_artists_response.json()

#             # Fetch Top Tracks with time_range
#             top_tracks_url = f'https://api.spotify.com/v1/me/top/tracks?time_range={time_range}&limit=50'
#             top_tracks_response = requests.get(top_tracks_url, headers=headers)
#             if top_tracks_response.status_code != 200:
#                 messages.error(request, 'Failed to fetch top tracks.')
#                 return redirect('wraps_list')
#             top_tracks = top_tracks_response.json()

#             # Fetch Playlists (no time_range parameter)
#             playlists_url = 'https://api.spotify.com/v1/me/playlists?limit=50'
#             playlists_response = requests.get(playlists_url, headers=headers)
#             if playlists_response.status_code != 200:
#                 messages.error(request, 'Failed to fetch playlists.')
#                 return redirect('wraps_list')
#             playlists = playlists_response.json()

#             # Process data
#             processed_top_artists = process_artists(top_artists)
#             processed_top_tracks = process_tracks(top_tracks)
#             processed_playlists = process_playlists(playlists)

#             # Limit to Top 5 Tracks for playback
#             processed_top_tracks = processed_top_tracks[:5]

#             # Determine if today is a holiday
#             holiday = get_current_holiday()

#             # Generate insights using your model (e.g., OpenAI)
#             try:
#                 if holiday:
#                     prompt = (
#                         f"Today is {holiday}! Based on the following Spotify data:\n"
#                         f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
#                         f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n"
#                         f"Playlists: {[playlist['name'] for playlist in processed_playlists]}\n\n"
#                         f"Provide {holiday}-themed insights on how someone who listens to this kind of music might celebrate {holiday}."
#                     )
#                 else:
#                     prompt = (
#                         f"Based on the following Spotify data (Time Range: {time_range}):\n"
#                         f"Top Artists: {[artist['name'] for artist in processed_top_artists]}\n"
#                         f"Top Tracks: {[track['name'] for track in processed_top_tracks]}\n"
#                         f"Playlists: {[playlist['name'] for playlist in processed_playlists]}\n\n"
#                         "Provide insights on how someone who listens to this kind of music tends to act, think, and dress."
#                     )
#                 # Replace 'model.generate_content' with your actual method to generate insights
#                 response = model.generate_content(prompt)
#                 insights = response.text.strip()
#             except Exception as e:
#                 insights = "Insights could not be generated at this time."
#                 print(f"Error generating insights: {e}")  # Log the error for debugging

#             insights_html = markdown.markdown(insights)

#             # Save data with timestamp, insights, holiday, and time_range
#             wrap = SpotifyData.objects.create(
#                 user=request.user,
#                 top_artists=top_artists,
#                 top_tracks=top_tracks,
#                 playlists=playlists,
#                 insights=insights,
#                 timestamp=timezone.now(),
#                 holiday=holiday,
#                 time_range=time_range,  # Save the time range
#             )

#             # Prepare context for the template
#             context = {
#                 'wrap': wrap,                          # Pass the 'wrap' object to the template
#                 'insights_html': insights_html,        # Pass the converted HTML
#                 'top_artists': processed_top_artists,  # Processed data for display
#                 'top_tracks': processed_top_tracks,    # Processed data with 'preview_url's
#                 'playlists': processed_playlists,      # Processed data for display
#                 'holiday': holiday,                    # Pass the holiday to the template
#             }

#             # Render the 'wrap_detail.html' template
#             return render(request, 'users/wrap_detail.html', context)
#     else:
#         form = TimeRangeForm()

#     # If GET request, display the time range selection form
#     return render(request, 'users/generate.html', {'form': form})




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
        #preview_url = track.get('preview_url', '').strip() # Fetch the preview URL
        processed_tracks.append({
            'name': track['name'],
            'artists': artists,
            'album_image_url': album_image_url,
            #'preview_url': preview_url,  # Include the preview URL
        })
    return processed_tracks

def process_playlists(playlists_data):
    processed_playlists = []
    for playlist in playlists_data.get('items', []):
        if playlist:
            images = playlist.get('images', [])
            image_url = images[0].get('url') if images else None
            name = playlist.get('name', 'Unknown Playlist')
            processed_playlists.append({'name': name, 'image_url': image_url})
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

    # Process combined top tracks and limit to top 5
    processed_top_tracks = process_tracks(combined_top_tracks)
    processed_top_tracks = processed_top_tracks[:5]  # Get top 5 tracks

    # Process other combined data
    processed_top_artists = process_artists(combined_top_artists)
    processed_playlists = process_playlists(combined_playlists)

    # Generate insights using Gemini
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

    # Process data for rendering
    context = {
        'duo_wrap': duo_wrap,
        'top_artists': processed_top_artists,
        'top_tracks': processed_top_tracks,  # Top 5 tracks for playback
        'playlists': processed_playlists,
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


