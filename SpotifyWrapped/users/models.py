from django.db import models
from django.contrib.auth.models import User
from PIL import Image

# Extending User Model Using a One-To-One Link
# models.py

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    avatar = models.ImageField(default='default.jpg', upload_to='profile_images')
    bio = models.TextField()
    spotify_access_token = models.CharField(max_length=255, blank=True, null=True)
    spotify_refresh_token = models.CharField(max_length=255, blank=True, null=True)
    spotify_token_expires = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.user.username

    def save(self, *args, **kwargs):
        super().save()

        img = Image.open(self.avatar.path)

        if img.height > 100 or img.width > 100:
            new_img = (100, 100)
            img.thumbnail(new_img)
            img.save(self.avatar.path)

            
class SpotifyData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    top_artists = models.JSONField()
    top_tracks = models.JSONField()
    playlists = models.JSONField()
    insights = models.TextField(blank=True, null=True)  # New field for insights
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.timestamp}"
    
    
class DuoWrapInvitation(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
    ]
    sender = models.ForeignKey(User, related_name='sent_duo_invitations', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_duo_invitations', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.username} invited {self.receiver.username} - {self.status}"

class DuoSpotifyData(models.Model):
    users = models.ManyToManyField(User)
    combined_top_artists = models.JSONField()
    combined_top_tracks = models.JSONField()
    combined_playlists = models.JSONField()
    insights = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        usernames = ', '.join([user.username for user in self.users.all()])
        return f"Duo wrap: {usernames} - {self.timestamp}"