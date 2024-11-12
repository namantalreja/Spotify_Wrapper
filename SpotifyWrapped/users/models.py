from django.db import models
from django.contrib.auth.models import User
from PIL import Image

# Extending User Model Using a One-To-One Link
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    avatar = models.ImageField(default='default.jpg', upload_to='profile_images')
    bio = models.TextField()

    def __str__(self):
        return self.user.username

    def save(self, *args, **kwargs):
        super().save()

        img = Image.open(self.avatar.path)

        if img.height > 100 or img.width > 100:
            new_img = (100, 100)
            img.thumbnail(new_img)
            img.save(self.avatar.path)

#ab
class WrappedSummary(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    top_tracks = models.JSONField()  # Store list of top track names
    top_artists = models.JSONField()  # Store list of top artist names
    playlists = models.JSONField()  # Store list of playlist names
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s Wrapped on {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"


