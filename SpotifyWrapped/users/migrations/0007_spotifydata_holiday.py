# Generated by Django 4.2.16 on 2024-11-25 07:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_duowrapinvitation_duospotifydata'),
    ]

    operations = [
        migrations.AddField(
            model_name='spotifydata',
            name='holiday',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
