# Generated by Django 4.2.16 on 2024-11-12 19:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_alter_spotifydata_timestamp"),
    ]

    operations = [
        migrations.AddField(
            model_name="spotifydata",
            name="insights",
            field=models.TextField(blank=True, null=True),
        ),
    ]
