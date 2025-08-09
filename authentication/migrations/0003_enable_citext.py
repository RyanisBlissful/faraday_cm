from django.db import migrations
from django.contrib.postgres.operations import CITextExtension

class Migration(migrations.Migration):
    dependencies = [
        ('authentication', '0002_remove_customuser_username'),
    ]

    operations = [
        CITextExtension(),
    ]
