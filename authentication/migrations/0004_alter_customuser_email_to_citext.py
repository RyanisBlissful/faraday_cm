from django.db import migrations
import django.contrib.postgres.fields.citext

class Migration(migrations.Migration):
    dependencies = [
        ('authentication', '0003_enable_citext'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='email',
            field=django.contrib.postgres.fields.citext.CIEmailField(max_length=254, unique=True),
        ),
    ]
