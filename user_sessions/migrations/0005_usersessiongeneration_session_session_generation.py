import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('user_sessions', '0004_alter_session_expire_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSessionGeneration',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='session_generation', serialize=False, to=settings.AUTH_USER_MODEL)),
                ('generation', models.PositiveIntegerField(default=1)),
            ],
        ),
        migrations.AddField(
            model_name='session',
            name='session_generation',
            field=models.PositiveIntegerField(default=1),
        ),
    ]
