from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user_sessions', '0004_alter_session_expire_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='session',
            name='user_version',
            field=models.PositiveIntegerField(db_index=True, default=0),
        ),
        migrations.CreateModel(
            name='SessionRotation',
            fields=[
                (
                    'old_session_key',
                    models.CharField(max_length=40, primary_key=True,
                                     serialize=False),
                ),
                (
                    'new_session_key',
                    models.CharField(blank=True, db_index=True, max_length=40,
                                     null=True),
                ),
                ('user_version', models.PositiveIntegerField(default=0)),
                (
                    'outcome',
                    models.CharField(
                        choices=[
                            ('accepted', 'Accepted'),
                            ('rejected', 'Rejected'),
                            ('revoked', 'Revoked'),
                        ],
                        default='accepted', max_length=16,
                    ),
                ),
                (
                    'phase',
                    models.CharField(default='rotation', max_length=32),
                ),
                (
                    'stage',
                    models.CharField(blank=True, default='commit', max_length=32),
                ),
                (
                    'rejection_phase',
                    models.CharField(blank=True, default='', max_length=32),
                ),
                (
                    'detail',
                    models.CharField(blank=True, default='', max_length=255),
                ),
                ('grace_until', models.DateTimeField(blank=True, db_index=True,
                                                     null=True)),
                ('rejected_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'user',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'ordering': ('-created_at',),
            },
        ),
    ]
