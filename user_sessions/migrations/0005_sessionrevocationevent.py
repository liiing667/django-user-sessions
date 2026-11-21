from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_sessions', '0004_alter_session_expire_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='SessionRevocationEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name='ID')),
                ('batch_id', models.CharField(db_index=True, max_length=64)),
                ('session_key', models.CharField(db_index=True, max_length=40)),
                ('outcome', models.CharField(
                    choices=[('retained', 'Retained'),
                             ('revoked', 'Revoked'),
                             ('failed', 'Failed')],
                    max_length=16)),
                ('stage', models.CharField(
                    choices=[('query', 'Query'),
                             ('delete', 'Delete'),
                             ('commit', 'Commit')],
                    max_length=16)),
                ('detail', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ('id',),
            },
        ),
        migrations.AddIndex(
            model_name='sessionrevocationevent',
            index=models.Index(
                fields=['batch_id', 'session_key'],
                name='user_session_batch_session_idx',
            ),
        ),
    ]
