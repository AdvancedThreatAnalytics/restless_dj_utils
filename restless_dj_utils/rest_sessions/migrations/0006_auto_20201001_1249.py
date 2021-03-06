# Generated by Django 2.2.16 on 2020-10-01 12:49

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('rest_sessions', '0005_apisession_description'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='apisession',
            options={
                'get_latest_by': ['created'],
                'ordering': ['-created'],
                'verbose_name': 'API session',
                'verbose_name_plural': 'API sessions'
            },
        ),
        migrations.AlterModelOptions(
            name='apisessionaccess',
            options={
                'get_latest_by': ['created'],
                'ordering': ['-created'],
                'verbose_name': 'API session access',
                'verbose_name_plural': 'API session accesses'
            },
        ),
    ]
