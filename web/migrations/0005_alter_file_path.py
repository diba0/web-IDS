# Generated by Django 4.0.3 on 2022-04-10 04:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0004_alter_file_path'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='path',
            field=models.CharField(max_length=100),
        ),
    ]
