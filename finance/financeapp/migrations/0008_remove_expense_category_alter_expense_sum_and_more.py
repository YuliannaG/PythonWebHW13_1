# Generated by Django 4.1.2 on 2022-10-19 18:58

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('financeapp', '0007_remove_expense_category_expense_category'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='expense',
            name='category',
        ),
        migrations.AlterField(
            model_name='expense',
            name='sum',
            field=models.FloatField(),
        ),
        migrations.AddField(
            model_name='expense',
            name='category',
            field=models.ForeignKey(default=0, on_delete=django.db.models.deletion.CASCADE, to='financeapp.category'),
            preserve_default=False,
        ),
    ]
