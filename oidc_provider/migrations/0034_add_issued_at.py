import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("oidc_provider", "0033_token_lookup_hash_part_3_of_3"),
    ]

    operations = [
        migrations.AddField(
            model_name="code",
            name="issued_at",
            field=models.DateTimeField(
                default=django.utils.timezone.now, verbose_name="Issue Date"
            ),
        ),
        migrations.AddField(
            model_name="token",
            name="issued_at",
            field=models.DateTimeField(
                default=django.utils.timezone.now, verbose_name="Issue Date"
            ),
        ),
        migrations.AddField(
            model_name="userconsent",
            name="issued_at",
            field=models.DateTimeField(
                default=django.utils.timezone.now, verbose_name="Issue Date"
            ),
        ),
    ]
