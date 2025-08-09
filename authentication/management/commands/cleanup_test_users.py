from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = "Deletes users by email or domain"

    def add_arguments(self, parser):
        parser.add_argument(
            'identifiers',
            nargs='+',
            type=str,
            help='Email addresses or domains (e.g., @example.com) to delete users by'
        )

    def handle(self, *args, **options):
        identifiers = options['identifiers']
        total_deleted = 0

        for identifier in identifiers:
            if identifier.startswith('@'):
                # Domain-based deletion
                users_to_delete = User.objects.filter(email__iendswith=identifier)
            else:
                # Exact email match
                users_to_delete = User.objects.filter(email=identifier)

            deleted_count, _ = users_to_delete.delete()
            if deleted_count:
                self.stdout.write(self.style.SUCCESS(f"✅ Deleted {deleted_count} user(s) for '{identifier}'"))
                total_deleted += deleted_count
            else:
                self.stdout.write(self.style.WARNING(f"⚠️ No user found for '{identifier}'"))

        self.stdout.write(self.style.NOTICE(f"🧹 Total users deleted: {total_deleted}"))
