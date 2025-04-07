from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from .models import Task

@receiver(post_save, sender=Task)
def create_task_permissions(sender, instance, created, **kwargs):
    if created:
        content_type = ContentType.objects.get_for_model(Task)

        view_perm = Permission.objects.create(
            codename=f'view_task_{instance.id}',
            name=f'Puede ver la tarea {instance.name}',
            content_type=content_type
        )

        edit_perm = Permission.objects.create(
            codename=f'edit_task_{instance.id}',
            name=f'Puede editar la tarea {instance.name}',
            content_type=content_type
        )

        delete_perm = Permission.objects.create(
            codename=f'delete_task_{instance.id}',
            name=f'Puede eliminar la tarea {instance.name}',
            content_type=content_type
        )

        print(f"Permisos creados para la tarea {instance.name}: {view_perm.codename}, {edit_perm.codename}, {delete_perm.codename}")
