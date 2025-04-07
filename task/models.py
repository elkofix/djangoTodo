from django.db import models

class Status(models.Model):
    id = models.AutoField(
        primary_key=True,
        null=False,
        blank=False,
    )

    name = models.CharField(
        max_length=100,
        unique=True,
        null=False,
        blank=False,
    )

    def __str__(self):
        return self.name
    
class Task(models.Model):
    id = models.AutoField(
        primary_key=True,
        null=False,
        blank=False,
    )

    name = models.CharField(
        max_length=100,
        null=False,
        blank=False,
    )

    description = models.TextField(
        null=True,
        blank=True,
    )
    
    created_at = models.DateTimeField(
        auto_now_add=True,
        null=False,
        blank=False,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        null=False,
        blank=False,
    )
    
    deadline = models.DateTimeField(
        null=True,
        blank=True,
    )

    status_id = models.ForeignKey(
        Status,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
    )

    def __str__(self):
        return self.name