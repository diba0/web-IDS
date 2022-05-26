from django.utils import timezone
from django.db import models

# Create your models here.

class File(models.Model):
    name = models.CharField(max_length=50, primary_key=True)
    path = models.CharField(max_length=100)
    upload_time = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name