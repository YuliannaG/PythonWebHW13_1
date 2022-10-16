from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Category(models.Model):
    name = models.CharField(max_length=25, null=False)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user_id', 'name'], name='category of username')
        ]

    def __str__(self):
        return f"{self.name}:{self.user_id}"


class Expense(models.Model):
    sum = models.IntegerField(null=False)
    description = models.CharField(max_length=150, null=True, blank=True)
    # done = models.BooleanField(default=False)
    created = models.DateField(null=False)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.sum}:{self.category}"
