# -*- coding: utf-8 -*-

from django import VERSION
from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.encoding import force_str


class BlacklistedTokenManager(models.Manager):
    def delete_stale_tokens(self):
        return self.filter(expires_at__lt=timezone.now()).delete()


class BlacklistedToken(models.Model):
    class Meta:
        if VERSION >= (2, 2):
            constraints = [
                models.CheckConstraint(
                    check=Q(token_id__isnull=False) | Q(token__isnull=False),
                    name='token_or_id_not_null',
                )
            ]

    # This holds the original token id for refreshed tokens with ids
    token_id = models.UUIDField(db_index=True, null=True)
    token = models.TextField(db_index=True, null=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    expires_at = models.DateTimeField(db_index=True)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    objects = BlacklistedTokenManager()

    def __str__(self):
        return 'Blacklisted token - {} - {}'.format(self.user, self.token)


    @staticmethod
    def is_blocked(token):
        return BlacklistedToken.objects.filter(token=force_str(token)).exists()
