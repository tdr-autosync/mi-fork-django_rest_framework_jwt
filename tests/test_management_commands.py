# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from sys import version

if version[0] == '2':
    import mock
else:
    from unittest import mock

from django.conf import settings
from pytest import raises

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.management.commands.obtain_token import Command


def test_obtain_token_command_should_fail_in_DEBUG_False(
        monkeypatch, user
):
    stdout = mock.Mock()
    command = Command()
    monkeypatch.setattr(command, "stdout", stdout)

    monkeypatch.setattr(settings, "DEBUG", False)
    with raises(SystemExit):
        command.handle(user.pk)


def test_obtain_token_command_should_produce_valid_token(
        monkeypatch, user
):
    monkeypatch.setattr(settings, "DEBUG", True)
    stdout = mock.Mock()
    command = Command()
    monkeypatch.setattr(command, "stdout", stdout)
    command.handle(user.pk)
    printed_token = stdout.write.mock_calls[0][1][0]

    payload = JSONWebTokenAuthentication.jwt_decode_token(printed_token.encode())
    assert payload['user_id'] == user.pk
