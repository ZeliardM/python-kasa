"""Tests for smart camera devices."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kasa import Credentials, Device, DeviceType, Module, StreamResolution

from ...conftest import device_smartcam, parametrize

not_child_camera_smartcam = parametrize(
    "not child camera smartcam",
    device_type_filter=[DeviceType.Camera],
    protocol_filter={"SMARTCAM"},
)


@device_smartcam
async def test_state(dev: Device):
    if dev.device_type is DeviceType.Hub:
        pytest.skip("Hubs cannot be switched on and off")

    state = dev.is_on
    await dev.set_state(not state)
    await dev.update()
    assert dev.is_on is not state


@not_child_camera_smartcam
async def test_stream_rtsp_url(dev: Device):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    await camera_module.set_state(True)
    await dev.update()
    assert camera_module.is_on
    url = camera_module.stream_rtsp_url(Credentials("foo", "bar"))
    assert url == "rtsp://foo:bar@127.0.0.123:554/stream1"

    url = camera_module.stream_rtsp_url(
        Credentials("foo", "bar"), stream_resolution=StreamResolution.HD
    )
    assert url == "rtsp://foo:bar@127.0.0.123:554/stream1"

    url = camera_module.stream_rtsp_url(
        Credentials("foo", "bar"), stream_resolution=StreamResolution.SD
    )
    assert url == "rtsp://foo:bar@127.0.0.123:554/stream2"

    # RTSP should use only third-account credentials passed to this method.
    with patch.object(dev.config, "credentials", Credentials("bar", "foo")):
        url = camera_module.stream_rtsp_url()
    assert url is None

    with patch.object(dev.config, "credentials", Credentials("bar", "")):
        url = camera_module.stream_rtsp_url()
    assert url is None

    with patch.object(dev.config, "credentials", Credentials("", "Foo")):
        url = camera_module.stream_rtsp_url()
    assert url is None

    with patch.object(dev.config, "credentials", None):
        url = camera_module.stream_rtsp_url()
    assert url is None


@not_child_camera_smartcam
async def test_onvif_url(dev: Device):
    """Test the onvif url."""
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    url = camera_module.onvif_url()
    assert url == "http://127.0.0.123:2020/onvif/device_service"


@not_child_camera_smartcam
async def test_update_third_account_credentials_enables_updates_and_verifies(
    dev: Device,
):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    is_enabled_mock = AsyncMock(return_value=False)
    enable_mock = AsyncMock(return_value={})
    change_mock = AsyncMock(return_value={})
    verify_mock = AsyncMock(return_value={"ok": True})
    with (
        patch.object(camera_module, "_is_third_account_enabled", is_enabled_mock),
        patch.object(camera_module, "_set_third_account_enabled", enable_mock),
        patch.object(camera_module, "_change_third_account", change_mock),
        patch.object(camera_module, "_verify_third_account", verify_mock),
    ):
        res = await camera_module.update_third_account_credentials(
            "camaccuser", "camaccpassword"
        )

    assert res == {"ok": True}
    is_enabled_mock.assert_awaited_once_with()
    enable_mock.assert_awaited_once_with(True)
    change_mock.assert_awaited_once_with("camaccuser", "camaccpassword", None)
    verify_mock.assert_awaited_once_with("camaccuser", "camaccpassword", None)


@not_child_camera_smartcam
async def test_update_third_account_credentials_skips_enable_when_already_on(
    dev: Device,
):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    is_enabled_mock = AsyncMock(return_value=True)
    enable_mock = AsyncMock(return_value={})
    change_mock = AsyncMock(return_value={})
    verify_mock = AsyncMock(return_value={"ok": True})
    with (
        patch.object(camera_module, "_is_third_account_enabled", is_enabled_mock),
        patch.object(camera_module, "_set_third_account_enabled", enable_mock),
        patch.object(camera_module, "_change_third_account", change_mock),
        patch.object(camera_module, "_verify_third_account", verify_mock),
    ):
        await camera_module.update_third_account_credentials(
            "camaccuser", "camaccpassword"
        )

    enable_mock.assert_not_awaited()
    change_mock.assert_awaited_once_with("camaccuser", "camaccpassword", None)
    verify_mock.assert_awaited_once_with("camaccuser", "camaccpassword", None)


@not_child_camera_smartcam
async def test_change_third_account_payload(dev: Device):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    query_mock = AsyncMock(return_value={})
    with (
        patch.object(dev.protocol, "query", query_mock),
        patch.object(
            camera_module, "_encrypt_password", return_value="cipher"
        ) as encrypt_patch,
    ):
        await camera_module._change_third_account("camaccuser", "camaccpassword")

    encrypt_patch.assert_called_once_with("camaccpassword", None)
    query_mock.assert_awaited_once_with(
        {
            "changeThirdAccount": {
                "user_management": {
                    "change_third_account": {
                        "secname": "third_account",
                        "passwd": "A253072AD9B1A66796CABAFC9FEEADF1",
                        "old_passwd": "",
                        "ciphertext": "cipher",
                        "username": "camaccuser",
                    }
                }
            }
        }
    )


@not_child_camera_smartcam
async def test_verify_third_account_payload(dev: Device):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    with (
        patch.object(dev.protocol, "query", query_mock := AsyncMock(return_value={})),
        patch.object(
            camera_module, "_encrypt_password", return_value="cipher"
        ) as encrypt_patch,
    ):
        await camera_module._verify_third_account("camaccuser", "camaccpassword")

    encrypt_patch.assert_called_once_with("camaccpassword", None)
    query_mock.assert_awaited_once_with(
        {
            "verifyThirdAccount": {
                "user_management": {
                    "verify_third_account": {
                        "secname": "third_account",
                        "passwd": "A253072AD9B1A66796CABAFC9FEEADF1",
                        "old_passwd": "",
                        "ciphertext": "cipher",
                        "username": "camaccuser",
                    }
                }
            }
        }
    )


@not_child_camera_smartcam
async def test_change_third_account_payload_with_public_key_metadata(dev: Device):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    with (
        patch.object(dev.protocol, "query", query_mock := AsyncMock(return_value={})),
        patch.object(
            camera_module, "_encrypt_password", return_value="cipher"
        ) as encrypt_patch,
    ):
        await camera_module._change_third_account(
            "camaccuser",
            "camaccpassword",
            "DEVICE_PUBLIC_KEY_B64",
        )

    encrypt_patch.assert_called_once_with("camaccpassword", "DEVICE_PUBLIC_KEY_B64")
    query_mock.assert_awaited_once_with(
        {
            "changeThirdAccount": {
                "user_management": {
                    "change_third_account": {
                        "secname": "third_account",
                        "passwd": "A253072AD9B1A66796CABAFC9FEEADF1",
                        "old_passwd": "",
                        "ciphertext": "cipher",
                        "username": "camaccuser",
                        "public_key": "DEVICE_PUBLIC_KEY_B64",
                        "unique_key": 1,
                    }
                }
            }
        }
    )


@not_child_camera_smartcam
async def test_set_third_account_credentials_alias(dev: Device):
    camera_module = dev.modules.get(Module.Camera)
    assert camera_module

    update_mock = AsyncMock(return_value={"ok": True})
    with patch.object(camera_module, "update_third_account_credentials", update_mock):
        res = await camera_module.set_third_account_credentials(
            "camaccuser", "camaccpassword"
        )

    assert res == {"ok": True}
    update_mock.assert_awaited_once_with("camaccuser", "camaccpassword")
