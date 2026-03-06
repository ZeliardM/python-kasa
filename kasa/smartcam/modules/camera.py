"""Implementation of camera module."""

from __future__ import annotations

import base64
import hashlib
import logging
from enum import StrEnum
from typing import Annotated
from urllib.parse import quote_plus

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ...credentials import Credentials
from ...feature import Feature
from ...module import FeatureAttribute, Module
from ..smartcammodule import SmartCamModule

_LOGGER = logging.getLogger(__name__)

LOCAL_STREAMING_PORT = 554
ONVIF_PORT = 2020
_STATIC_PUBLIC_KEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4D6i0oD/Ga5qb//RfSe8MrPVI"
    "rMIGecCxkcGWGj9kxxk74qQNq8XUuXoy2PczQ30BpiRHrlkbtBEPeWLpq85tfubT"
    "UjhBz1NPNvWrC88uaYVGvzNpgzZOqDC35961uPTuvdUa8vztcUQjEZy16WbmetRj"
    "URFIiWJgFCmemyYVbQIDAQAB"
)


class StreamResolution(StrEnum):
    """Class for stream resolution."""

    HD = "HD"
    SD = "SD"


class Camera(SmartCamModule):
    """Implementation of device module."""

    REQUIRED_COMPONENT = "video"

    @staticmethod
    def _hash_third_account_password(password: str) -> str:
        """Return the third account password hash expected by the camera API."""
        return hashlib.md5(password.encode()).hexdigest().upper()  # noqa: S324

    def _encrypt_password(
        self, password: str, public_key_b64: str | None = None
    ) -> str:
        """Encrypt a plaintext password using camera RSA key."""
        key_b64 = (
            public_key_b64
            or getattr(self._device, "_public_key", None)
            or _STATIC_PUBLIC_KEY_B64
        )
        key_bytes = base64.b64decode(key_b64)
        public_key = serialization.load_der_public_key(key_bytes)
        if not isinstance(public_key, RSAPublicKey):
            raise TypeError("Loaded public key is not an RSA public key")
        encrypted = public_key.encrypt(password.encode(), padding.PKCS1v15())
        return base64.b64encode(encrypted).decode()

    def _build_third_account_auth_payload(
        self,
        *,
        section: str,
        username: str,
        password: str,
        public_key_b64: str | None = None,
    ) -> dict:
        """Build a third-account auth payload matching APK field semantics."""
        payload: dict[str, object] = {
            "secname": "third_account",
            "passwd": self._hash_third_account_password(password),
            "old_passwd": "",
            # APK encrypts the plaintext password, not the MD5 hash.
            "ciphertext": self._encrypt_password(password, public_key_b64),
            "username": username,
        }
        if public_key_b64:
            payload["public_key"] = public_key_b64
            payload["unique_key"] = 1

        return {
            "user_management": {
                section: payload,
            }
        }

    def _initialize_features(self) -> None:
        """Initialize features after the initial update."""
        if Module.LensMask in self._device.modules:
            self._add_feature(
                Feature(
                    self._device,
                    id="state",
                    name="State",
                    container=self,
                    attribute_getter="is_on",
                    attribute_setter="set_state",
                    type=Feature.Type.Switch,
                    category=Feature.Category.Primary,
                )
            )

    @property
    def is_on(self) -> bool:
        """Return the device on state."""
        if lens_mask := self._device.modules.get(Module.LensMask):
            return not lens_mask.enabled
        return True

    async def set_state(self, on: bool) -> Annotated[dict, FeatureAttribute()]:
        """Set the device on state.

        If the device does not support setting state will do nothing.
        """
        if lens_mask := self._device.modules.get(Module.LensMask):
            # Turning off enables the privacy mask which is why value is reversed.
            return await lens_mask.set_enabled(not on)
        return {}

    def stream_rtsp_url(
        self,
        credentials: Credentials | None = None,
        *,
        stream_resolution: StreamResolution = StreamResolution.HD,
    ) -> str | None:
        """Return the local rtsp streaming url.

        :param credentials: Credentials for the camera third account.
            RTSP authentication must use the third-party camera account,
            not the device admin/cloud credentials.
        :return: rtsp url with escaped credentials or None if no credentials or
            camera is off.
        """
        if self._device._is_hub_child:
            return None

        streams = {
            StreamResolution.HD: "stream1",
            StreamResolution.SD: "stream2",
        }
        if (stream := streams.get(stream_resolution)) is None:
            return None

        if not credentials or not credentials.username or not credentials.password:
            return None

        username = quote_plus(credentials.username)
        password = quote_plus(credentials.password)

        return f"rtsp://{username}:{password}@{self._device.host}:{LOCAL_STREAMING_PORT}/{stream}"

    @staticmethod
    def _find_enabled_flag(payload: object) -> bool | None:
        """Best-effort parser for account enabled status in nested payloads."""
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_lower = str(key).lower()
                if key_lower in {"enabled", "account_enabled"} and isinstance(
                    value, str
                ):
                    if value.lower() == "on":
                        return True
                    if value.lower() == "off":
                        return False
                found = Camera._find_enabled_flag(value)
                if found is not None:
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = Camera._find_enabled_flag(item)
                if found is not None:
                    return found

        return None

    @staticmethod
    def _find_public_key(payload: object) -> str | None:
        """Best-effort parser for account public key in nested payloads."""
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_lower = str(key).lower()
                if key_lower in {"publickey", "public_key"} and isinstance(value, str):
                    return value
                found = Camera._find_public_key(value)
                if found is not None:
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = Camera._find_public_key(item)
                if found is not None:
                    return found

        return None

    async def _get_third_account_info(self) -> dict | None:
        """Fetch third account information from the camera, if supported."""
        for method, payload in (
            (
                "getThirdAccount",
                {"user_management": {"name": "third_account"}},
            ),
            (
                "getAccountInfo",
                {"user_management": {"name": "account_info"}},
            ),
        ):
            try:
                response = await self.call(method, payload)
            except Exception as ex:
                _LOGGER.debug("Third-account info call %s failed: %s", method, ex)
                continue

            if isinstance(response, dict):
                return response

        return None

    async def _is_third_account_enabled(self) -> bool | None:
        """Return third account enabled state if device exposes it, else None."""
        info = await self._get_third_account_info()
        if info is None:
            return None
        return self._find_enabled_flag(info)

    async def _get_third_account_public_key(self) -> str | None:
        """Return third account public key if the device exposes it."""
        info = await self._get_third_account_info()
        if info is None:
            return None
        return self._find_public_key(info)

    async def _set_third_account_enabled(self, enabled: bool = True) -> dict:
        """Enable or disable third-party camera account access for RTSP/ONVIF."""
        return await self.call(
            "setAccountEnabled",
            {
                "user_management": {
                    "set_account_enabled": {
                        "enabled": "on" if enabled else "off",
                        "secname": "third_account",
                    }
                }
            },
        )

    async def _change_third_account(
        self,
        username: str,
        password: str,
        public_key_b64: str | None = None,
    ) -> dict:
        """Set third-party camera account credentials used by RTSP/ONVIF clients."""
        payload = self._build_third_account_auth_payload(
            section="change_third_account",
            username=username,
            password=password,
            public_key_b64=public_key_b64,
        )
        return await self.call("changeThirdAccount", payload)

    async def _verify_third_account(
        self,
        username: str,
        password: str,
        public_key_b64: str | None = None,
    ) -> dict:
        """Verify third-party camera account credentials."""
        payload = self._build_third_account_auth_payload(
            section="verify_third_account",
            username=username,
            password=password,
            public_key_b64=public_key_b64,
        )
        return await self.call("verifyThirdAccount", payload)

    def onvif_url(self) -> str | None:
        """Return the onvif url."""
        if self._device._is_hub_child:
            return None

        return f"http://{self._device.host}:{ONVIF_PORT}/onvif/device_service"

    async def update_third_account_credentials(
        self, username: str, password: str
    ) -> dict:
        """Ensure third account is enabled, then update and verify credentials."""
        if await self._is_third_account_enabled() is not True:
            await self._set_third_account_enabled(True)

        public_key_b64 = await self._get_third_account_public_key()
        await self._change_third_account(username, password, public_key_b64)
        return await self._verify_third_account(username, password, public_key_b64)

    async def set_third_account_credentials(self, username: str, password: str) -> dict:
        """Backward-compatible alias for update_third_account_credentials."""
        return await self.update_third_account_credentials(username, password)
