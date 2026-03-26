"""Implementation of the TP-Link AES transport.

Based on the work of https://github.com/petretiandrea/plugp100
under compatible GNU GPL3 license.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, cast

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from yarl import URL

from kasa.credentials import DEFAULT_CREDENTIALS, Credentials, get_default_credentials
from kasa.deviceconfig import DeviceConfig
from kasa.exceptions import (
    SMART_AUTHENTICATION_ERRORS,
    SMART_RETRYABLE_ERRORS,
    AuthenticationError,
    DeviceError,
    KasaException,
    SmartErrorCode,
    TimeoutError,
    _ConnectionError,
    _RetryableError,
)
from kasa.httpclient import HttpClient
from kasa.json import dumps as json_dumps
from kasa.json import loads as json_loads

from .basetransport import BaseTransport

_LOGGER = logging.getLogger(__name__)


ONE_DAY_SECONDS = 86400
SESSION_EXPIRE_BUFFER_SECONDS = 60 * 20


def _sha1(payload: bytes) -> str:
    sha1_algo = hashlib.sha1()  # noqa: S324
    sha1_algo.update(payload)
    return sha1_algo.hexdigest()


def _public_key_encode(payload: bytes) -> str:
    encoded = base64.encodebytes(payload).decode().replace("\r\n", "\n")
    if not encoded.endswith("\n"):
        encoded += "\n"
    return encoded


def _hex_preview(data: bytes | None, limit: int = 64) -> str:
    """Return a short hex preview for debug logging."""
    if data is None:
        return "<none>"
    preview = data[:limit].hex()
    if len(data) > limit:
        preview += "..."
    return preview


def _safe_text_preview(data: bytes | None, limit: int = 400) -> str:
    """Return a safe utf-8 preview for debug logging."""
    if data is None:
        return "<none>"
    text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + "...<truncated>"
    return text


class TransportState(Enum):
    """Enum for AES state."""

    HANDSHAKE_REQUIRED = auto()  # Handshake needed
    LOGIN_REQUIRED = auto()  # Login needed
    ESTABLISHED = auto()  # Ready to send requests


class AesTransport(BaseTransport):
    """Implementation of the AES encryption protocol.

    AES is the name used in device discovery for TP-Link's TAPO encryption
    protocol, sometimes used by newer firmware versions on kasa devices.
    """

    DEFAULT_PORT: int = 80
    SESSION_COOKIE_NAME = "TP_SESSIONID"
    TIMEOUT_COOKIE_NAME = "TIMEOUT"
    COMMON_HEADERS = {
        "Content-Type": "application/json; charset=UTF-8",
        "requestByApp": "true",
        "Accept": "application/json",
    }
    CONTENT_LENGTH = "Content-Length"
    REFERRER = "Referer"

    def __init__(
        self,
        *,
        config: DeviceConfig,
    ) -> None:
        super().__init__(config=config)

        self._login_version = config.connection_type.login_version
        if (
            not self._credentials or self._credentials.username is None
        ) and not self._credentials_hash:
            self._credentials = Credentials()
        if self._credentials:
            self._login_params = self._get_login_params(self._credentials)
        else:
            self._login_params = json_loads(
                base64.b64decode(self._credentials_hash.encode()).decode()  # type: ignore[union-attr]
            )
        self._default_credentials: Credentials | None = None
        self._http_client: HttpClient = HttpClient(config)

        self._state = TransportState.HANDSHAKE_REQUIRED

        self._encryption_session: AesEncyptionSession | None = None
        self._session_expire_at: float | None = None

        self._session_cookie: dict[str, str] | None = None

        self._key_pair: KeyPair | None = None
        if config.aes_keys:
            aes_keys = config.aes_keys
            self._key_pair = KeyPair.create_from_der_keys(
                aes_keys["private"], aes_keys["public"]
            )
        self._app_url = URL(f"http://{self._host}:{self._port}/app")
        self._headers = {
            **self.COMMON_HEADERS,
            self.REFERRER: f"http://{self._host}:{self._port}",
        }
        self._token_url: URL | None = None

        _LOGGER.debug("Created AES transport for %s", self._host)

    @property
    def default_port(self) -> int:
        """Default port for the transport."""
        if port := self._config.connection_type.http_port:
            return port
        return self.DEFAULT_PORT

    @property
    def credentials_hash(self) -> str | None:
        """The hashed credentials used by the transport."""
        if self._credentials == Credentials():
            return None
        return base64.b64encode(json_dumps(self._login_params).encode()).decode()

    def _get_login_params(self, credentials: Credentials) -> dict[str, str]:
        """Get the login parameters based on the login_version."""
        un, pw = self.hash_credentials(self._login_version == 2, credentials)
        password_field_name = "password2" if self._login_version == 2 else "password"
        return {password_field_name: pw, "username": un}

    @staticmethod
    def hash_credentials(login_v2: bool, credentials: Credentials) -> tuple[str, str]:
        """Hash the credentials."""
        un = base64.b64encode(_sha1(credentials.username.encode()).encode()).decode()
        if login_v2:
            pw = base64.b64encode(
                _sha1(credentials.password.encode()).encode()
            ).decode()
        else:
            pw = base64.b64encode(credentials.password.encode()).decode()
        return un, pw

    def _handle_response_error_code(self, resp_dict: dict, msg: str) -> None:
        error_code_raw = resp_dict.get("error_code")
        try:
            error_code = SmartErrorCode.from_int(error_code_raw)
        except ValueError:
            _LOGGER.warning(
                "Device %s received unknown error code: %s", self._host, error_code_raw
            )
            error_code = SmartErrorCode.INTERNAL_UNKNOWN_ERROR
        if error_code is SmartErrorCode.SUCCESS:
            return
        msg = f"{msg}: {self._host}: {error_code.name}({error_code.value})"
        if error_code in SMART_RETRYABLE_ERRORS:
            raise _RetryableError(msg, error_code=error_code)
        if error_code in SMART_AUTHENTICATION_ERRORS:
            self._state = TransportState.HANDSHAKE_REQUIRED
            raise AuthenticationError(msg, error_code=error_code)
        raise DeviceError(msg, error_code=error_code)

    async def send_secure_passthrough(self, request: str) -> dict[str, Any]:
        """Send encrypted message as passthrough."""
        if self._state is TransportState.ESTABLISHED and self._token_url:
            url = self._token_url
        else:
            url = self._app_url

        encrypted_payload = self._encryption_session.encrypt(request.encode())  # type: ignore
        passthrough_request = {
            "method": "securePassthrough",
            "params": {"request": encrypted_payload.decode()},
        }
        _LOGGER.debug(
            "Secure passthrough plaintext request for %s: %s", self._host, request
        )
        _LOGGER.debug(
            "Secure passthrough encrypted request for %s: len=%d preview=%r",
            self._host,
            len(encrypted_payload),
            encrypted_payload[:120],
        )
        _LOGGER.debug(
            "Secure passthrough request object for %s: %s",
            self._host,
            passthrough_request,
        )
        status_code, resp_dict = await self._http_client.post(
            url,
            json=passthrough_request,
            headers=self._headers,
            cookies_dict=self._session_cookie,
        )
        _LOGGER.debug(
            "Secure passthrough response for %s: status=%s response=%s",
            self._host,
            status_code,
            resp_dict,
        )

        if status_code != 200:
            raise KasaException(
                f"{self._host} responded with an unexpected "
                + f"status code {status_code} to passthrough"
            )

        if TYPE_CHECKING:
            resp_dict = cast(dict[str, Any], resp_dict)
            assert self._encryption_session is not None

        self._handle_response_error_code(
            resp_dict, "Error sending secure_passthrough message"
        )

        raw_response: str = resp_dict["result"]["response"]
        _LOGGER.debug(
            "Secure passthrough raw encrypted response for %s: %r",
            self._host,
            raw_response,
        )

        try:
            response = self._encryption_session.decrypt(raw_response.encode())
            _LOGGER.debug(
                "Secure passthrough decrypted response for %s: %s",
                self._host,
                response,
            )
            ret_val = json_loads(response)
        except Exception as ex:
            try:
                ret_val = json_loads(raw_response)
                _LOGGER.debug(
                    "Received unencrypted response over secure passthrough from %s",
                    self._host,
                )
            except Exception:
                raise KasaException(
                    f"Unable to decrypt response from {self._host}, "
                    + f"error: {ex}, response: {raw_response}",
                    ex,
                ) from ex
        return ret_val  # type: ignore[return-value]

    async def perform_login(self) -> None:
        """Login to the device."""
        try:
            await self.try_login(self._login_params)
            _LOGGER.debug(
                "%s: logged in with provided credentials",
                self._host,
            )
        except AuthenticationError as aex:
            try:
                if aex.error_code is not SmartErrorCode.LOGIN_ERROR:
                    raise aex
                _LOGGER.debug(
                    "%s: trying login with default TAPO credentials",
                    self._host,
                )
                if self._default_credentials is None:
                    self._default_credentials = get_default_credentials(
                        DEFAULT_CREDENTIALS["TAPO"]
                    )
                await self.perform_handshake()
                await self.try_login(self._get_login_params(self._default_credentials))
                _LOGGER.debug(
                    "%s: logged in with default TAPO credentials",
                    self._host,
                )
            except (AuthenticationError, _ConnectionError, TimeoutError):
                raise
            except Exception as ex:
                raise KasaException(
                    "Unable to login and trying default "
                    + f"login raised another exception: {ex}",
                    ex,
                ) from ex

    async def try_login(self, login_params: dict[str, Any]) -> None:
        """Try to login with supplied login_params."""
        login_request = {
            "method": "login_device",
            "params": login_params,
            "request_time_milis": round(time.time() * 1000),
        }
        request = json_dumps(login_request)

        resp_dict = await self.send_secure_passthrough(request)
        self._handle_response_error_code(resp_dict, "Error logging in")
        login_token = resp_dict["result"]["token"]
        self._token_url = self._app_url.with_query(f"token={login_token}")
        self._state = TransportState.ESTABLISHED

    def _generate_key_pair_payload(self) -> bytes:
        """Generate handshake request body bytes for the current key pair."""
        _LOGGER.debug("Generating keypair for %s", self._host)

        if not self._key_pair:
            kp = KeyPair.create_key_pair()
            self._config.aes_keys = {
                "private": kp.private_key_der_b64,
                "public": kp.public_key_der_b64,
            }
            self._key_pair = kp
            _LOGGER.debug(
                "Generated new RSA keypair for %s: public_der_len=%d "
                "private_der_len=%d public_b64_len=%d private_b64_len=%d",
                self._host,
                len(kp.public_key_der_bytes),
                len(kp.private_key_der_bytes),
                len(kp.public_key_der_b64),
                len(kp.private_key_der_b64),
            )
        else:
            _LOGGER.debug(
                "Reusing RSA keypair for %s: public_der_len=%d "
                "private_der_len=%d public_b64_len=%d private_b64_len=%d",
                self._host,
                len(self._key_pair.public_key_der_bytes),
                len(self._key_pair.private_key_der_bytes),
                len(self._key_pair.public_key_der_b64),
                len(self._key_pair.private_key_der_b64),
            )

        pub_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            + _public_key_encode(self._key_pair.public_key_der_bytes)
            + "-----END PUBLIC KEY-----\n"
        )

        handshake_params = {"key": pub_key}
        request_body = {"method": "handshake", "params": handshake_params}
        payload = json_dumps(request_body).encode()

        _LOGGER.debug("Handshake public key repr for %s: %r", self._host, pub_key)
        _LOGGER.debug(
            "Handshake public key stats for %s: pem_len=%d lines=%d",
            self._host,
            len(pub_key),
            pub_key.count("\n"),
        )
        _LOGGER.debug("Handshake request object for %s: %s", self._host, request_body)
        _LOGGER.debug("Handshake request payload repr for %s: %r", self._host, payload)
        _LOGGER.debug(
            "Handshake request payload hex preview for %s: %s",
            self._host,
            _hex_preview(payload, 128),
        )

        return payload

    async def perform_handshake(self) -> None:
        """Perform the handshake."""
        _LOGGER.debug("Will perform handshaking with %s", self._host)

        self._token_url = None
        self._session_expire_at = None
        self._session_cookie = None

        payload = self._generate_key_pair_payload()

        headers = {
            **self._headers,
            self.CONTENT_LENGTH: str(len(payload)),
        }

        _LOGGER.debug("Handshake headers for %s: %s", self._host, headers)
        _LOGGER.debug(
            "Handshake cookies before request for %s: %s",
            self._host,
            self._session_cookie,
        )

        http_client = self._http_client

        status_code, resp_dict = await http_client.post(
            self._app_url,
            json=payload,
            headers=headers,
            cookies_dict=self._session_cookie,
        )

        _LOGGER.debug(
            "Handshake parsed response for %s: status=%s body=%s",
            self._host,
            status_code,
            resp_dict,
        )

        if status_code != 200:
            raise KasaException(
                f"{self._host} responded with an unexpected "
                + f"status code {status_code} to handshake"
            )

        if TYPE_CHECKING:
            resp_dict = cast(dict[str, Any], resp_dict)

        self._handle_response_error_code(resp_dict, "Unable to complete handshake")

        handshake_key = resp_dict["result"]["key"]
        _LOGGER.debug("Handshake result.key repr for %s: %r", self._host, handshake_key)
        _LOGGER.debug(
            "Handshake result.key length for %s: %d", self._host, len(handshake_key)
        )

        if (cookie := http_client.get_cookie(self.SESSION_COOKIE_NAME)) or (
            cookie := http_client.get_cookie("SESSIONID")
        ):
            self._session_cookie = {self.SESSION_COOKIE_NAME: cookie}

        timeout = int(
            http_client.get_cookie(self.TIMEOUT_COOKIE_NAME) or ONE_DAY_SECONDS
        )

        _LOGGER.debug(
            "Handshake cookies after request for %s: "
            "TP_SESSIONID=%r TIMEOUT=%r stored=%s",
            self._host,
            http_client.get_cookie(self.SESSION_COOKIE_NAME)
            or http_client.get_cookie("SESSIONID"),
            http_client.get_cookie(self.TIMEOUT_COOKIE_NAME),
            self._session_cookie,
        )

        self._session_expire_at = time.time() + timeout - SESSION_EXPIRE_BUFFER_SECONDS

        if TYPE_CHECKING:
            assert self._key_pair is not None

        try:
            handshake_key_bytes = base64.b64decode(handshake_key.encode())
            _LOGGER.debug(
                "Handshake result.key decoded for %s: ciphertext_len=%d hex_preview=%s",
                self._host,
                len(handshake_key_bytes),
                _hex_preview(handshake_key_bytes, 128),
            )

            key_and_iv = self._key_pair.decrypt_handshake_key(handshake_key_bytes)
            _LOGGER.debug(
                "Handshake RSA decrypt result for %s: plaintext_len=%d hex=%s",
                self._host,
                len(key_and_iv),
                key_and_iv.hex(),
            )

            if len(key_and_iv) >= 32:
                _LOGGER.debug(
                    "Handshake AES material for %s: key=%s iv=%s",
                    self._host,
                    key_and_iv[:16].hex(),
                    key_and_iv[16:32].hex(),
                )
            else:
                _LOGGER.debug(
                    "Handshake RSA plaintext too short for %s: len=%d",
                    self._host,
                    len(key_and_iv),
                )

            self._encryption_session = AesEncyptionSession(
                key_and_iv[:16], key_and_iv[16:]
            )
        except Exception:
            _LOGGER.exception(
                "Handshake decrypt/session creation failed for %s", self._host
            )
            raise

        self._state = TransportState.LOGIN_REQUIRED

        _LOGGER.debug("Handshake with %s complete", self._host)

    def _handshake_session_expired(self) -> bool:
        """Return true if session has expired."""
        return (
            self._session_expire_at is None
            or self._session_expire_at - time.time() <= 0
        )

    async def send(self, request: str) -> dict[str, Any]:
        """Send the request."""
        if (
            self._state is TransportState.HANDSHAKE_REQUIRED
            or self._handshake_session_expired()
        ):
            await self.perform_handshake()
        if self._state is not TransportState.ESTABLISHED:
            try:
                await self.perform_login()
            # After a login failure handshake needs to
            # be redone or a 9999 error is received.
            except AuthenticationError as ex:
                self._state = TransportState.HANDSHAKE_REQUIRED
                raise ex

        return await self.send_secure_passthrough(request)

    async def close(self) -> None:
        """Close the http client and reset internal state."""
        await self.reset()
        await self._http_client.close()

    async def reset(self) -> None:
        """Reset internal handshake and login state."""
        self._state = TransportState.HANDSHAKE_REQUIRED


class AesEncyptionSession:
    """Class for an AES encryption session."""

    @staticmethod
    def create_from_keypair(
        handshake_key: str, keypair: KeyPair
    ) -> AesEncyptionSession:
        """Create the encryption session."""
        handshake_key_bytes: bytes = base64.b64decode(handshake_key.encode())

        key_and_iv = keypair.decrypt_handshake_key(handshake_key_bytes)
        if key_and_iv is None:
            raise ValueError("Decryption failed!")

        return AesEncyptionSession(key_and_iv[:16], key_and_iv[16:])

    def __init__(self, key: bytes, iv: bytes) -> None:
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        self.padding_strategy = padding.PKCS7(algorithms.AES.block_size)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt the message."""
        encryptor = self.cipher.encryptor()
        padder = self.padding_strategy.padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(encrypted)

    def decrypt(self, data: str | bytes) -> str:
        """Decrypt the message."""
        decryptor = self.cipher.decryptor()
        unpadder = self.padding_strategy.unpadder()
        decrypted = decryptor.update(base64.b64decode(data)) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
        return unpadded_data.decode()


class KeyPair:
    """Class for generating key pairs."""

    @staticmethod
    def create_key_pair(key_size: int = 1024) -> KeyPair:
        """Create a key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        return KeyPair(private_key, public_key)

    @staticmethod
    def create_from_der_keys(
        private_key_der_b64: str, public_key_der_b64: str
    ) -> KeyPair:
        """Create a key pair."""
        key_bytes = base64.b64decode(private_key_der_b64.encode())
        private_key = cast(
            rsa.RSAPrivateKey, serialization.load_der_private_key(key_bytes, None)
        )
        key_bytes = base64.b64decode(public_key_der_b64.encode())
        public_key = cast(
            rsa.RSAPublicKey, serialization.load_der_public_key(key_bytes, None)
        )

        return KeyPair(private_key, public_key)

    def __init__(
        self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey
    ) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.private_key_der_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_key_der_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.private_key_der_b64 = base64.b64encode(self.private_key_der_bytes).decode()
        self.public_key_der_b64 = base64.b64encode(self.public_key_der_bytes).decode()

    def get_public_pem(self) -> bytes:
        """Get public key in PEM encoding."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def decrypt_handshake_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt an aes handshake key."""
        decrypted = self.private_key.decrypt(
            encrypted_key, asymmetric_padding.PKCS1v15()
        )
        return decrypted

    def decrypt_discovery_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt an aes discovery key."""
        decrypted = self.private_key.decrypt(
            encrypted_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),  # noqa: S303
                algorithm=hashes.SHA1(),  # noqa: S303
                label=None,
            ),
        )
        return decrypted
