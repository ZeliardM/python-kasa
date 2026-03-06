"""Module for cli camera control commands."""

from __future__ import annotations

import asyncclick as click

from kasa import Credentials, Device, Module

from .common import echo, error, pass_dev_or_child


def _require_camera_module(dev: Device):
    """Return camera module or emit a user-facing error if unavailable."""
    camera = dev.modules.get(Module.Camera)
    if not camera:
        error("Device does not support camera module.")
        return None
    return camera


@click.group()
@pass_dev_or_child
def camera(dev) -> None:
    """Commands to control camera settings."""


@camera.command()
@click.option(
    "--username",
    required=True,
    prompt=True,
    help="Third account username for RTSP/ONVIF camera access",
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    help="Third account password for RTSP/ONVIF camera access",
)
@pass_dev_or_child
async def update_third_account_credentials(dev: Device, username: str, password: str):
    """Update camera third-account credentials and verify them."""
    camera_module = _require_camera_module(dev)
    if camera_module is None:
        return

    if not hasattr(camera_module, "update_third_account_credentials"):
        error("Camera module does not support third-account credential updates.")
        return

    result = await camera_module.update_third_account_credentials(username, password)
    echo("Third-account credentials updated and verified.")
    return result


@camera.command(name="stream_rtsp_url")
@click.option(
    "--username",
    required=True,
    prompt=True,
    help="Third account username for RTSP authentication",
)
@click.option(
    "--password",
    required=True,
    prompt=True,
    help="Third account password for RTSP authentication",
)
@click.option(
    "--stream-resolution",
    type=click.Choice(["hd", "sd"], case_sensitive=False),
    default="hd",
    show_default=True,
    help="RTSP stream profile to use",
)
@pass_dev_or_child
async def stream_rtsp_url(
    dev: Device,
    username: str,
    password: str,
    stream_resolution: str,
):
    """Print the RTSP URL for camera stream using third-account credentials."""
    camera_module = _require_camera_module(dev)
    if camera_module is None:
        return

    from kasa.smartcam.modules.camera import StreamResolution

    resolution = StreamResolution(stream_resolution.upper())
    url = camera_module.stream_rtsp_url(
        Credentials(username, password),
        stream_resolution=resolution,
    )
    if url is None:
        error("Unable to generate RTSP URL.")
        return

    echo(url)
    return url
