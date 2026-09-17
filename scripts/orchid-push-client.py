#!/usr/bin/env python3
"""
Orchid Image Push Client - Runs on Windows PC to push images to VPN server.

Periodically fetches the latest image from the local orchid-images server
and sends it to the VPN server for use in visual-entropy authentication.

Usage:
    python orchid-push-client.py <server-url> [local-image-server] [interval-secs]

Example:
    python orchid-push-client.py https://rockywearsahat.com http://127.0.0.1:8080 60
    python orchid-push-client.py https://rockywearsahat.com  # uses defaults
"""

import sys
import time
import requests
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Parse arguments and start the push loop."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    server_url = sys.argv[1]
    local_server = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8080"
    interval_secs = int(sys.argv[3]) if len(sys.argv) > 3 else 60

    logger.info(f"Orchid Image Push Client starting")
    logger.info(f"  VPN Server: {server_url}")
    logger.info(f"  Local server: {local_server}")
    logger.info(f"  Push interval: {interval_secs} seconds")

    push_loop(server_url, local_server, interval_secs)


def push_loop(server_url: str, local_server: str, interval_secs: int) -> None:
    """Continuously fetch and push images."""
    consecutive_errors = 0
    max_consecutive_errors = 10

    while consecutive_errors < max_consecutive_errors:
        try:
            image_data = fetch_image(local_server)
            if not image_data:
                logger.warning("No image data received from local server")
                consecutive_errors += 1
            else:
                push_image(server_url, image_data)
                consecutive_errors = 0  # Reset error counter on success
                logger.info(f"✓ Image pushed ({len(image_data)} bytes)")

        except Exception as e:
            logger.error(f"Error in push loop: {e}")
            consecutive_errors += 1

        # Wait before next push
        time.sleep(interval_secs)

    logger.error(f"Stopping after {max_consecutive_errors} consecutive errors")
    sys.exit(1)


def fetch_image(local_server: str) -> Optional[bytes]:
    """Fetch latest image from local orchid-images server."""
    url = f"{local_server}/latest-image"
    logger.debug(f"Fetching image from {url}")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.content
        if not data:
            logger.warning("Received empty response from local server")
            return None

        # Validate it looks like a JPEG (FFD8 header)
        if len(data) < 2 or data[0] != 0xFF or data[1] != 0xD8:
            logger.warning("Response doesn't look like a valid JPEG")
            return None

        return data

    except requests.RequestException as e:
        logger.error(f"Failed to fetch image: {e}")
        return None


def push_image(server_url: str, image_data: bytes) -> None:
    """Push image to VPN server."""
    url = f"{server_url}/api/images/push"
    logger.debug(f"Pushing {len(image_data)} bytes to {url}")

    try:
        response = requests.post(
            url,
            data=image_data,
            headers={"Content-Type": "image/jpeg"},
            timeout=30,
            verify=True  # Verify SSL certificates in production
        )

        if response.status_code == 200:
            try:
                result = response.json()
                logger.debug(f"Server response: {result}")
            except:
                logger.debug("Server response (non-JSON)")
        else:
            logger.error(f"Server returned {response.status_code}: {response.text[:200]}")
            raise Exception(f"HTTP {response.status_code}")

    except requests.RequestException as e:
        logger.error(f"Failed to push image: {e}")
        raise


if __name__ == "__main__":
    main()
