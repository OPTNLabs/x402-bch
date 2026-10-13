"""Compatibility facade for the modular x402-BCH SDK.

New code should import from ``wallet``, ``builders``, ``provider``, ``store``,
``client``, or ``facilitator`` according to responsibility. Existing imports
from ``x402_bch.sdk`` remain supported.
"""

from .wallet import *  # noqa: F401,F403
from .builders import *  # noqa: F401,F403
from .provider import *  # noqa: F401,F403
from .store import *  # noqa: F401,F403
from .client import *  # noqa: F401,F403
from .facilitator import *  # noqa: F401,F403
