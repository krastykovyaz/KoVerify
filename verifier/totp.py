"""TOTP matching that reports which time step a code belongs to.

pyotp's verify() only says yes or no. Knowing the step lets the caller refuse
a code that was already used, which RFC 6238 requires of a verifier.
"""
import time

import pyotp

from .security import constant_time_equals

STEP_SECONDS = 30


def match_step(secret, otp, window=1, now=None):
    """Return the time step the code is valid for, or None."""
    if not secret or not otp:
        return None
    current = int((time.time() if now is None else now) // STEP_SECONDS)
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    matched = None
    for step in range(current - window, current + window + 1):
        if constant_time_equals(totp.generate_otp(step), otp):
            matched = step
    return matched
