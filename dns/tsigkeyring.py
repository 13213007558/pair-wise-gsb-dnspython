# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""A place to store TSIG keys."""

import base64
import os
import re
import time
from typing import Any
from pathlib import Path
import dns.name
import dns.tsig

TSIG_KEY_FILE_RE = re.compile(
    r"key\s*"
    r'(?:"([^"]*)"'  # group 1: quoted name
    r"|([^{\s]+))"  # group 2: unquoted name
    r"\s*\{\s*"
    r"(?:algorithm\s*"  # --- algorithm block (optional) ---
    r'(?:"([^"]*)"'  # group 3: quoted algo
    r"|([^;\s}]+))"  # group 4: unquoted algo
    r"\s*;\s*)?"  # --- end optional block ---
    r"secret\s*"
    r'(?:"([^"]*)"'  # group 5: quoted secret
    r"|([^;\s}]+))"  # group 6: unquoted secret
    r"\s*;?\s*\}?"
)


def from_file(key_file: str | os.PathLike) -> dict[dns.name.Name, Any]:
    """Open a tsig key file generate by tsig-keygen
    and parse to retrieve key, algo and secret
    @rtype: dict"""

    content = Path(key_file).read_text().replace("\n", "").strip()

    if m := TSIG_KEY_FILE_RE.match(content):
        key_name = m.group(1) or m.group(2)
        algorithm = m.group(3) or m.group(4)
        secret = m.group(5) or m.group(6)
        if algorithm:
            return from_text({key_name: (algorithm, secret)})
        else:
            return from_text({key_name: secret})
    else:
        raise Exception(f"Error while parsing {key_file}")


def from_text(textring: dict[str, Any]) -> dict[dns.name.Name, Any]:
    """Convert a dictionary containing (textual DNS name, base64 secret)
    pairs into a binary keyring which has (dns.name.Name, bytes) pairs, or
    a dictionary containing (textual DNS name, (algorithm, base64 secret))
    pairs into a binary keyring which has (dns.name.Name, dns.tsig.Key) pairs.
    @rtype: dict"""

    keyring: dict[dns.name.Name, Any] = {}
    for name, value in textring.items():
        kname = dns.name.from_text(name)
        if isinstance(value, str):
            keyring[kname] = dns.tsig.Key(kname, value).secret
        else:
            algorithm, secret = value
            keyring[kname] = dns.tsig.Key(kname, secret, algorithm)
    return keyring


def to_text(keyring: dict[dns.name.Name, Any]) -> dict[str, Any]:
    """Convert a dictionary containing (dns.name.Name, dns.tsig.Key) pairs
    into a text keyring which has (textual DNS name, (textual algorithm,
    base64 secret)) pairs, or a dictionary containing (dns.name.Name, bytes)
    pairs into a text keyring which has (textual DNS name, base64 secret) pairs.
    @rtype: dict"""

    textring = {}

    def b64encode(secret):
        return base64.encodebytes(secret).decode().rstrip()

    for name, key in keyring.items():
        tname = name.to_text()
        if isinstance(key, bytes):
            textring[tname] = b64encode(key)
        else:
            if isinstance(key.secret, bytes):
                text_secret = b64encode(key.secret)
            else:
                text_secret = str(key.secret)

            textring[tname] = (key.algorithm.to_text(), text_secret)
    return textring


class RotationKey:
    """A TSIG key with an associated validity interval.

    The key is valid for message signing times `t` with
    ``not_before <= t < not_after``; a `None` bound is open-ended.
    """

    def __init__(
        self,
        key: dns.tsig.Key,
        not_before: int | None = None,
        not_after: int | None = None,
    ):
        self.key = key
        self.not_before = not_before
        self.not_after = not_after

    @property
    def name(self) -> dns.name.Name:
        return self.key.name

    @property
    def algorithm(self) -> dns.name.Name:
        return self.key.algorithm

    def valid_at(self, when: int) -> bool:
        """Is the key valid at the specified time?"""
        if self.not_before is not None and when < self.not_before:
            return False
        if self.not_after is not None and when >= self.not_after:
            return False
        return True

    def __repr__(self):
        return (
            f"<RotationKey name='{self.name}', algorithm='{self.algorithm}', "
            f"not_before={self.not_before}, not_after={self.not_after}>"
        )


class RotationKeyring:
    """A TSIG keyring supporting rotation between a current and a
    previous key.

    Each key has its own algorithm and validity interval.  When
    validating a message, exactly one key is selected, based on the
    message's signing time rather than the local clock; if verification
    with the selected key fails, there is no fallback to the other key.
    When signing, the key valid at the current local time is used.
    """

    def __init__(
        self,
        current: RotationKey | dns.tsig.Key,
        previous: RotationKey | dns.tsig.Key | None = None,
    ):
        def ensure_rotation_key(k):
            if isinstance(k, dns.tsig.Key):
                return RotationKey(k)
            return k

        self.current = ensure_rotation_key(current)
        if previous is not None:
            previous = ensure_rotation_key(previous)
        self.previous = previous

    def _keys(self):
        return [k for k in (self.current, self.previous) if k is not None]

    def get_key(self, keyname: dns.name.Name, time_signed: int) -> dns.tsig.Key | None:
        """Return the single key to use for a message with the specified
        key name and signing time, or `None` if there is no such key.

        The current key is preferred if both keys are valid at
        *time_signed*.
        """
        for rotation_key in self._keys():
            if rotation_key.name == keyname and rotation_key.valid_at(time_signed):
                return rotation_key.key
        return None

    def __getitem__(self, keyname: dns.name.Name) -> dns.tsig.Key:
        # Signing path; select by the current local time.
        key = self.get_key(keyname, int(time.time()))
        if key is None:
            raise KeyError(keyname)
        return key

    def __iter__(self):
        seen = set()
        for rotation_key in self._keys():
            if rotation_key.name not in seen:
                seen.add(rotation_key.name)
                yield rotation_key.name

    def __contains__(self, keyname: dns.name.Name) -> bool:
        return any(k.name == keyname for k in self._keys())

    def __repr__(self):
        return f"<RotationKeyring current={self.current!r} previous={self.previous!r}>"
