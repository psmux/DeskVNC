#!/usr/bin/env python3
"""Password resolution shared by every python limb.

A limb has to authenticate against a real server, and the one thing that must
never happen is a password reaching a shell history file, a log line, a process
argument list (visible to every user on the box via `ps`) or a checked-in file.
So there is exactly one supported path in and it is the environment:

  1. `DVV_PASS` if it is set. This is the normal case and the only one that
     works on a machine with no macOS keychain.
  2. Otherwise, if a profile id is supplied (`--profile` on any limb, or the
     `DVV_PROFILE` environment variable), read it out of the macOS keychain.
     The app stores its credentials as a JSON blob under service
     `com.deskvncviewer.app` with the profile UUID as the account, so the blob
     has to be parsed rather than used directly.
  3. Otherwise the empty string, which is correct for a server offering
     security type None (the `proxy` limb offers exactly that downstream).

The resolved value is never printed, never logged, and never placed on a
command line. `describe_source()` exists so a limb can tell the operator WHERE
the password came from without revealing WHAT it is, which is the difference
between a useful diagnostic and a leak.
"""
import json
import os
import shutil
import subprocess

# The service name the shipping app registers with the macOS keychain. Kept
# overridable because a dev build signed with a different bundle id writes to a
# different service and would otherwise be invisible to the limbs.
DEFAULT_KEYCHAIN_SERVICE = os.environ.get(
    "DVV_KEYCHAIN_SERVICE", "com.deskvncviewer.app"
)

# The key inside the stored JSON blob. Also overridable: the schema has changed
# once already, and a limb that cannot read a password is more annoying than a
# limb with one extra environment variable.
DEFAULT_KEYCHAIN_FIELD = os.environ.get("DVV_KEYCHAIN_FIELD", "vncPassword")


class CredentialError(RuntimeError):
    pass


def _keychain_lookup(profile, service=None, field=None):
    """Pull one profile's password out of the macOS keychain.

    Returns the password, or raises CredentialError with a message that
    deliberately contains no secret material.
    """
    service = service or DEFAULT_KEYCHAIN_SERVICE
    field = field or DEFAULT_KEYCHAIN_FIELD

    if not shutil.which("security"):
        raise CredentialError(
            "the `security` tool is not available, so keychain lookup is not "
            "possible on this platform. Set DVV_PASS instead."
        )

    proc = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-a", profile, "-w"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise CredentialError(
            f"no keychain item for service {service!r} account {profile!r}. "
            f"Check the profile id, or set DVV_PASS."
        )

    raw = proc.stdout.strip()
    # The app stores JSON, but a hand-created item may hold the bare password.
    # Accept both rather than making the operator care which one they have.
    try:
        blob = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(blob, dict) or field not in blob:
        raise CredentialError(
            f"keychain item for {profile!r} is JSON but has no {field!r} key"
        )
    return str(blob[field])


def resolve_password(profile=None, service=None, field=None):
    """Return the VNC password for this run. Never prints it.

    `profile` is a keychain account id (the app uses a UUID). It is only
    consulted when DVV_PASS is unset, so an explicit environment variable
    always wins and a limb can be pointed at a different server without
    touching the keychain at all.
    """
    env = os.environ.get("DVV_PASS")
    if env is not None:
        return env
    profile = profile or os.environ.get("DVV_PROFILE")
    if profile:
        return _keychain_lookup(profile, service=service, field=field)
    return ""


def describe_source(profile=None):
    """A one-line, secret-free description of where the password came from.

    Printed by the limbs at startup because "auth failed" against a real server
    is otherwise unattributable: the operator cannot tell whether the wrong
    password was used or the right one was rejected.
    """
    if os.environ.get("DVV_PASS") is not None:
        n = len(os.environ["DVV_PASS"])
        return f"password: from DVV_PASS ({n} characters)" if n else "password: empty (DVV_PASS is set but blank)"
    profile = profile or os.environ.get("DVV_PROFILE")
    if profile:
        return f"password: from macOS keychain, profile {profile}"
    return "password: none supplied (fine for a server offering security type None)"


def add_credential_args(parser):
    """Attach the credential flags every limb that talks to a server shares."""
    parser.add_argument(
        "--profile",
        default=None,
        metavar="UUID",
        help="macOS keychain account id to read the password from. Only used "
             "when DVV_PASS is unset. Defaults to $DVV_PROFILE.",
    )
    parser.add_argument(
        "--keychain-service",
        default=None,
        metavar="NAME",
        help=f"keychain service name (default {DEFAULT_KEYCHAIN_SERVICE}, "
             f"override with $DVV_KEYCHAIN_SERVICE)",
    )
    return parser


def password_from_args(args):
    """Resolve the password from a parsed argparse namespace."""
    return resolve_password(
        profile=getattr(args, "profile", None),
        service=getattr(args, "keychain_service", None),
    )
