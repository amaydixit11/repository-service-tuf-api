# SPDX-FileCopyrightText: 2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

"""Trusted online-key discovery and delegation request validation."""

from collections.abc import Mapping
from typing import Any, Dict, List, Optional

ONLINE_KEY_URI_FIELD = "x-rstuf-online-key-uri"
KEY_NAME_FIELD = "x-rstuf-key-name"
NESTED_BINS_FIELD = "x-rstuf-num-bins"

# URI schemes the Worker can resolve to a signer (securesystemslib's
# SIGNER_FOR_URI_SCHEME plus RSTUF's own file-name signer). A role-local
# online key may only reference one of these: the scheme selects the signer
# backend, so an unknown scheme is unusable and an unrestricted one would let
# a request point the Worker at an arbitrary backend.
ALLOWED_ONLINE_KEY_URI_SCHEMES = frozenset(
    {
        "fn",
        "envvar",
        "file",
        # securesystemslib's current CryptoSigner file scheme (the Worker's
        # signer resolver registers "file2", not "file"); a file-based online
        # key must use this scheme to be resolvable at signing time.
        "file2",
        "awskms",
        "gcpkms",
        "azurekms",
        "hv",
        "sigstore",
    }
)


class DelegationValidationError(ValueError):
    """Raised when a delegation cannot be resolved to trusted signing keys."""


def _as_dict(value: Any) -> Dict[str, Any]:
    """Convert supported metadata/settings containers to a plain dictionary."""
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, exclude_none=True)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise DelegationValidationError("Trusted root metadata is unavailable")


def online_keys_from_root(root_metadata: Any) -> Dict[str, Dict[str, Any]]:
    """Return URI-tagged public keys from a root metadata envelope."""
    root = _as_dict(root_metadata)
    signed = root.get("signed")
    if not isinstance(signed, Mapping):
        raise DelegationValidationError(
            "Trusted root metadata has no signed root object"
        )

    keys = signed.get("keys")
    if not isinstance(keys, Mapping):
        raise DelegationValidationError("Trusted root metadata has no keys")

    online_keys: Dict[str, Dict[str, Any]] = {}
    for keyid, key in keys.items():
        key_data = _as_dict(key)
        if ONLINE_KEY_URI_FIELD in key_data:
            uri = key_data[ONLINE_KEY_URI_FIELD]
            if not isinstance(uri, str) or not uri:
                raise DelegationValidationError(
                    f"Online key {keyid!r} has an invalid "
                    f"{ONLINE_KEY_URI_FIELD}"
                )
            online_keys[str(keyid)] = key_data

    return online_keys


def online_key_catalog(root_metadata: Any) -> List[Dict[str, str]]:
    """Build the safe, public online-key catalogue returned to CLI clients."""
    catalog = []
    for keyid, key in online_keys_from_root(root_metadata).items():
        catalog.append(
            {
                "keyid": keyid,
                "name": str(key.get(KEY_NAME_FIELD) or keyid),
                "keytype": str(key.get("keytype") or ""),
                "scheme": str(key.get("scheme") or ""),
            }
        )

    return catalog


def validate_online_key_assignments(
    root_metadata: Any,
    online_keys: Mapping[str, Any],
) -> None:
    """Verify all top-level online roles use the URI-tagged key set."""
    root = _as_dict(root_metadata)
    signed = root.get("signed")
    if not isinstance(signed, Mapping):
        raise DelegationValidationError(
            "Trusted root metadata has no signed root object"
        )

    expected = set(online_keys)
    if not expected:
        raise DelegationValidationError(
            "Submitted root metadata has no configured online keys"
        )

    roles = signed.get("roles")
    if not isinstance(roles, Mapping):
        raise DelegationValidationError(
            "Submitted root metadata has no top-level role assignments"
        )

    for role_name in ("timestamp", "snapshot", "targets"):
        role = roles.get(role_name)
        if not isinstance(role, Mapping):
            raise DelegationValidationError(
                f"Submitted root metadata has no {role_name!r} role"
            )
        keyids = role.get("keyids")
        if not isinstance(keyids, list) or not all(
            isinstance(keyid, str) for keyid in keyids
        ):
            raise DelegationValidationError(
                f"Submitted root role {role_name!r} keyids must be a list "
                "of strings"
            )
        if len(keyids) != len(set(keyids)):
            raise DelegationValidationError(
                f"Submitted root role {role_name!r} has duplicate keyids"
            )
        if set(keyids) != expected:
            raise DelegationValidationError(
                f"Submitted root role {role_name!r} must use exactly the "
                "configured online keyids"
            )


def role_keyids_from_targets(targets_metadata: Any) -> Dict[str, List[str]]:
    """Return ``role name -> keyids`` from a targets metadata envelope.

    Used to compare an update against the currently trusted delegation
    state. Returns an empty mapping when the repository has no delegated
    roles, but fails closed (raises ``DelegationValidationError``) when the
    trusted targets metadata is absent or malformed -- otherwise a parsing
    failure would silently disable the online-key removal guard on updates.
    """
    try:
        targets = _as_dict(targets_metadata)
    except DelegationValidationError as e:
        raise DelegationValidationError(
            "Trusted targets metadata is unavailable; cannot validate the "
            "delegation update against the current state"
        ) from e

    signed = targets.get("signed")
    if not isinstance(signed, Mapping):
        raise DelegationValidationError(
            "Trusted targets metadata is malformed (missing 'signed')"
        )
    delegations = signed.get("delegations")
    if not isinstance(delegations, Mapping):
        # A repository with no delegations block has no role state to guard.
        return {}

    roles = delegations.get("roles")
    # python-tuf serializes delegated roles as a list; accept a name-keyed
    # mapping as well so either shape can be passed in.
    if isinstance(roles, Mapping):
        roles = list(roles.values())
    if not isinstance(roles, list):
        return {}

    current: Dict[str, List[str]] = {}
    for role in roles:
        if not isinstance(role, Mapping):
            continue
        name = role.get("name")
        keyids = role.get("keyids", [])
        if isinstance(name, str) and isinstance(keyids, list):
            current[name] = [k for k in keyids if isinstance(k, str)]
    return current


def validate_delegations(
    delegations: Any,
    online_keys: Mapping[str, Any],
    current_role_keyids: Optional[Mapping[str, List[str]]] = None,
) -> None:
    """Validate TUF delegation key references without changing the payload.

    Empty role keyids mean repository defaults. Non-empty keyids may
    reference URI-tagged root keys, public keys supplied in
    ``delegations.keys``, or both. Nested bins are Worker-managed and so
    require keys the Worker can sign with (repository or role-local online
    keys).

    ``current_role_keyids`` is the currently trusted ``role -> keyids`` state
    (update operations only). When given, a role may not drop a repository
    online key it currently trusts: trusting a repository key grants no
    privilege over it, and removing one is reserved for root-signed
    operations.
    """
    data = _as_dict(delegations)
    delegation_keys = data.get("keys", {})
    roles = data.get("roles", [])
    if not isinstance(delegation_keys, Mapping) or not isinstance(roles, list):
        raise DelegationValidationError("Invalid TUF delegations object")

    online_keyids = set(online_keys)
    supplied_keyids = set(delegation_keys)
    shadowed = online_keyids & supplied_keyids
    if shadowed:
        keyids = ", ".join(sorted(shadowed))
        raise DelegationValidationError(
            "Online keyids must not be redefined in delegations.keys: "
            f"{keyids}"
        )

    # Role-local online keys: a supplied key may declare an online-key URI so
    # the Worker can sign that role automatically. Only allowlisted schemes
    # are accepted, so a request cannot select an arbitrary signer backend.
    role_local_online_keyids = set()
    for keyid, key in delegation_keys.items():
        key_data = key if isinstance(key, Mapping) else _as_dict(key)
        if ONLINE_KEY_URI_FIELD not in key_data:
            continue  # offline key: nothing for the Worker to resolve
        uri = key_data[ONLINE_KEY_URI_FIELD]
        if not isinstance(uri, str) or not uri:
            raise DelegationValidationError(
                f"Key {keyid!r} has an invalid {ONLINE_KEY_URI_FIELD}"
            )
        scheme = uri.split(":", 1)[0]
        if scheme not in ALLOWED_ONLINE_KEY_URI_SCHEMES:
            allowed = ", ".join(sorted(ALLOWED_ONLINE_KEY_URI_SCHEMES))
            raise DelegationValidationError(
                f"Key {keyid!r} uses unsupported online-key URI scheme "
                f"{scheme!r}; allowed schemes: {allowed}"
            )
        role_local_online_keyids.add(keyid)

    seen_roles = set()
    for role in roles:
        if not isinstance(role, Mapping):
            raise DelegationValidationError("Invalid delegated role object")

        role_name = role.get("name")
        if role_name in seen_roles:
            raise DelegationValidationError(
                f"Duplicate delegated role name: {role_name}"
            )
        seen_roles.add(role_name)

        selected = role.get("keyids", [])
        if not isinstance(selected, list) or not all(
            isinstance(keyid, str) for keyid in selected
        ):
            raise DelegationValidationError(
                f"Role {role_name!r} keyids must be a list of strings"
            )
        if len(selected) != len(set(selected)):
            raise DelegationValidationError(
                f"Role {role_name!r} has duplicate keyids"
            )

        selected_keyids = set(selected)
        unknown = selected_keyids - online_keyids - supplied_keyids
        if unknown:
            keyids = ", ".join(sorted(unknown))
            raise DelegationValidationError(
                f"Role {role_name!r} references unknown keyids: {keyids}"
            )

        if current_role_keyids is not None:
            current = set(current_role_keyids.get(role_name, []))
            removed_online = (current & online_keyids) - selected_keyids
            if removed_online:
                keyids = ", ".join(sorted(removed_online))
                raise DelegationValidationError(
                    f"Role {role_name!r} cannot remove repository online "
                    f"key(s) {keyids}; use a root metadata update"
                )

        threshold = role.get("threshold")
        if not isinstance(threshold, int) or isinstance(threshold, bool):
            raise DelegationValidationError(
                f"Role {role_name!r} threshold must be an integer"
            )
        if threshold < 1:
            raise DelegationValidationError(
                f"Role {role_name!r} threshold must be at least 1"
            )

        effective_key_count = (
            len(selected_keyids) if selected else len(online_keyids)
        )
        if effective_key_count == 0:
            raise DelegationValidationError(
                f"Role {role_name!r} uses repository defaults, but no "
                "online keys are configured"
            )
        if threshold > effective_key_count:
            raise DelegationValidationError(
                f"Role {role_name!r} threshold {threshold} exceeds its "
                f"{effective_key_count} available keys"
            )

        num_bins = role.get(NESTED_BINS_FIELD)
        if num_bins is None:
            continue
        if (
            not isinstance(num_bins, int)
            or isinstance(num_bins, bool)
            or num_bins < 1
            or num_bins & (num_bins - 1) != 0
        ):
            raise DelegationValidationError(
                f"Role {role_name!r} {NESTED_BINS_FIELD} must be a positive "
                "power of 2"
            )
        if threshold != 1:
            raise DelegationValidationError(
                f"Role {role_name!r} nested hash bins require threshold 1"
            )
        # Bins are generated and signed by the Worker, so every key the
        # parent trusts must be Worker-signable: a repository online key or
        # a role-local online key.
        signable_keyids = online_keyids | role_local_online_keyids
        if not signable_keyids:
            raise DelegationValidationError(
                f"Role {role_name!r} nested hash bins require at least one "
                "online key"
            )
        if selected_keyids and not selected_keyids.issubset(signable_keyids):
            raise DelegationValidationError(
                f"Role {role_name!r} nested hash-bin keyids must all be "
                "online keys"
            )
