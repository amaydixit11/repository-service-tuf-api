# SPDX-FileCopyrightText: 2026 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import pytest

from repository_service_tuf_api.online_keys import (
    DelegationValidationError,
    role_keyids_from_targets,
    validate_delegations,
)

ONLINE_KEYID = "a" * 64
ROLE_KEYID = "b" * 64
OFFLINE_KEYID = "c" * 64

ONLINE_KEYS = {
    ONLINE_KEYID: {
        "keytype": "rsa",
        "scheme": "rsassa-pss-sha256",
        "keyval": {"public": "online-public"},
        "x-rstuf-online-key-uri": f"fn:{ONLINE_KEYID}",
    }
}


def _role(keyids, threshold=1, num_bins=None):
    role = {
        "name": "packages",
        "keyids": keyids,
        "threshold": threshold,
        "paths": ["packages/*"],
        "terminating": False,
    }
    if num_bins is not None:
        role["x-rstuf-num-bins"] = num_bins
    return role


def _key(uri=None):
    key = {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "some-public-value"},
    }
    if uri is not None:
        key["x-rstuf-online-key-uri"] = uri
    return key


class TestRoleLocalOnlineKeys:
    def test_role_local_online_key_accepted(self):
        delegations = {
            "keys": {ROLE_KEYID: _key(uri=f"fn:{ROLE_KEYID}")},
            "roles": [_role([ROLE_KEYID])],
        }

        validate_delegations(delegations, ONLINE_KEYS)

    def test_role_local_online_key_can_back_nested_bins(self):
        # Bins are Worker-signed, and a role-local online key is signable.
        delegations = {
            "keys": {ROLE_KEYID: _key(uri=f"fn:{ROLE_KEYID}")},
            "roles": [_role([ROLE_KEYID], num_bins=4)],
        }

        validate_delegations(delegations, ONLINE_KEYS)

    def test_offline_key_cannot_back_nested_bins(self):
        # An offline key has no URI, so the Worker could not sign the bins.
        delegations = {
            "keys": {OFFLINE_KEYID: _key()},
            "roles": [_role([OFFLINE_KEYID], num_bins=4)],
        }

        with pytest.raises(DelegationValidationError, match="online keys"):
            validate_delegations(delegations, ONLINE_KEYS)

    @pytest.mark.parametrize(
        "uri", ["ftp://evil/key", "exec:rm -rf /", "unknown:x"]
    )
    def test_unsupported_uri_scheme_rejected(self, uri):
        # A request must not be able to point the Worker at an arbitrary
        # signer backend.
        delegations = {
            "keys": {ROLE_KEYID: _key(uri=uri)},
            "roles": [_role([ROLE_KEYID])],
        }

        with pytest.raises(
            DelegationValidationError, match="unsupported online-key URI"
        ):
            validate_delegations(delegations, ONLINE_KEYS)

    @pytest.mark.parametrize("uri", ["", 42, None])
    def test_malformed_uri_rejected(self, uri):
        key = _key()
        key["x-rstuf-online-key-uri"] = uri
        delegations = {
            "keys": {ROLE_KEYID: key},
            "roles": [_role([ROLE_KEYID])],
        }

        with pytest.raises(DelegationValidationError, match="invalid"):
            validate_delegations(delegations, ONLINE_KEYS)


class TestOnlineKeyRemovalGuard:
    CURRENT = {"packages": [ONLINE_KEYID, OFFLINE_KEYID]}

    def test_removing_online_key_rejected(self):
        delegations = {
            "keys": {OFFLINE_KEYID: _key()},
            "roles": [_role([OFFLINE_KEYID])],
        }

        with pytest.raises(
            DelegationValidationError, match="cannot remove repository online"
        ):
            validate_delegations(delegations, ONLINE_KEYS, self.CURRENT)

    def test_removing_offline_key_allowed(self):
        # Role-level keys stay under the role owner's control.
        delegations = {"keys": {}, "roles": [_role([ONLINE_KEYID])]}

        validate_delegations(delegations, ONLINE_KEYS, self.CURRENT)

    def test_guard_skipped_without_current_state(self):
        # add operations pass no current state
        delegations = {
            "keys": {OFFLINE_KEYID: _key()},
            "roles": [_role([OFFLINE_KEYID])],
        }

        validate_delegations(delegations, ONLINE_KEYS)

    def test_unknown_role_has_no_current_keys(self):
        delegations = {"keys": {}, "roles": [_role([ONLINE_KEYID])]}

        validate_delegations(
            delegations, ONLINE_KEYS, {"other": [ONLINE_KEYID]}
        )


class TestRoleKeyidsFromTargets:
    def test_reads_roles_list(self):
        targets = {
            "signed": {
                "delegations": {
                    "keys": {},
                    "roles": [{"name": "packages", "keyids": [ONLINE_KEYID]}],
                }
            }
        }

        assert role_keyids_from_targets(targets) == {
            "packages": [ONLINE_KEYID]
        }

    def test_reads_roles_mapping(self):
        targets = {
            "signed": {
                "delegations": {
                    "keys": {},
                    "roles": {
                        "packages": {
                            "name": "packages",
                            "keyids": [ONLINE_KEYID],
                        }
                    },
                }
            }
        }

        assert role_keyids_from_targets(targets) == {
            "packages": [ONLINE_KEYID]
        }

    @pytest.mark.parametrize(
        "targets",
        [
            None,
            {},
            {"signed": {}},
            {"signed": {"delegations": {}}},
            {"signed": {"delegations": {"roles": "bad"}}},
        ],
    )
    def test_missing_or_malformed_returns_empty(self, targets):
        assert role_keyids_from_targets(targets) == {}
