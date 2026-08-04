# SPDX-FileCopyrightText: 2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import json

import pretend
from fastapi import status

from repository_service_tuf_api import BootstrapState

DELEGATIONS_URL = "/api/v1/delegations/"
DELEGATIONS_DELETE_URL = "/api/v1/delegations/delete"
MOCK_PATH = "repository_service_tuf_api.delegations"

ONLINE_KEYID = "0d9d3d4bad91c455bc03921daa95774576b86625ac45570d0cac025b08e65043"  # noqa: E501


def _trusted_root(online_keyid: str = ONLINE_KEYID) -> dict:
    """Minimal trusted root metadata declaring one online key."""
    return {
        "signed": {
            "keys": {
                online_keyid: {
                    "keytype": "rsa",
                    "scheme": "rsassa-pss-sha256",
                    "keyval": {"public": "fake-public-value"},
                    "x-rstuf-online-key-uri": f"fn:{online_keyid}",
                    "x-rstuf-key-name": "online-key",
                }
            },
            "roles": {
                "timestamp": {"keyids": [online_keyid], "threshold": 1},
                "snapshot": {"keyids": [online_keyid], "threshold": 1},
                "targets": {"keyids": [online_keyid], "threshold": 1},
            },
        }
    }


def _mock_settings(monkeypatch, trusted_targets: dict | None = None) -> None:
    """Provide the trusted metadata the delegation validator reads."""
    stored = {
        "TRUSTED_ROOT": _trusted_root(),
        "TRUSTED_TARGETS": trusted_targets,
    }
    monkeypatch.setattr(
        f"{MOCK_PATH}.settings_repository",
        pretend.stub(get_fresh=lambda key: stored.get(key)),
    )


class TestPostDelegationAPI:
    def test_post_delegation(self, test_client, monkeypatch, fake_datetime):
        """Test creating a new delegation via POST /api/v1/delegations/"""
        # Mock bootstrap_state to return a bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=True, state="FINISHED")
            ),
        )

        # Mock get_task_id to return a deterministic task ID
        monkeypatch.setattr(
            f"{MOCK_PATH}.get_task_id",
            pretend.call_recorder(lambda: "fake_task_id"),
        )

        # Mock repository_metadata.apply_async
        mock_apply_async = pretend.call_recorder(lambda **kw: None)
        monkeypatch.setattr(
            f"{MOCK_PATH}.repository_metadata",
            pretend.stub(apply_async=mock_apply_async),
        )

        # Mock datetime
        monkeypatch.setattr(f"{MOCK_PATH}.datetime", fake_datetime)

        # Trusted metadata the delegation validator reads
        _mock_settings(monkeypatch)

        # Load test payload
        with open("tests/data_examples/metadata/delegation-payload.json") as f:
            payload = json.loads(f.read())

        # Make API request
        response = test_client.post(DELEGATIONS_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.url == f"{test_client.base_url}{DELEGATIONS_URL}"
        assert (
            response.json()["message"] == "Metadata delegation add accepted."
        )
        assert response.json()["data"]["task_id"] == "fake_task_id"

        # Verify mocks were called correctly
        assert mock_apply_async.calls
        call_kwargs = mock_apply_async.calls[0].kwargs
        assert call_kwargs["task_id"] == "fake_task_id"
        assert call_kwargs["queue"] == "metadata_repository"
        assert call_kwargs["kwargs"]["action"] == "metadata_delegation"
        assert call_kwargs["kwargs"]["payload"]["action"] == "add"

    def test_post_delegation_no_bootstrap(self, test_client, monkeypatch):
        """Test error case when bootstrap is not complete"""
        # Mock bootstrap_state to return a non-bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=False, state="PRE")
            ),
        )

        # Load test payload
        with open("tests/data_examples/metadata/delegation-payload.json") as f:
            payload = json.loads(f.read())

        # Make API request
        response = test_client.post(DELEGATIONS_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.json()
        assert "message" in response.json()["detail"]
        assert response.json()["detail"]["message"] == "Task not accepted."
        assert (
            "Requires bootstrap finished" in response.json()["detail"]["error"]
        )


class TestPutDelegationAPI:
    def test_put_delegation(self, test_client, monkeypatch, fake_datetime):
        """Test updating a delegation via PUT /api/v1/delegations/"""
        # Mock bootstrap_state to return a bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=True, state="FINISHED")
            ),
        )

        # Mock get_task_id to return a deterministic task ID
        monkeypatch.setattr(
            f"{MOCK_PATH}.get_task_id",
            pretend.call_recorder(lambda: "fake_task_id"),
        )

        # Mock repository_metadata.apply_async
        mock_apply_async = pretend.call_recorder(lambda **kw: None)
        monkeypatch.setattr(
            f"{MOCK_PATH}.repository_metadata",
            pretend.stub(apply_async=mock_apply_async),
        )

        # Mock datetime
        monkeypatch.setattr(f"{MOCK_PATH}.datetime", fake_datetime)

        # Trusted metadata the delegation validator reads. An update is
        # validated against the currently trusted delegation state, so a
        # (parseable) trusted targets envelope must be present.
        _mock_settings(
            monkeypatch,
            trusted_targets={"signed": {"delegations": {"roles": []}}},
        )

        # Load test payload
        with open("tests/data_examples/metadata/delegation-payload.json") as f:
            payload = json.loads(f.read())

        # Make API request
        response = test_client.put(DELEGATIONS_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.url == f"{test_client.base_url}{DELEGATIONS_URL}"
        assert (
            response.json()["message"]
            == "Metadata delegation update accepted."
        )
        assert response.json()["data"]["task_id"] == "fake_task_id"

        # Verify mocks were called correctly
        assert mock_apply_async.calls
        call_kwargs = mock_apply_async.calls[0].kwargs
        assert call_kwargs["task_id"] == "fake_task_id"
        assert call_kwargs["queue"] == "metadata_repository"
        assert call_kwargs["kwargs"]["action"] == "metadata_delegation"
        assert call_kwargs["kwargs"]["payload"]["action"] == "update"

    def test_put_delegation_no_bootstrap(self, test_client, monkeypatch):
        """Test error case when bootstrap is not complete"""
        # Mock bootstrap_state to return a non-bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=False, state="PRE")
            ),
        )

        # Load test payload
        with open("tests/data_examples/metadata/delegation-payload.json") as f:
            payload = json.loads(f.read())

        # Make API request
        response = test_client.put(DELEGATIONS_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.json()
        assert "message" in response.json()["detail"]
        assert response.json()["detail"]["message"] == "Task not accepted."
        assert (
            "Requires bootstrap finished" in response.json()["detail"]["error"]
        )


class TestDeleteDelegationAPI:
    def test_delete_delegation(self, test_client, monkeypatch, fake_datetime):
        """Test deleting a delegation via POST /api/v1/delegations/delete"""
        # Mock bootstrap_state to return a bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=True, state="FINISHED")
            ),
        )

        # Mock get_task_id to return a deterministic task ID
        monkeypatch.setattr(
            f"{MOCK_PATH}.get_task_id",
            pretend.call_recorder(lambda: "fake_task_id"),
        )

        # Mock repository_metadata.apply_async
        mock_apply_async = pretend.call_recorder(lambda **kw: None)
        monkeypatch.setattr(
            f"{MOCK_PATH}.repository_metadata",
            pretend.stub(apply_async=mock_apply_async),
        )

        # Mock datetime
        monkeypatch.setattr(f"{MOCK_PATH}.datetime", fake_datetime)

        # Create delete payload
        payload = {"delegations": {"roles": [{"name": "dev"}]}}

        # Make API request
        response = test_client.post(DELEGATIONS_DELETE_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert (
            response.url == f"{test_client.base_url}{DELEGATIONS_DELETE_URL}"
        )
        assert (
            response.json()["message"]
            == "Metadata delegation delete accepted."
        )
        assert response.json()["data"]["task_id"] == "fake_task_id"

        # Verify mocks were called correctly
        assert mock_apply_async.calls
        call_kwargs = mock_apply_async.calls[0].kwargs
        assert call_kwargs["task_id"] == "fake_task_id"
        assert call_kwargs["queue"] == "metadata_repository"
        assert call_kwargs["kwargs"]["action"] == "metadata_delegation"
        assert call_kwargs["kwargs"]["payload"]["action"] == "delete"

    def test_delete_delegation_no_bootstrap(self, test_client, monkeypatch):
        """Test error case when bootstrap is not complete"""
        # Mock bootstrap_state to return a non-bootstrapped state
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            pretend.call_recorder(
                lambda: BootstrapState(bootstrap=False, state="PRE")
            ),
        )

        # Create delete payload
        payload = {"delegations": {"roles": [{"name": "dev"}]}}

        # Make API request
        response = test_client.post(DELEGATIONS_DELETE_URL, json=payload)

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.json()
        assert "message" in response.json()["detail"]
        assert response.json()["detail"]["message"] == "Task not accepted."
        assert (
            "Requires bootstrap finished" in response.json()["detail"]["error"]
        )


class TestOnlineKeyPrivilege:
    """A role trusting a repository online key gains no privilege over it."""

    def _bootstrapped(self, monkeypatch, trusted_targets=None):
        monkeypatch.setattr(
            f"{MOCK_PATH}.bootstrap_state",
            lambda: BootstrapState(bootstrap=True, state="FINISHED"),
        )
        monkeypatch.setattr(
            f"{MOCK_PATH}.get_task_id", lambda: "fake_task_id"
        )
        monkeypatch.setattr(
            f"{MOCK_PATH}.repository_metadata",
            pretend.stub(apply_async=pretend.call_recorder(lambda **kw: None)),
        )
        _mock_settings(monkeypatch, trusted_targets=trusted_targets)

    @staticmethod
    def _targets_with(role_keyids):
        return {
            "signed": {
                "delegations": {
                    "keys": {},
                    "roles": [
                        {
                            "name": "packages",
                            "keyids": role_keyids,
                            "threshold": 1,
                            "paths": ["packages/*"],
                            "terminating": False,
                        }
                    ],
                }
            }
        }

    @staticmethod
    def _update_payload(keyids, keys=None):
        return {
            "delegations": {
                "keys": keys or {},
                "roles": [
                    {
                        "name": "packages",
                        "keyids": keyids,
                        "threshold": 1,
                        "paths": ["packages/*"],
                        "terminating": False,
                        "x-rstuf-expire-policy": 30,
                    }
                ],
            }
        }

    def test_update_cannot_remove_online_key(self, test_client, monkeypatch):
        # packages currently trusts the repository online key; an update
        # replacing it with an attacker-supplied key must be rejected.
        self._bootstrapped(
            monkeypatch, trusted_targets=self._targets_with([ONLINE_KEYID])
        )
        attacker_keyid = "a" * 64
        payload = self._update_payload(
            [attacker_keyid],
            keys={
                attacker_keyid: {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "attacker-public-value"},
                }
            },
        )

        response = test_client.put(DELEGATIONS_URL, json=payload)

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "cannot remove repository online key" in (
            response.json()["detail"]["error"]
        )

    def test_update_keeping_online_key_accepted(
        self, test_client, monkeypatch
    ):
        # Keeping the online key while adding an offline key is legitimate.
        self._bootstrapped(
            monkeypatch, trusted_targets=self._targets_with([ONLINE_KEYID])
        )
        extra_keyid = "b" * 64
        payload = self._update_payload(
            [ONLINE_KEYID, extra_keyid],
            keys={
                extra_keyid: {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "extra-public-value"},
                }
            },
        )

        response = test_client.put(DELEGATIONS_URL, json=payload)

        assert response.status_code == status.HTTP_202_ACCEPTED

    def test_add_is_not_restricted_by_current_state(
        self, test_client, monkeypatch
    ):
        # The guard applies to updates only: creating a role scoped to an
        # offline key is a normal, supported flow.
        self._bootstrapped(monkeypatch)
        offline_keyid = "c" * 64
        payload = self._update_payload(
            [offline_keyid],
            keys={
                offline_keyid: {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "offline-public-value"},
                }
            },
        )

        response = test_client.post(DELEGATIONS_URL, json=payload)

        assert response.status_code == status.HTTP_202_ACCEPTED
