import base64
import hashlib
import io
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import select
from pydantic import SecretStr

import digital_forensics.storage as storage_module
from digital_forensics.identity import digest_token
from digital_forensics.models import AuditEvent, AuthSession, User
from digital_forensics.settings import Settings
from digital_forensics.storage import EvidenceObjectStore, VaultTransitClient

from support import authenticate, create_test_identity


class _FakeVault:
    def encrypt_data_key(self, data_key: bytes) -> str:
        return "vault:v1:" + base64.b64encode(data_key).decode("ascii")

    def decrypt_data_key(self, ciphertext: str) -> bytes:
        return base64.b64decode(ciphertext.removeprefix("vault:v1:"))


class _FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, dict[int, bytes]] = {}

    @staticmethod
    def _etag(body: bytes) -> str:
        return f'"{hashlib.md5(body).hexdigest()}"'

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kwargs: object):
        self.objects[Key] = Body
        return {"VersionId": "v1"}

    def create_multipart_upload(self, *, Bucket: str, Key: str, **kwargs: object):
        upload_id = str(uuid4())
        self.uploads[upload_id] = {}
        return {"UploadId": upload_id}

    def upload_part(
        self,
        *,
        Bucket: str,
        Key: str,
        UploadId: str,
        PartNumber: int,
        Body: bytes,
    ):
        self.uploads[UploadId][PartNumber] = Body
        return {"ETag": self._etag(Body)}

    def complete_multipart_upload(
        self,
        *,
        Bucket: str,
        Key: str,
        UploadId: str,
        MultipartUpload: dict[str, object],
    ):
        self.objects[Key] = b"".join(
            self.uploads[UploadId][number]
            for number in sorted(self.uploads[UploadId])
        )
        return {"VersionId": "v1"}

    def abort_multipart_upload(self, *, UploadId: str, **kwargs: object):
        self.uploads.pop(UploadId, None)

    def get_object(self, *, Key: str, **kwargs: object):
        body = self.objects[Key]
        return {"Body": io.BytesIO(body), "ETag": self._etag(body), "VersionId": "v1"}

    def delete_object(self, *, Key: str, **kwargs: object):
        self.objects.pop(Key, None)

    def close(self) -> None:
        pass


def _storage() -> EvidenceObjectStore:
    store = EvidenceObjectStore.__new__(EvidenceObjectStore)
    store._bucket = "test-bucket"
    store._vault = _FakeVault()
    store._s3 = _FakeS3()
    store._upload_slot = BoundedSemaphore(1)
    return store


def test_encrypted_object_round_trips_multipart_and_detects_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "PART_SIZE", 4)
    monkeypatch.setattr(storage_module, "READ_SIZE", 3)
    store = _storage()
    case_id = uuid4()
    evidence_id = uuid4()
    source = b"synthetic evidence bytes"
    stored = store.store(
        io.BytesIO(source),
        case_id=case_id,
        evidence_id=evidence_id,
    )

    verified = store.verify(
        object_key=stored.object_key,
        version_id=stored.version_id,
        encrypted_data_key=stored.encrypted_data_key,
        nonce=stored.nonce,
        tag=stored.tag,
        case_id=case_id,
        evidence_id=evidence_id,
        expected_sha256=stored.sha256,
        expected_size=stored.size_bytes,
    )
    plaintext = b"".join(
        store.stream(
            object_key=stored.object_key,
            verified=verified,
            encrypted_data_key=stored.encrypted_data_key,
            nonce=stored.nonce,
            tag=stored.tag,
            case_id=case_id,
            evidence_id=evidence_id,
        )
    )
    assert plaintext == source
    assert stored.sha256 == hashlib.sha256(source).hexdigest()

    store._s3.objects[stored.object_key] = b"tampered"
    with pytest.raises(storage_module.EvidenceIntegrityError):
        store.verify(
            object_key=stored.object_key,
            version_id=stored.version_id,
            encrypted_data_key=stored.encrypted_data_key,
            nonce=stored.nonce,
            tag=stored.tag,
            case_id=case_id,
            evidence_id=evidence_id,
            expected_sha256=stored.sha256,
            expected_size=stored.size_bytes,
        )


def test_empty_evidence_round_trips() -> None:
    store = _storage()
    case_id = uuid4()
    evidence_id = uuid4()
    stored = store.store(io.BytesIO(b""), case_id=case_id, evidence_id=evidence_id)
    verified = store.verify(
        object_key=stored.object_key,
        version_id=stored.version_id,
        encrypted_data_key=stored.encrypted_data_key,
        nonce=stored.nonce,
        tag=stored.tag,
        case_id=case_id,
        evidence_id=evidence_id,
        expected_sha256=hashlib.sha256(b"").hexdigest(),
        expected_size=0,
    )
    assert b"".join(
        store.stream(
            object_key=stored.object_key,
            verified=verified,
            encrypted_data_key=stored.encrypted_data_key,
            nonce=stored.nonce,
            tag=stored.tag,
            case_id=case_id,
            evidence_id=evidence_id,
        )
    ) == b""


def test_vault_transit_client_uses_encrypt_and_decrypt_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_key = b"key material for a test object".ljust(32, b"!")
    captured: list[dict[str, object]] = []

    class _Response:
        def __init__(self, value: str) -> None:
            self.value = value

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, object]:
            return {"data": self.value}

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            pass

        def post(self, url: str, *, json: dict[str, str], headers: dict[str, str]):
            captured.append({"url": url, "json": json, "headers": headers})
            if "/encrypt/" in url:
                return _Response({"ciphertext": f"vault:v1:{json['plaintext']}"})
            return _Response({"plaintext": json["ciphertext"].removeprefix("vault:v1:")})

        def close(self) -> None:
            pass

    monkeypatch.setattr(storage_module.httpx, "Client", _Client)
    settings = Settings(
        evidence_s3_bucket="test-bucket",
        vault_addr="https://vault.example.test",
        vault_token=SecretStr("test-vault-token"),
        vault_transit_key="evidence",
    )
    vault = VaultTransitClient(settings)

    wrapped = vault.encrypt_data_key(data_key)
    assert vault.decrypt_data_key(wrapped) == data_key
    vault.close()

    assert [call["url"] for call in captured] == [
        "https://vault.example.test/v1/transit/encrypt/evidence",
        "https://vault.example.test/v1/transit/decrypt/evidence",
    ]
    assert captured[0]["headers"]["X-Vault-Token"] == "test-vault-token"
    assert captured[0]["json"]["plaintext"] == base64.b64encode(data_key).decode()


@pytest.mark.anyio
async def test_uploaded_evidence_is_encrypted_and_verified_before_download(
    client: AsyncClient,
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "PART_SIZE", 4)
    monkeypatch.setattr(storage_module, "READ_SIZE", 3)
    identity = create_test_identity(app)
    authenticate(client, identity)
    case = await client.post(
        f"/organizations/{identity['organization_id']}/cases",
        json={"case_number": "STORE-001", "name": "Storage test"},
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )
    assert case.status_code == 201
    case_id = case.json()["id"]
    store = _storage()
    app.state.evidence_storage = store
    source = b"synthetic uploaded evidence"

    uploaded = await client.post(
        f"/cases/{case_id}/evidence/upload",
        data={
            "evidence_number": "STORE-E1",
            "name": "evidence.bin",
            "acquisition_method": "synthetic upload",
            "source_description": "Test fixture",
            "acquired_at": "2026-01-01T00:00:00+00:00",
        },
        files={"file": ("evidence.bin", source, "application/octet-stream")},
        headers={"X-CSRF-Token": str(identity["csrf_token"])},
    )

    assert uploaded.status_code == 201
    evidence = uploaded.json()
    assert evidence["binary_available"] is True
    assert evidence["size_bytes"] == len(source)
    assert evidence["original_sha256"] == hashlib.sha256(source).hexdigest()
    object_key = f"cases/{case_id}/evidence/{evidence['id']}"
    assert store._s3.objects[object_key] != source

    downloaded = await client.get(f"/evidence/{evidence['id']}/binary")
    assert downloaded.status_code == 200
    assert downloaded.content == source
    assert downloaded.headers["cache-control"] == "private, no-store"

    with app.state.session_factory() as db:
        audit = db.scalars(
            select(AuditEvent).where(AuditEvent.case_id == UUID(case_id))
        ).all()
        assert "evidence.binary_download_requested" in {
            event.action for event in audit
        }


@pytest.mark.anyio
async def test_unassigned_user_cannot_download_evidence(
    client: AsyncClient,
    app: FastAPI,
) -> None:
    owner = create_test_identity(app)
    authenticate(client, owner)
    case = await client.post(
        f"/organizations/{owner['organization_id']}/cases",
        json={"case_number": "STORE-002", "name": "Private storage case"},
        headers={"X-CSRF-Token": str(owner["csrf_token"])},
    )
    evidence = await client.post(
        f"/cases/{case.json()['id']}/evidence",
        json={
            "evidence_number": "STORE-E2",
            "name": "Metadata only",
            "size_bytes": 1,
            "original_sha256": "a" * 64,
            "acquisition_method": "manual",
            "source_description": "Synthetic",
            "acquired_at": "2026-01-01T00:00:00+00:00",
        },
        headers={"X-CSRF-Token": str(owner["csrf_token"])},
    )
    token = "storage-outsider-session"
    csrf = "storage-outsider-csrf"
    with app.state.session_factory() as db:
        outsider = User(email="storage-outsider@example.test", display_name="Outsider")
        db.add(outsider)
        db.flush()
        db.add(
            AuthSession(
                user_id=outsider.id,
                token_digest=digest_token(token),
                csrf_digest=digest_token(csrf),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()
    authenticate(client, {"raw_session_token": token, "csrf_token": csrf})

    response = await client.get(f"/evidence/{evidence.json()['id']}/binary")
    assert response.status_code == 404
    upload_response = await client.post(
        f"/cases/{case.json()['id']}/evidence/upload",
        content=b"malformed multipart body",
        headers={
            "X-CSRF-Token": csrf,
            "Content-Type": "multipart/form-data; boundary=missing",
        },
    )
    assert upload_response.status_code == 404
