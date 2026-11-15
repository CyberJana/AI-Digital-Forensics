import base64
import binascii
import hashlib
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from secrets import token_bytes
from threading import BoundedSemaphore
from typing import BinaryIO
from uuid import UUID

import boto3
import httpx
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from digital_forensics.settings import Settings

logger = logging.getLogger(__name__)
PART_SIZE = 64 * 1024 * 1024
READ_SIZE = 1024 * 1024
MAX_MULTIPART_PARTS = 10_000


class StorageUnavailable(Exception):
    pass


class StorageBusy(Exception):
    pass


class EvidenceTooLarge(Exception):
    pass


class EvidenceIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class StoredEvidence:
    object_key: str
    version_id: str | None
    encrypted_data_key: str
    nonce: str
    tag: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class VerifiedObject:
    version_id: str | None
    etag: str


class VaultTransitClient:
    def __init__(self, settings: Settings) -> None:
        if settings.vault_addr is None or settings.vault_transit_key is None:
            raise ValueError("Vault Transit is not configured")
        self._base_url = f"{settings.vault_addr.rstrip('/')}/v1/transit"
        self._key_name = settings.vault_transit_key
        self._static_token = settings.vault_token
        self._token_file = settings.vault_token_file
        self._namespace = settings.vault_namespace
        self._client = httpx.Client(timeout=30.0)

    def close(self) -> None:
        self._client.close()

    def encrypt_data_key(self, data_key: bytes) -> str:
        response = self._post(
            "encrypt",
            {"plaintext": base64.b64encode(data_key).decode("ascii")},
        )
        ciphertext = response.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:v"):
            raise StorageUnavailable("Vault Transit returned an invalid wrapped key")
        return ciphertext

    def decrypt_data_key(self, ciphertext: str) -> bytes:
        response = self._post("decrypt", {"ciphertext": ciphertext})
        plaintext = response.get("plaintext")
        if not isinstance(plaintext, str):
            raise StorageUnavailable("Vault Transit returned an invalid data key")
        try:
            data_key = base64.b64decode(plaintext, validate=True)
        except (binascii.Error, ValueError) as error:
            raise StorageUnavailable("Vault Transit returned an invalid data key") from error
        if len(data_key) != 32:
            raise StorageUnavailable("Vault Transit returned an invalid data key")
        return data_key

    def _post(self, operation: str, body: dict[str, str]) -> dict[str, object]:
        token = self._read_token()
        headers = {"X-Vault-Token": token}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        try:
            response = self._client.post(
                f"{self._base_url}/{operation}/{self._key_name}",
                json=body,
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise StorageUnavailable("Vault Transit request failed") from error
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("data"), dict)
        ):
            raise StorageUnavailable("Vault Transit returned an invalid response")
        return payload["data"]

    def _read_token(self) -> str:
        if self._token_file is not None:
            try:
                token = self._token_file.read_text(encoding="utf-8").strip()
            except OSError as error:
                raise StorageUnavailable("Vault Agent token is unavailable") from error
        elif self._static_token is not None:
            token = self._static_token.get_secret_value()
        else:
            raise StorageUnavailable("Vault Transit authentication is not configured")
        if not token:
            raise StorageUnavailable("Vault Agent token is empty")
        return token


class EvidenceObjectStore:
    def __init__(self, settings: Settings) -> None:
        if not settings.evidence_storage_enabled or settings.evidence_s3_bucket is None:
            raise ValueError("Encrypted evidence storage is not configured")
        self._bucket = settings.evidence_s3_bucket
        self._vault = VaultTransitClient(settings)
        self._upload_slot = BoundedSemaphore(1)
        self._s3 = boto3.client(
            "s3",
            region_name=settings.evidence_s3_region,
            endpoint_url=settings.evidence_s3_endpoint_url,
            aws_access_key_id=(
                settings.evidence_s3_access_key_id.get_secret_value()
                if settings.evidence_s3_access_key_id
                else None
            ),
            aws_secret_access_key=(
                settings.evidence_s3_secret_access_key.get_secret_value()
                if settings.evidence_s3_secret_access_key
                else None
            ),
            config=Config(
                signature_version="s3v4",
                s3={
                    "addressing_style": (
                        "path" if settings.evidence_s3_endpoint_url else "virtual"
                    )
                },
                max_pool_connections=4,
            ),
        )

    def close(self) -> None:
        self._vault.close()
        self._s3.close()

    def store(
        self,
        fileobj: BinaryIO,
        *,
        case_id: UUID,
        evidence_id: UUID,
    ) -> StoredEvidence:
        if not self._upload_slot.acquire(blocking=False):
            raise StorageBusy("Another evidence upload is in progress")
        try:
            return self._store(fileobj, case_id=case_id, evidence_id=evidence_id)
        finally:
            self._upload_slot.release()

    def _store(
        self,
        fileobj: BinaryIO,
        *,
        case_id: UUID,
        evidence_id: UUID,
    ) -> StoredEvidence:
        try:
            fileobj.seek(0, 2)
            expected_size = fileobj.tell()
            fileobj.seek(0)
        except (OSError, AttributeError) as error:
            raise EvidenceIntegrityError("Evidence upload must be seekable") from error
        if expected_size > PART_SIZE * MAX_MULTIPART_PARTS:
            raise EvidenceTooLarge(
                "Evidence exceeds the configured S3 multipart limit"
            )

        data_key = token_bytes(32)
        nonce = token_bytes(12)
        encrypted_data_key = self._vault.encrypt_data_key(data_key)
        encryptor = Cipher(
            algorithms.AES(data_key),
            modes.GCM(nonce),
        ).encryptor()
        encryptor.authenticate_additional_data(
            f"{case_id}:{evidence_id}".encode("ascii")
        )
        object_key = f"cases/{case_id}/evidence/{evidence_id}"
        digest = hashlib.sha256()
        actual_size = 0
        multipart_id: str | None = None
        completed = False
        part_number = 0
        parts: list[dict[str, object]] = []
        try:
            if expected_size <= PART_SIZE:
                plaintext = fileobj.read(PART_SIZE + 1)
                if len(plaintext) != expected_size:
                    raise EvidenceIntegrityError("Evidence upload changed while being read")
                digest.update(plaintext)
                actual_size = len(plaintext)
                ciphertext = encryptor.update(plaintext)
                encryptor.finalize()
                result = self._s3.put_object(
                    Bucket=self._bucket,
                    Key=object_key,
                    Body=ciphertext,
                    ContentType="application/octet-stream",
                )
                completed = True
            else:
                created = self._s3.create_multipart_upload(
                    Bucket=self._bucket,
                    Key=object_key,
                    ContentType="application/octet-stream",
                )
                multipart_id = created["UploadId"]
                while True:
                    plaintext = fileobj.read(PART_SIZE)
                    if not plaintext:
                        break
                    actual_size += len(plaintext)
                    digest.update(plaintext)
                    ciphertext = encryptor.update(plaintext)
                    part_number += 1
                    if part_number > MAX_MULTIPART_PARTS:
                        raise EvidenceTooLarge(
                            "Evidence exceeds the configured S3 multipart limit"
                        )
                    part = self._s3.upload_part(
                        Bucket=self._bucket,
                        Key=object_key,
                        UploadId=multipart_id,
                        PartNumber=part_number,
                        Body=ciphertext,
                    )
                    parts.append(
                        {"ETag": part["ETag"], "PartNumber": part_number}
                    )
                if actual_size != expected_size:
                    raise EvidenceIntegrityError("Evidence upload changed while being read")
                encryptor.finalize()
                result = self._s3.complete_multipart_upload(
                    Bucket=self._bucket,
                    Key=object_key,
                    UploadId=multipart_id,
                    MultipartUpload={"Parts": parts},
                )
                completed = True
        except (BotoCoreError, ClientError, OSError) as error:
            raise StorageUnavailable("Evidence object storage request failed") from error
        finally:
            if multipart_id is not None and not completed:
                try:
                    self._s3.abort_multipart_upload(
                        Bucket=self._bucket,
                        Key=object_key,
                        UploadId=multipart_id,
                    )
                except (BotoCoreError, ClientError):
                    logger.exception("Could not abort incomplete evidence upload")

        if actual_size != expected_size:
            raise EvidenceIntegrityError("Evidence upload size did not match")
        return StoredEvidence(
            object_key=object_key,
            version_id=result.get("VersionId"),
            encrypted_data_key=encrypted_data_key,
            nonce=base64.b64encode(nonce).decode("ascii"),
            tag=base64.b64encode(encryptor.tag).decode("ascii"),
            sha256=digest.hexdigest(),
            size_bytes=actual_size,
        )

    def delete(self, object_key: str, version_id: str | None = None) -> None:
        params: dict[str, str] = {"Bucket": self._bucket, "Key": object_key}
        if version_id:
            params["VersionId"] = version_id
        try:
            self._s3.delete_object(**params)
        except (BotoCoreError, ClientError) as error:
            raise StorageUnavailable("Could not remove incomplete evidence object") from error

    def verify(
        self,
        *,
        object_key: str,
        version_id: str | None,
        encrypted_data_key: str,
        nonce: str,
        tag: str,
        case_id: UUID,
        evidence_id: UUID,
        expected_sha256: str,
        expected_size: int,
    ) -> VerifiedObject:
        data_key = self._vault.decrypt_data_key(encrypted_data_key)
        nonce_bytes = self._decode(nonce, 12)
        tag_bytes = self._decode(tag, 16)
        params: dict[str, str] = {"Bucket": self._bucket, "Key": object_key}
        if version_id:
            params["VersionId"] = version_id
        try:
            response = self._s3.get_object(**params)
            body = response["Body"]
            try:
                decryptor = self._decryptor(
                    data_key, nonce_bytes, tag_bytes, case_id, evidence_id
                )
                digest = hashlib.sha256()
                size = 0
                while chunk := body.read(READ_SIZE):
                    plaintext = decryptor.update(chunk)
                    digest.update(plaintext)
                    size += len(plaintext)
                decryptor.finalize()
            finally:
                body.close()
        except InvalidTag as error:
            raise EvidenceIntegrityError("Stored evidence failed authentication") from error
        except (BotoCoreError, ClientError, OSError, KeyError) as error:
            raise StorageUnavailable("Could not read evidence object") from error
        if size != expected_size or digest.hexdigest() != expected_sha256:
            raise EvidenceIntegrityError("Stored evidence does not match its registered digest")
        etag = response.get("ETag")
        verified_version = response.get("VersionId") or version_id
        if not verified_version and not isinstance(etag, str):
            raise StorageUnavailable("Object storage did not provide an object validator")
        return VerifiedObject(version_id=verified_version, etag=etag or "")

    def stream(
        self,
        *,
        object_key: str,
        verified: VerifiedObject,
        encrypted_data_key: str,
        nonce: str,
        tag: str,
        case_id: UUID,
        evidence_id: UUID,
    ) -> Iterator[bytes]:
        data_key = self._vault.decrypt_data_key(encrypted_data_key)
        params: dict[str, str] = {"Bucket": self._bucket, "Key": object_key}
        if verified.version_id:
            params["VersionId"] = verified.version_id
        elif verified.etag:
            params["IfMatch"] = verified.etag
        try:
            response = self._s3.get_object(**params)
            body = response["Body"]
            try:
                decryptor = self._decryptor(
                    data_key,
                    self._decode(nonce, 12),
                    self._decode(tag, 16),
                    case_id,
                    evidence_id,
                )
                while chunk := body.read(READ_SIZE):
                    plaintext = decryptor.update(chunk)
                    if plaintext:
                        yield plaintext
                decryptor.finalize()
            finally:
                body.close()
        except InvalidTag as error:
            raise EvidenceIntegrityError("Stored evidence failed authentication") from error
        except (BotoCoreError, ClientError, OSError, KeyError) as error:
            raise StorageUnavailable("Could not stream evidence object") from error

    @staticmethod
    def _decode(value: str, expected_length: int) -> bytes:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise EvidenceIntegrityError("Stored evidence encryption metadata is invalid") from error
        if len(decoded) != expected_length:
            raise EvidenceIntegrityError("Stored evidence encryption metadata is invalid")
        return decoded

    @staticmethod
    def _decryptor(
        data_key: bytes,
        nonce: bytes,
        tag: bytes,
        case_id: UUID,
        evidence_id: UUID,
    ):
        decryptor = Cipher(
            algorithms.AES(data_key),
            modes.GCM(nonce, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(
            f"{case_id}:{evidence_id}".encode("ascii")
        )
        return decryptor
