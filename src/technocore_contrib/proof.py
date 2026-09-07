from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


@dataclass(frozen=True)
class Contribution:
    did: str
    contribution: str
    revision: str

    def to_dict(self) -> dict[str, str]:
        return {
            "did": self.did,
            "contribution": self.contribution,
            "revision": self.revision,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
        )


@dataclass(frozen=True)
class ContributionProof:
    contribution: Contribution
    digest: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "contribution": self.contribution.to_dict(),
            "digest": self.digest,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=2,
        )


def create_proof(
    contribution: Contribution,
    private_key: Ed25519PrivateKey,
) -> ContributionProof:
    payload = contribution.canonical_bytes()

    digest = hashlib.sha256(payload).hexdigest()

    signature = base64.urlsafe_b64encode(
        private_key.sign(payload)
    ).decode("ascii").rstrip("=")

    return ContributionProof(
        contribution=contribution,
        digest=digest,
        signature=signature,
    )
