"""Minimal DER reader for X.509 and PKCS key metadata.

Only structural fields are returned. Private-key OCTET STRING bodies are
discarded after a length or algorithm is read.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_INTEGER = 0x02
_TAG_OID = 0x06
_TAG_OCTET = 0x04
_TAG_BITSTRING = 0x03
_TAG_UTCTIME = 0x17
_TAG_GENTIME = 0x18
_TAG_UTF8 = 0x0C
_TAG_PRINTABLE = 0x13
_TAG_IA5 = 0x16
_TAG_T61 = 0x14
_TAG_BMP = 0x1E
_TAG_BOOLEAN = 0x01
_TAG_CONTEXT_0 = 0xA0
_TAG_CONTEXT_1 = 0xA1
_TAG_CONTEXT_2 = 0xA2
_TAG_CONTEXT_3 = 0xA3
_TAG_CONTEXT_IMPLICIT_0 = 0x80
_TAG_CONTEXT_IMPLICIT_1 = 0x81
_TAG_CONTEXT_IMPLICIT_2 = 0x82
_TAG_CONTEXT_IMPLICIT_7 = 0x87

_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "RSA",
    "1.2.840.113549.1.1.11": "RSA",
    "1.2.840.113549.1.1.12": "RSA",
    "1.2.840.113549.1.1.13": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10045.4.3.2": "ECDSA",
    "1.2.840.10045.4.3.3": "ECDSA",
    "1.2.840.10045.4.3.4": "ECDSA",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10040.4.3": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.10": "RSA",
    "1.2.840.10045.3.1.7": "secp256r1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.132.0.10": "secp256k1",
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.29.17": "subjectAltName",
}

_SIGNATURE_HASH: dict[str, str] = {
    "1.2.840.113549.1.1.5": "SHA-1",
    "1.2.840.113549.1.1.11": "SHA-256",
    "1.2.840.113549.1.1.12": "SHA-384",
    "1.2.840.113549.1.1.13": "SHA-512",
    "1.2.840.10045.4.3.2": "SHA-256",
    "1.2.840.10045.4.3.3": "SHA-384",
    "1.2.840.10045.4.3.4": "SHA-512",
}


class DerError(ValueError):
    """The buffer is not a well-formed DER value."""


@dataclass
class CertificateMetadata:
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    validity_start: str | None = None
    validity_end: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    key_size: int | None = None
    curve: str | None = None
    san: tuple[str, ...] = ()
    chain: bool = False


@dataclass
class KeyMetadata:
    algorithm: str | None = None
    key_size: int | None = None
    curve: str | None = None
    format: str = "PEM"


class DerReader:
    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def peek(self) -> int:
        if self.pos >= self.end:
            raise DerError("truncated")
        return self.data[self.pos]

    def _read_length(self) -> int:
        if self.pos >= self.end:
            raise DerError("truncated length")
        first = self.data[self.pos]
        self.pos += 1
        if first < 0x80:
            return first
        count = first & 0x7F
        if count == 0 or count > 4 or self.pos + count > self.end:
            raise DerError("invalid length")
        value = int.from_bytes(self.data[self.pos : self.pos + count], "big")
        self.pos += count
        return value

    def read_tlv(self) -> tuple[int, bytes]:
        if self.pos >= self.end:
            raise DerError("truncated tag")
        tag = self.data[self.pos]
        self.pos += 1
        length = self._read_length()
        if self.pos + length > self.end:
            raise DerError("truncated value")
        value = self.data[self.pos : self.pos + length]
        self.pos += length
        return tag, value

    def read_sequence(self) -> "DerReader":
        tag, value = self.read_tlv()
        if tag != _TAG_SEQUENCE:
            raise DerError("expected SEQUENCE")
        return DerReader(value)

    def maybe_explicit(self, tag: int) -> "DerReader | None":
        if self.remaining() and self.peek() == tag:
            _tag, value = self.read_tlv()
            return DerReader(value)
        return None

    def read_integer_bytes(self) -> bytes:
        tag, value = self.read_tlv()
        if tag != _TAG_INTEGER:
            raise DerError("expected INTEGER")
        return value

    def read_integer(self) -> int:
        return int.from_bytes(self.read_integer_bytes() or b"\x00", "big")

    def read_oid(self) -> str:
        tag, value = self.read_tlv()
        if tag != _TAG_OID:
            raise DerError("expected OID")
        return _decode_oid(value)

    def skip(self) -> None:
        self.read_tlv()


def _decode_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    parts = [value[0] // 40, value[0] % 40]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(current)
            current = 0
    return ".".join(str(part) for part in parts)


def _decode_time(tag: int, value: bytes) -> str | None:
    text = value.decode("ascii", errors="replace")
    if tag == _TAG_UTCTIME and len(text) >= 13 and text.endswith("Z"):
        year = int(text[0:2])
        year += 1900 if year >= 50 else 2000
        return f"{year:04d}-{text[2:4]}-{text[4:6]}T{text[6:8]}:{text[8:10]}:{text[10:12]}Z"
    if tag == _TAG_GENTIME and len(text) >= 15 and text.endswith("Z"):
        return f"{text[0:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}Z"
    return None


def _decode_string(tag: int, value: bytes) -> str:
    if tag == _TAG_BMP:
        return value.decode("utf-16-be", errors="replace")
    return value.decode("utf-8", errors="replace")


def _decode_name(reader: DerReader) -> str:
    parts: list[str] = []
    while reader.remaining():
        tag, rdn = reader.read_tlv()
        if tag != _TAG_SET:
            continue
        inner = DerReader(rdn)
        while inner.remaining():
            attr = inner.read_sequence()
            try:
                oid = attr.read_oid()
                atag, aval = attr.read_tlv()
            except DerError:
                continue
            label = _OIDS.get(oid, oid)
            parts.append(f"{label}={_decode_string(atag, aval)}")
    return ", ".join(parts) or None  # type: ignore[return-value]


def _algorithm_identifier(reader: DerReader) -> tuple[str | None, str | None]:
    body = reader.read_sequence()
    oid = body.read_oid()
    curve = None
    if body.remaining() and body.peek() == _TAG_OID:
        parameter = body.read_oid()
        curve = _OIDS.get(parameter) if parameter in _OIDS and _OIDS[parameter].startswith("secp") else None
        if parameter in _OIDS and _OIDS[parameter] in {"secp256r1", "secp384r1", "secp521r1", "secp256k1"}:
            curve = _OIDS[parameter]
    return _OIDS.get(oid), curve


def parse_certificate(der: bytes) -> CertificateMetadata | None:
    try:
        cert = DerReader(der).read_sequence()
        tbs = cert.read_sequence()
        version_wrapper = tbs.maybe_explicit(_TAG_CONTEXT_0)
        if version_wrapper is not None:
            version_wrapper.read_integer()
        serial = tbs.read_integer_bytes()
        signature_oid, _curve = _algorithm_identifier(tbs)
        issuer = _decode_name(tbs.read_sequence())
        validity = tbs.read_sequence()
        start_tag, start_value = validity.read_tlv()
        end_tag, end_value = validity.read_tlv()
        subject = _decode_name(tbs.read_sequence())
        spki = tbs.read_sequence()
        public_algorithm, curve = _algorithm_identifier(spki)
        key_size = None
        if spki.remaining() and spki.peek() == _TAG_BITSTRING:
            _tag, bitstring = spki.read_tlv()
            key_bytes = bitstring[1:] if bitstring else b""
            if public_algorithm == "RSA":
                key_size = _rsa_modulus_bits(key_bytes)
            elif public_algorithm in {"EC", "ECDSA"} and curve is None:
                curve = _ec_curve_from_spki(key_bytes)
        san: list[str] = []
        tbs.maybe_explicit(_TAG_CONTEXT_1)
        tbs.maybe_explicit(_TAG_CONTEXT_2)
        extensions = tbs.maybe_explicit(_TAG_CONTEXT_3)
        if extensions is not None:
            san.extend(_subject_alt_names(extensions))
        return CertificateMetadata(
            subject=subject,
            issuer=issuer,
            serial_number=serial.hex() if serial else None,
            validity_start=_decode_time(start_tag, start_value),
            validity_end=_decode_time(end_tag, end_value),
            signature_algorithm=signature_oid,
            public_key_algorithm=public_algorithm,
            key_size=key_size,
            curve=curve,
            san=tuple(san),
            chain=bool(subject and issuer and subject != issuer),
        )
    except DerError:
        return None


def parse_pkcs1_rsa_key(der: bytes) -> KeyMetadata | None:
    try:
        body = DerReader(der).read_sequence()
        body.read_integer()
        modulus = body.read_integer_bytes()
        return KeyMetadata(algorithm="RSA", key_size=_bit_length(modulus), format="PEM")
    except DerError:
        return None


def parse_pkcs1_ec_key(der: bytes) -> KeyMetadata | None:
    try:
        body = DerReader(der).read_sequence()
        body.read_integer()
        if body.remaining() and body.peek() == _TAG_OCTET:
            body.read_tlv()
        curve = None
        parameters = body.maybe_explicit(_TAG_CONTEXT_0)
        if parameters is not None and parameters.remaining() and parameters.peek() == _TAG_OID:
            oid = parameters.read_oid()
            curve = _OIDS.get(oid)
        return KeyMetadata(algorithm="EC", curve=curve if curve and curve.startswith("secp") else curve, format="PEM")
    except DerError:
        return None


def parse_pkcs8_key(der: bytes) -> KeyMetadata | None:
    try:
        body = DerReader(der).read_sequence()
        body.read_integer()
        algorithm, curve = _algorithm_identifier(body)
        key_size = None
        if body.remaining() and body.peek() == _TAG_OCTET:
            _tag, octet = body.read_tlv()
            if algorithm == "RSA":
                nested = parse_pkcs1_rsa_key(octet)
                if nested:
                    key_size = nested.key_size
            elif algorithm in {"EC", "ECDSA"} and curve is None:
                nested = parse_pkcs1_ec_key(octet)
                if nested and nested.curve:
                    curve = nested.curve
            octet = b""
        return KeyMetadata(algorithm=algorithm, key_size=key_size, curve=curve, format="PEM")
    except DerError:
        return None


def _rsa_modulus_bits(bitstring_payload: bytes) -> int | None:
    try:
        sequence = DerReader(bitstring_payload).read_sequence()
        return _bit_length(sequence.read_integer_bytes())
    except DerError:
        return None


def _ec_curve_from_spki(_key_bytes: bytes) -> str | None:
    return None


def _subject_alt_names(extensions_wrapper: DerReader) -> list[str]:
    names: list[str] = []
    try:
        extensions = extensions_wrapper.read_sequence() if extensions_wrapper.peek() == _TAG_SEQUENCE else extensions_wrapper
        while extensions.remaining():
            item = extensions.read_sequence()
            oid = item.read_oid()
            if item.remaining() and item.peek() == _TAG_BOOLEAN:
                item.read_tlv()
            if _OIDS.get(oid) != "subjectAltName" or not item.remaining():
                continue
            _tag, value = item.read_tlv()
            if _tag != _TAG_OCTET:
                continue
            general = DerReader(value).read_sequence()
            while general.remaining():
                tag, payload = general.read_tlv()
                if tag == _TAG_CONTEXT_IMPLICIT_2:
                    names.append(payload.decode("ascii", errors="replace"))
                elif tag == _TAG_CONTEXT_IMPLICIT_7 and len(payload) == 4:
                    names.append(".".join(str(part) for part in payload))
    except DerError:
        return names
    return names


def _bit_length(modulus: bytes) -> int:
    stripped = modulus.lstrip(b"\x00")
    return len(stripped) * 8 if stripped else 0


def decode_pem_blocks(text: str) -> list[tuple[str, bytes]]:
    """Return (label, der) pairs. Private-key DER is for metadata only."""
    blocks: list[tuple[str, bytes]] = []
    marker = "-----BEGIN "
    end_marker = "-----END "
    index = 0
    while True:
        start = text.find(marker, index)
        if start < 0:
            return blocks
        line_end = text.find("\n", start)
        header = text[start + len(marker) : line_end if line_end > 0 else start + 40]
        label = header.split("-", 1)[0].strip()
        finish = text.find(end_marker, start)
        if finish < 0:
            return blocks
        body_start = text.find("\n", start)
        body = text[body_start + 1 : finish] if body_start > 0 else ""
        payload = "".join(line.strip() for line in body.splitlines() if not line.startswith("-----"))
        try:
            der = base64.b64decode(payload, validate=False)
        except (ValueError, OSError):
            der = b""
        blocks.append((label, der))
        index = finish + len(end_marker)
