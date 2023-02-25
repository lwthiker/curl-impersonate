import enum
import struct
import collections
from typing import List, Dict, Any

import yaml


# Special value to denote GREASE in various placements in the Client Hello.
# Intentionally negative so that it won't conflict with any real field.
TLS_GREASE = -1


class TLSVersion(enum.Enum):
    # See https://github.com/openssl/openssl/blob/master/include/openssl/prov_ssl.h
    TLS_VERSION_1_0 = 0x0301
    TLS_VERSION_1_1 = 0x0302
    TLS_VERSION_1_2 = 0x0303
    TLS_VERSION_1_3 = 0x0304

    # Special value to denote a GREASE randomized value.
    GREASE = TLS_GREASE

    @classmethod
    def has_value(cls, value):
        return value in [x.value for x in cls]


class TLSExtensionType(enum.Enum):
    # TLS extensions list
    # See https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    # for the official list, and
    # https://github.com/google/boringssl/blob/master/include/openssl/tls1.h
    # for BoringSSL's list of supported extensions
    server_name = 0
    status_request = 5
    supported_groups = 10
    ec_point_formats = 11
    signature_algorithms = 13
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    padding = 21
    extended_master_secret = 23
    compress_certificate = 27
    record_size_limit = 28
    delegated_credentials = 34
    session_ticket = 35
    pre_shared_key = 41
    supported_versions = 43
    psk_key_exchange_modes = 45
    keyshare = 51
    application_settings = 17513
    renegotiation_info = 65281

    # Special value to denote a GREASE extension.
    GREASE = TLS_GREASE


# Possible values for GREASE
TLS_GREASE_VALUES = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
]

# Structs for parsing TLS packets
TLS_RECORD_HEADER = "!BHH"
TLSRecordHeader = collections.namedtuple(
    "TLSRecordHeader",
    "type, version, length"
)

TLS_HANDSHAKE_HEADER = "!BBHH32sB"
TLSHandshakeHeader = collections.namedtuple(
    "TLSHandshakeHeader",
    "type, length_high, length_low, version, random, session_id_length"
)

TLS_EXTENSION_HEADER = "!HH"
TLSExtensionHeader = collections.namedtuple(
    "TLSExtensionHeader",
    "type, length"
)


def serialize_grease(l: List[Any]) -> List[Any]:
    return list(map(lambda x: "GREASE" if x == TLS_GREASE else x, l))


def unserialize_grease(l: List[Any]) -> List[Any]:
    return list(map(lambda x: TLS_GREASE if x == "GREASE" else x, l))


def parse_tls_int_list(data: bytes,
                       entry_size: int,
                       header_size: int = 2,
                       replace_grease=True):
    """Parse a TLS-encoded list of integers.

    This list format is common in TLS packets.
    It consists of a two-byte header indicating the total length
    of the list, with the entries following.

    The entries may be one of TLS_GREASE_VALUES, in which case they
    are replaced with the constant TLS_GREASE (unless replace_grease=False).

    Returns
    -------
    entries : list[int]
        List of entries extracted from the TLS-encoded list.
    size : int
        Total size, in bytes, of the list.
    """

    off = 0
    h = "!H" if header_size == 2 else "!B"
    (list_length, ) = struct.unpack_from(h, data, off)
    off += struct.calcsize(h)
    if list_length > len(data) - off:
        raise Exception(f"TLS list of integers too long: {list_length} bytes")

    entries = []
    s = "!H" if entry_size == 2 else "!B"
    for i in range(list_length // entry_size):
        (entry, ) = struct.unpack_from(s, data, off)
        off += struct.calcsize(s)
        if replace_grease and entry in TLS_GREASE_VALUES:
            entry = TLS_GREASE
        entries.append(entry)

    return entries, struct.calcsize(h) + list_length


def parse_tls_str_list(data: bytes):
    """Parse a TLS-encoded list of strings.

    Returns
    -------
    entries : list[str]
        List of entries extracted from the TLS-encoded list.
    size : int
        Total size, in bytes, of the list.
    """
    off = 0
    header_size = struct.calcsize("!H")
    (list_length, ) = struct.unpack_from("!H", data, off)
    off += header_size
    if list_length > len(data) - off:
        raise Exception("TLS list of strings too long")

    entries = []
    while off - header_size < list_length:
        (strlen, ) = struct.unpack_from("!B", data, off)
        off += struct.calcsize("!B")
        entries.append(data[off:off + strlen].decode())
        off += strlen

    return entries, struct.calcsize("!H") + list_length


class TLSExtensionSignature():
    """
    Signature of a TLS extension.

    Used to check if two TLS extensions are configured similarly.

    For TLS extensions that have internal parameters to be checked,
    a subclass should be created. Subclasses should implement to_dict(),
    from_dict() and from_bytes() classmethods. See the subclasses below.
    """

    # A registry of subclasses
    registry = {}

    def __init__(self,
                 ext_type: TLSExtensionType,
                 length=None):
        self.ext_type = ext_type
        self.length = length

    def __init_subclass__(cls, /, ext_type: TLSExtensionType, **kwargs):
        """Register subclasses to the registry"""
        super().__init_subclass__(**kwargs)
        cls.registry[ext_type] = cls
        cls.ext_type = ext_type

    def to_dict(self):
        """Serialize to a dict object.

        By default we serialize the type and length only.
        To serialize additional parameters, override this in a subclass.
        """
        d = {
            "type": self.ext_type.name,
        }
        if self.length is not None:
            d["length"] = self.length
        return d

    def equals(self, other: 'TLSExtensionSignature'):
        # To check equality, we just compare the dict serializations.
        return self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, d):
        """Unserialize a TLSExtensionSignature from a dict.

        Initializes the suitable subclass if exists, otherwise initializes
        a TLSExtensionSignature proper instance.
        """
        d = d.copy()
        ext_type = TLSExtensionType[d.pop("type")]
        if ext_type in cls.registry:
            return cls.registry[ext_type].from_dict(d)
        else:
            return TLSExtensionSignature(
                ext_type=ext_type,
                length=d.pop("length", None)
            )

    @classmethod
    def from_bytes(cls, ext: bytes):
        """Build a TLSExtensionSignature from a raw TLS extension.

        Parameters
        ----------
        ext : bytes
            Raw over-the-wire contents of the TLS extension.
        """
        off = 0
        header = TLSExtensionHeader._make(struct.unpack_from(
            TLS_EXTENSION_HEADER, ext, off
        ))
        off += struct.calcsize(TLS_EXTENSION_HEADER)
        if header.type in TLS_GREASE_VALUES:
            ext_type = TLSExtensionType.GREASE
        else:
            ext_type = TLSExtensionType(header.type)

        if ext_type in cls.registry:
            return cls.registry[ext_type].from_bytes(
                length=header.length,
                data=ext[off:off + header.length]
            )
        else:
            return TLSExtensionSignature(
                ext_type=ext_type,
                length=header.length
            )


class TLSExtensionGrease(TLSExtensionSignature,
        ext_type=TLSExtensionType.GREASE):
    def __init__(self, length, data=None):
        super().__init__(self.ext_type, length)
        self.data = data

    def to_dict(self):
        # Add the binary data to the serialization.
        d = super().to_dict()
        if self.data:
            d["data"] = self.data
        return d

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionGrease(d["length"], d.get("data"))

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return TLSExtensionGrease(length, data)


class TLSExtensionServerName(TLSExtensionSignature,
        ext_type=TLSExtensionType.server_name):
    def __init__(self):
        # Set length to None. Server names have differing lengths,
        # so the length should not be part of the signature.
        super().__init__(self.ext_type, length=None)

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionServerName()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return TLSExtensionServerName()


class TLSExtensionStatusRequest(TLSExtensionSignature,
        ext_type=TLSExtensionType.status_request):
    def __init__(self, length, status_request_type: int):
        super().__init__(self.ext_type, length=length)
        self.status_request_type = status_request_type

    def to_dict(self):
        d = super().to_dict()
        d["status_request_type"] = self.status_request_type
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionStatusRequest(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (status_request_type, ) = struct.unpack_from("!B", data, 0)
        return TLSExtensionStatusRequest(length, status_request_type)


class TLSExtensionSupportedGroups(TLSExtensionSignature,
        ext_type=TLSExtensionType.supported_groups):
    def __init__(self, length, supported_groups: List[int]):
        super().__init__(self.ext_type, length)
        self.supported_groups = supported_groups

    def to_dict(self):
        d = super().to_dict()
        d["supported_groups"] = serialize_grease(self.supported_groups)
        return d

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionSupportedGroups(
            length=d["length"],
            supported_groups=unserialize_grease(d["supported_groups"])
        )

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        groups, _ = parse_tls_int_list(data, entry_size=2)
        return TLSExtensionSupportedGroups(length, groups)


class TLSExtensionECPointFormats(TLSExtensionSignature,
        ext_type=TLSExtensionType.ec_point_formats):
    def __init__(self, length, ec_point_formats: List[int]):
        super().__init__(self.ext_type, length)
        self.ec_point_formats = ec_point_formats

    def to_dict(self):
        d = super().to_dict()
        d["ec_point_formats"] = self.ec_point_formats
        return d

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionECPointFormats(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        ec_point_formats, _ = parse_tls_int_list(
            data, entry_size=1, header_size=1
        )
        return TLSExtensionECPointFormats(length, ec_point_formats)


class TLSExtensionSignatureAlgorithms(TLSExtensionSignature,
        ext_type=TLSExtensionType.signature_algorithms):
    def __init__(self, length, sig_hash_algs: List[int]):
        super().__init__(self.ext_type, length=length)
        self.sig_hash_algs = sig_hash_algs

    def to_dict(self):
        d = super().to_dict()
        d["sig_hash_algs"] = self.sig_hash_algs
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionSignatureAlgorithms(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        sig_hash_algs, _ = parse_tls_int_list(data, entry_size=2)
        return TLSExtensionSignatureAlgorithms(length, sig_hash_algs)


class TLSExtensionALPN(TLSExtensionSignature,
        ext_type=TLSExtensionType.application_layer_protocol_negotiation):
    def __init__(self, length, alpn_list: List[str]):
        super().__init__(self.ext_type, length=length)
        self.alpn_list = alpn_list

    def to_dict(self):
        d = super().to_dict()
        d["alpn_list"] = self.alpn_list
        return d

    @classmethod
    def from_dict(cls, d):
        return TLSExtensionALPN(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        alpn_list, _ = parse_tls_str_list(data)
        return TLSExtensionALPN(length, alpn_list)


class TLSExtensionPadding(TLSExtensionSignature,
        ext_type=TLSExtensionType.padding):
    def __init__(self):
        # Padding has varying lengths, so don't include in the signature
        super().__init__(self.ext_type, length=None)
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionPadding()

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        return TLSExtensionPadding()


class TLSExtensionCompressCertificate(TLSExtensionSignature,
        ext_type=TLSExtensionType.compress_certificate):
    def __init__(self, length, algorithms):
        super().__init__(self.ext_type, length=length)
        self.algorithms = algorithms

    def to_dict(self):
        d = super().to_dict()
        d["algorithms"] = self.algorithms
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionCompressCertificate(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        algos, _ = parse_tls_int_list(data, entry_size=2, header_size=1)
        return TLSExtensionCompressCertificate(length, algos)


class TLSExtensionRecordSizeLimit(TLSExtensionSignature,
        ext_type=TLSExtensionType.record_size_limit):
    def __init__(self, length, record_size_limit):
        super().__init__(self.ext_type, length=length)
        self.record_size_limit = record_size_limit

    def to_dict(self):
        d = super().to_dict()
        d["record_size_limit"] = self.record_size_limit
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionRecordSizeLimit(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (limit, ) = struct.unpack("!H", data)
        return TLSExtensionRecordSizeLimit(length, limit)


class TLSExtensionDelegatedCredentials(TLSExtensionSignature,
        ext_type=TLSExtensionType.delegated_credentials):
    def __init__(self, length, sig_hash_algs):
        super().__init__(self.ext_type, length=length)
        self.sig_hash_algs = sig_hash_algs

    def to_dict(self):
        d = super().to_dict()
        d["sig_hash_algs"] = self.sig_hash_algs
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionDelegatedCredentials(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        algs, _ = parse_tls_int_list(data, entry_size=2)
        return TLSExtensionDelegatedCredentials(length, algs)


class TLSExtensionSupportedVersions(TLSExtensionSignature,
        ext_type=TLSExtensionType.supported_versions):
    def __init__(self, length, supported_versions: List[TLSVersion]):
        super().__init__(self.ext_type, length=length)
        self.supported_versions = supported_versions

    def to_dict(self):
        d = super().to_dict()
        d["supported_versions"] = list(map(
            lambda v: v.name,
            self.supported_versions
        ))
        return d
    
    @classmethod
    def from_dict(cls, d):
        supported_versions = list(map(
            lambda v: TLSVersion[v],
            d["supported_versions"]
        ))
        return TLSExtensionSupportedVersions(d["length"], supported_versions)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        versions, _ = parse_tls_int_list(data, entry_size=2, header_size=1)
        versions = list(map(lambda v: TLSVersion(v), versions))
        return TLSExtensionSupportedVersions(length, versions)


class TLSExtensionPSKKeyExchangeModes(TLSExtensionSignature,
        ext_type=TLSExtensionType.psk_key_exchange_modes):
    def __init__(self, length, psk_ke_mode):
        super().__init__(self.ext_type, length=length)
        self.psk_ke_mode = psk_ke_mode

    def to_dict(self):
        d = super().to_dict()
        d["psk_ke_mode"] = self.psk_ke_mode
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionPSKKeyExchangeModes(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        (ke_length, ke_mode) = struct.unpack_from("!BB", data, 0)
        if ke_length > 1:
            # Unsupported
            raise Exception("Failed to parse psk_key_exchange_modes extension")
        
        return TLSExtensionPSKKeyExchangeModes(length, ke_mode)


class TLSExtensionKeyshare(TLSExtensionSignature,
        ext_type=TLSExtensionType.keyshare):
    def __init__(self, length, key_shares):
        super().__init__(self.ext_type, length=length)
        self.key_shares = key_shares

    def to_dict(self):
        d = super().to_dict()
        d["key_shares"] = [
            {
                "group": "GREASE" if ks["group"] == TLS_GREASE else ks["group"],
                "length": ks["length"]
            }
            for ks in self.key_shares
        ]
        return d
    
    @classmethod
    def from_dict(cls, d):
        key_shares = [
            {
                "group": TLS_GREASE if ks["group"] == "GREASE" else ks["group"],
                "length": ks["length"]
            }
            for ks in d["key_shares"]
        ]
        return TLSExtensionKeyshare(d["length"], d["key_shares"])

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        off = 0
        (key_share_length, ) = struct.unpack_from("!H", data, off)
        off += struct.calcsize("!H")

        key_shares = []
        while off < length:
            (group, key_ex_length) = struct.unpack_from("!HH", data, off)
            key_shares.append({
                "group": TLS_GREASE if group in TLS_GREASE_VALUES else group,
                "length": key_ex_length
            })
            off += struct.calcsize("!HH")
            off += key_ex_length

        return TLSExtensionKeyshare(length, key_shares)


class TLSExtensionApplicationSettings(TLSExtensionSignature,
        ext_type=TLSExtensionType.application_settings):
    def __init__(self, length, alps_alpn_list):
        super().__init__(self.ext_type, length=length)
        self.alps_alpn_list = alps_alpn_list

    def to_dict(self):
        d = super().to_dict()
        d["alps_alpn_list"] = self.alps_alpn_list
        return d
    
    @classmethod
    def from_dict(cls, d):
        return TLSExtensionApplicationSettings(**d)

    @classmethod
    def from_bytes(cls, length: int, data: bytes):
        alpn, _ = parse_tls_str_list(data)
        return TLSExtensionApplicationSettings(length, alpn)


class TLSClientHelloSignature():
    """
    Signature of a TLS Client Hello message.

    Combines multiple parameters from a TLS Client Hello message into a
    signature that is used to check if two such messages are identical, up to
    various random values which may be present.

    Why not use JA3? (https://github.com/salesforce/ja3)
    Our signature is more extensive and covers more parameters. For example, it
    checks whether a session ID is present, or what values are sent inside
    TLS extensions such as ALPN.
    """

    def __init__(self,
                 record_version: TLSVersion,
                 handshake_version: TLSVersion,
                 session_id_length: int,
                 ciphersuites: List[int],
                 comp_methods: List[int],
                 extensions: List[TLSExtensionSignature]):
        """
        Initialize a new TLSClientHelloSignature.

        Signatures can be compared with one another to check if they are equal.

        Parameters
        ----------
        record_version : TLSVersion
            Represents the "tls.record.version" field of the Client Hello.
        handshake_version : TLSVersion
            Represents the "tls.handshake.type" field.
        session_id_length : int
            Represents the "tls.handshake.session_id_length" field.
        ciphersuites : list[int]
            Represents the "tls.handshake.ciphersuites" list of ciphersuites.
        comp_methods : list[int]
            Represents the "tls.handshake.comp_methods" list of compression
            methods.
        extensions : list[TLSExtensionSignature]
            Represents the list of TLS extensions in the Client Hello.
        """
        self.record_version = record_version
        self.handshake_version = handshake_version
        self.session_id_length = session_id_length
        self.ciphersuites = ciphersuites
        self.comp_methods = comp_methods
        self.extensions = extensions

    @property
    def extension_list(self):
        return list(map(lambda ext: ext.ext_type, self.extensions))

    def _is_permuted_extension(self, ext: TLSExtensionSignature):
        # Chrome permutes all TLS extensions except for GREASE and pre_shared_key
        # (and the trailing padding)
        return ext.ext_type not in [
            TLSExtensionType.GREASE,
            TLSExtensionType.pre_shared_key,
            TLSExtensionType.padding
        ]

    def _compare_extensions(
        self,
        other: 'TLSClientHelloSignature',
        allow_tls_permutation: bool = False
    ):
        """Compare the TLS extensions of two Client Hello messages."""
        # Check that the extension lists are identical in content.
        if set(self.extension_list) != set(other.extension_list):
            symdiff = list(set(self.extension_list).symmetric_difference(
                other.extension_list
            ))
            return False, (f"TLS extension lists differ: "
                           f"Symmatric difference {symdiff}")

        if not allow_tls_permutation and self.extension_list != other.extension_list:
            return False, "TLS extension lists identical but differ in order"

        # Check the extensions' parameters.
        for i, ext in enumerate(self.extensions):
            if allow_tls_permutation and self._is_permuted_extension(ext):
                # If TLS extension permutation is enabled, locate this extension
                # in the other signature by type.
                other_ext = next(
                    e for e in other.extensions if e.ext_type == ext.ext_type
                )
            else:
                other_ext = other.extensions[i]
            if not ext.equals(other_ext):
                ours = ext.to_dict()
                ours.pop("type")
                theirs = other_ext.to_dict()
                theirs.pop("type")
                msg = (f"TLS extension {ext.ext_type.name} is different. "
                       f"{ours} != {theirs}")
                return False, msg

        return True, None

    def _equals(
        self,
        other: 'TLSClientHelloSignature',
        allow_tls_permutation: bool = False
    ):
        """Check if another TLSClientHelloSignature is identical."""
        if self.record_version != other.record_version:
            msg = (f"TLS record versions differ: "
                      f"{self.record_version} != {other.record_version}")
            return False, msg

        if self.handshake_version != other.handshake_version:
            msg = (f"TLS handshake versions differ: "
                      f"{self.handshake_version} != "
                      f"{other.handshake_version}")
            return False, msg

        if self.session_id_length != other.session_id_length:
            msg = (f"TLS session ID lengths differ: "
                      f"{self.session_id_length} != {other.session_id_length}")
            return False, msg

        if self.ciphersuites != other.ciphersuites:
            msg = f"TLS ciphersuites differ in contents or order. "
            return False, msg

        if self.comp_methods != other.comp_methods:
            msg = f"TLS compression methods differ in contents or order. "
            return False, msg

        return self._compare_extensions(other, allow_tls_permutation)

    def equals(
        self,
        other: 'TLSClientHelloSignature',
        allow_tls_permutation: bool = False,
        reason: bool = False
    ):
        """Checks whether two Client Hello messages have the same signature.

        Parameters
        ----------
        other : TLSClientHelloSignature
            The signature of the other Client Hello message.
        allow_tls_permutation : bool
            Allow TLS extension permutations. If set to True, and the TLS
            extensions are identical between the signatures but differ in
            order, the signatures will be considered equal.
        reason : bool
            If True, returns an additional string describing the reason of the
            difference in case of a difference, and None otherwise.
        """
        equal, msg = self._equals(
            other,
            allow_tls_permutation=allow_tls_permutation
        )
        if reason:
            return equal, msg
        else:
            return equal

    def to_dict(self):
        """Serialize to a dict object."""
        return {
            "record_version": self.record_version.name,
            "handshake_version": self.handshake_version.name,
            "session_id_length": self.session_id_length,
            "ciphersuites": serialize_grease(self.ciphersuites),
            "comp_methods": self.comp_methods,
            "extensions": list(map(lambda ext: ext.to_dict(), self.extensions))
        }

    @classmethod
    def from_dict(cls, d):
        """Unserialize a TLSClientHelloSignature from a dict.

        Parameters
        ----------
        d : dict
            Client Hello signature encoded to a Python dict.

        Returns
        -------
        sig : TLSClientHelloSignature
            Signature constructed based on the dict representation.
        """
        return TLSClientHelloSignature(
            record_version=TLSVersion[d["record_version"]],
            handshake_version=TLSVersion[d["handshake_version"]],
            session_id_length=d["session_id_length"],
            ciphersuites=unserialize_grease(d["ciphersuites"]),
            comp_methods=d["comp_methods"],
            extensions=list(map(
                lambda ext: TLSExtensionSignature.from_dict(ext),
                d["extensions"]
            ))
        )

    @classmethod
    def from_bytes(cls, record: bytes):
        """Build a TLSClientHelloSignature from a Client Hello TLS record.

        Parameters
        ----------
        record : bytes
            Raw over-the-wire content of the Client Hello TLS record.

        Returns
        -------
        sig : TLSClientHelloSignature
            Signature of the TLS record.
        """
        off = 0
        record_header = TLSRecordHeader._make(struct.unpack_from(
            TLS_RECORD_HEADER, record, off
        ))
        off += struct.calcsize(TLS_RECORD_HEADER)

        if record_header.type != 0x16:
            raise Exception(
                f"TLS record not of type Handshake (0x16). "
                f"Got 0x{record_header.type:02x}"
            )

        if not TLSVersion.has_value(record_header.version):
            raise Exception(
                f"Unknown TLS version 0x{record_header.version:04x}"
            )

        if len(record) - off != record_header.length:
            raise Exception("Corrupt record length")

        handshake_header = TLSHandshakeHeader._make(struct.unpack_from(
            TLS_HANDSHAKE_HEADER, record, off
        ))

        if handshake_header.type != 0x01:
            raise Exception(
                f"TLS handshake not of type Client Hello (0x01). "
                f"Got 0x{handshake_header.type:02x}"
           )

        if (len(record) - off - 4 != 
            (handshake_header.length_high << 16) + handshake_header.length_low):
            raise Exception("Corrupt handshake length")

        off += struct.calcsize(TLS_HANDSHAKE_HEADER)

        if not TLSVersion.has_value(handshake_header.version):
            raise Exception(
                f"Unknown TLS version 0x{handshake_header.version:04x}"
            )

        off += handshake_header.session_id_length

        ciphersuites, s = parse_tls_int_list(record[off:], entry_size=2)
        off += s

        comp_methods, s = parse_tls_int_list(
            record[off:], entry_size=1, header_size=1, replace_grease=False
        )
        off += s

        (extensions_length, ) = struct.unpack_from("!H", record, off)
        off += struct.calcsize("!H")

        if len(record) - off != extensions_length:
            raise Exception(f"Corrupt TLS extensions length")

        extensions = []
        while off < len(record):
            (ext_type, ext_len) = struct.unpack_from(
                TLS_EXTENSION_HEADER, record, off
            )
            ext_total_len = ext_len + struct.calcsize(TLS_EXTENSION_HEADER)
            extensions.append(TLSExtensionSignature.from_bytes(
                record[off:off + ext_total_len]
            ))
            off += ext_total_len

        return TLSClientHelloSignature(
            record_version=TLSVersion(record_header.version),
            handshake_version=TLSVersion(handshake_header.version),
            session_id_length=handshake_header.session_id_length,
            ciphersuites=ciphersuites,
            comp_methods=comp_methods,
            extensions=extensions
        )


class HTTP2Signature:
    """
    The HTTP/2 signature of a browser.

    In HTTP/2 multiple parameters can be used to fingerprint the browser.
    Currently this class contains the following parameters:
    * The order of the HTTP/2 pseudo-headers.
    * The "regular" HTTP headers sent by the browser upon first connection to a
      website.
    """
    def __init__(self,
                 pseudo_headers: List[str],
                 headers: List[str]):
        self.pseudo_headers = pseudo_headers
        self.headers = headers

    def _equals(self, other: 'HTTP2Signature', reason: bool = False):
        if set(self.pseudo_headers) != set(other.pseudo_headers):
            symdiff = list(set(self.pseudo_headers).symmetric_difference(
                other.pseudo_headers
            ))
            msg = (f"HTTP/2 pseudo-headers differ: "
                   f"Symmetric difference {symdiff}")
            return False, msg

        if self.pseudo_headers != other.pseudo_headers:
            msg = (f"HTTP/2 pseudo-headers differ in order: "
                   f"{self.pseudo_headers} != {other.pseudo_headers}")
            return False, msg

        if self.headers != other.headers:
            msg = (f"HTTP/2 headers differ: "
                   f"{self.headers} != {other.headers}")
            return False, msg

        return True, None

    def equals(self, other: 'HTTP2Signature', reason: bool = False):
        """Checks whether two browsers have the same HTTP/2 signature.

        Parameters
        ----------
        other : HTTP2Signature
            The signature of the other browser.
        reason : bool
            If True, returns an additional string describing the reason of the
            difference in case of a difference, and None otherwise.
        """
        equal, msg = self._equals(other)
        if reason:
            return equal, msg
        else:
            return equal

    def to_dict(self):
        """Serialize to a dict object."""
        return {
            "pseudo_headers": self.pseudo_headers,
            "headers": self.headers
        }

    @classmethod
    def from_dict(cls, d):
        """Unserialize a HTTP2Signature from a dict.

        Parameters
        ----------
        d : dict
            HTTP/2 signature encoded to a Python dict.

        Returns
        -------
        sig : HTTP2Signature
            Signature constructed based on the dict representation.
        """
        return HTTP2Signature(**d)


class BrowserSignature:
    """
    Represents the network signature of a specific browser based on multiple
    network parameters.

    Attributes
    ----------
    tls_client_hello : TLSClientHelloSignature
        The signature of the browser's TLS Client Hello message.
        Can be None, in which case it is ignored.
    http2 : HTTP2Signature
        The HTTP/2 signature of the browser.
        Can be None, in which case it is ignored.
    options: dict
        Optional parameters specifying how to
    """

    def __init__(self,
                 tls_client_hello: TLSClientHelloSignature = None,
                 http2: HTTP2Signature = None,
                 options: Dict = None):
        self.tls_client_hello = tls_client_hello
        self.http2 = http2
        self.options = options

    def _equals(self, other: 'BrowserSignature'):
        # If one is None, so must be the other
        if (self.tls_client_hello is None) != (other.tls_client_hello is None):
            return False, "TLS signature present in one but not the other"

        if self.tls_client_hello is not None:
            equal, msg = self.tls_client_hello.equals(
                other.tls_client_hello, reason=True
            )
            if not equal:
                return equal, msg

        # If one is None, so must be the other
        if (self.http2 is None) != (other.http2 is None):
            return False, "HTTP2 signature present in one but not the other"

        if self.http2 is not None:
            equal, msg = self.http2.equals(other.http2, reason=True)
            if not equal:
                return equal, msg

        if (self.options is None) != (other.options is None):
            return False, "Options present in one signature but not the other"

        if self.options is not None:
            if self.options != other.options:
                msg = (f"Options differ: {self.options} != {other.options}")
                return False, msg

        return True, None

    def equals(self, other: 'BrowserSignature', reason: bool = False):
        """Checks whether two browsers have the same network signatures.

        Parameters
        ----------
        other : BrowserSignature
            The other browser's network signature
        reason : bool
            If True, returns an additional string describing the reason of the
            difference in case of a difference, and None otherwise.
        """
        equal, msg = self._equals(other)
        if reason:
            return equal, msg
        else:
            return equal

    def to_dict(self):
        """Serialize to a dict object."""
        d = {}
        if self.options is not None:
            d["options"] = self.options
        if self.tls_client_hello is not None:
            d["tls_client_hello"] = self.tls_client_hello.to_dict()
        if self.http2 is not None:
            d["http2"] = self.http2.to_dict()
        return d

    @classmethod
    def from_dict(cls, d):
        """Unserialize a BrowserSignature from a dict."""
        if d.get("tls_client_hello"):
            tls_client_hello=TLSClientHelloSignature.from_dict(
                d["tls_client_hello"]
            )
        else:
            tls_client_hello = None

        if d.get("http2"):
            http2 = HTTP2Signature.from_dict(d["http2"])
        else:
            http2 = None

        return BrowserSignature(
            tls_client_hello=tls_client_hello,
            http2=http2,
            options=d.get("options")
        )
