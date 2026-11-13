"""
Generate the MaxMind DB test fixtures (``test_city.mmdb`` and
``test_country.mmdb``) without requiring the Perl MaxMind::DB::Writer module.

The produced files implement the subset of the MaxMind DB binary format that
is needed by the test-suite: a fixed-size search tree whose leaves point at
map records encoded in the data section.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

RECORD_SIZE = 24
IP_VERSION = 6

# MaxMind DB data section type numbers.
(
    POINTER,
    UTF8_STRING,
    DOUBLE,
    BYTES,
    UINT16,
    UINT32,
    MAP,
    INT32,
    UINT64,
    ARRAY,
    BOOLEAN,
) = (1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 14)


def _ctrl(type_num, size):
    if size < 29:
        size_bytes = bytes([size])
    elif size < 285:
        size_bytes = bytes([29, size - 29])
    elif size < 65821:
        size -= 285
        size_bytes = bytes([30, size >> 8, size & 0xFF])
    else:
        raise ValueError("payload too large")
    if type_num <= 7:
        return bytes([(type_num << 5) | size_bytes[0]]) + size_bytes[1:]
    # Extended type: a zero type field followed by type_num - 7.
    return bytes([size_bytes[0], type_num - 7]) + size_bytes[1:]


class Encoder:
    """
    Encode Python values into the MaxMind DB data section format.

    Strings are written inline the first time they are encountered; repeated
    strings reference the first occurrence through a pointer, which is how the
    canonical MaxMind writer serializes the metadata section and is required
    by the C reader for the ``languages`` array.
    """

    def __init__(self):
        self.buffer = bytearray()
        self.strings = {}

    def encode(self, value):
        if isinstance(value, str):
            return self._encode_string(value)
        if isinstance(value, bool):
            # The boolean type (14) uses the extended-type encoding.
            return _ctrl(BOOLEAN, 1 if value else 0)
        if isinstance(value, tuple) and value and value[0] == "uint64":
            length = (value[1].bit_length() + 7) // 8
            return _ctrl(UINT64, length) + value[1].to_bytes(length, "big")
        if isinstance(value, tuple) and value and value[0] == "uint32":
            length = (value[1].bit_length() + 7) // 8
            return _ctrl(UINT32, length) + value[1].to_bytes(length, "big")
        if isinstance(value, int):
            length = (value.bit_length() + 7) // 8
            type_num = UINT16 if length <= 2 else UINT32
            return _ctrl(type_num, length) + value.to_bytes(length, "big")
        if isinstance(value, float):
            return _ctrl(DOUBLE, 8) + struct.pack(">d", value)
        if isinstance(value, dict):
            out = _ctrl(MAP, len(value))
            for key, item in value.items():
                out += self._encode_inline_string(key)
                out += self.encode(item)
            return out
        if isinstance(value, (list, tuple)):
            out = _ctrl(ARRAY, len(value))
            for item in value:
                out += self.encode(item)
            return out
        if isinstance(value, (bytes, bytearray)):
            return _ctrl(BYTES, len(value)) + bytes(value)
        raise TypeError(f"unsupported value type: {type(value)!r}")

    def _encode_string(self, value):
        if value in self.strings:
            return self._pointer(self.strings[value])
        return self._encode_inline_string(value)

    def _encode_inline_string(self, value):
        offset = len(self.buffer)
        payload = value.encode("utf-8")
        self.buffer += _ctrl(UTF8_STRING, len(payload)) + payload
        self.strings.setdefault(value, offset)
        return _ctrl(UTF8_STRING, len(payload)) + payload

    @staticmethod
    def _pointer(offset):
        if offset < 2048:
            return bytes([0x20 | (offset >> 8), offset & 0xFF])
        if offset < 526336:
            offset -= 2048
            return bytes(
                [0x28 | (offset >> 16), (offset >> 8) & 0xFF, offset & 0xFF]
            )
        offset -= 526336
        return bytes(
            [0x30, (offset >> 24) & 0xFF, (offset >> 16) & 0xFF,
             (offset >> 8) & 0xFF, offset & 0xFF]
        )

    def finish(self, root):
        return self.encode(root) + bytes(self.buffer)


def _encode(value):
    return Encoder().encode(value)


class Tree:
    """
    IPv6 binary search tree. An explicit chain of 96 nodes with empty right
    records maps the ``::/96`` prefix to node 96, where IPv4 networks are
    inserted. The empty right records terminate IPv6 lookups outside the
    IPv4-mapped range, and every unallocated branch uses the empty record so
    that all lookups terminate cleanly.
    """

    def __init__(self):
        # node number -> (left record value, right record value)
        # A record value is either ("node", index) or ("data", offset).
        self.nodes = []
        for index in range(97):
            left = ("node", index + 1) if index < 96 else ("empty", None)
            self.nodes.append([left, ("empty", None)])

    def _new_node(self):
        self.nodes.append([("empty", None), ("empty", None)])
        return len(self.nodes) - 1

    def insert(self, network, data_offset):
        network = ipaddress.ip_network(network)
        if network.version == 4:
            prefix_offset = 96
        else:
            prefix_offset = 0
        address_bits = bin(int(network.network_address))[2:].zfill(
            network.max_prefixlen
        )
        node = prefix_offset
        for depth in range(network.prefixlen):
            bit = int(address_bits[depth])
            if depth == network.prefixlen - 1:
                self.nodes[node][bit] = ("data", data_offset)
                return
            record = self.nodes[node][bit]
            if record[0] == "empty":
                child = self._new_node()
                self.nodes[node][bit] = ("node", child)
                node = child
            else:
                node = record[1]

    def serialize(self, node_count):
        out = bytearray()
        for index in range(node_count):
            records = (
                self.nodes[index]
                if index < len(self.nodes)
                else [("empty", None), ("empty", None)]
            )
            for record in records:
                if record[0] == "empty":
                    value = node_count
                elif record[0] == "node":
                    value = record[1]
                else:
                    value = node_count + record[1]
                out += value.to_bytes(RECORD_SIZE // 8, "big")
        return bytes(out)


def write_database(path, database_type, records):
    data = bytearray(b"\x00" * 16)
    encoded_records = {}
    for network, value in records.items():
        offset = len(data)
        data += Encoder().finish(value)
        encoded_records[network] = offset

    tree = Tree()
    for network, offset in encoded_records.items():
        tree.insert(network, offset)
    node_count = len(tree.nodes)
    tree_section = tree.serialize(node_count)

    metadata = {
        "node_count": ("uint32", node_count),
        "record_size": RECORD_SIZE,
        "ip_version": IP_VERSION,
        "database_type": database_type,
        "languages": ["en"],
        "binary_format_major_version": 2,
        "binary_format_minor_version": 0,
        "build_epoch": ("uint64", 1770245369),
        "description": {"en": f"Test database of {database_type} data"},
    }
    metadata_section = Encoder().finish(metadata)

    Path(path).write_bytes(
        tree_section
        + bytes(data)
        + b"\xab\xcd\xefMaxMind.com"
        + metadata_section
    )


def main():
    base_dir = Path(__file__).resolve().parent
    write_database(
        base_dir / "test_city.mmdb",
        "GeoLite2-City",
        {
            "8.8.8.8/32": {
                "country": {
                    "iso_code": "US",
                    "names": {"en": "United States"},
                }
            },
            "44.55.66.77/32": {
                "city": {"names": {"en": "San Diego"}},
                "continent": {
                    "code": "NA",
                    "names": {"en": "North America"},
                },
                "country": {
                    "iso_code": "US",
                    "names": {"en": "United States"},
                },
                "is_in_european_union": False,
                "location": {
                    "latitude": 37.751,
                    "longitude": -97.822,
                    "metro_code": "custom metro code",
                    "time_zone": "America/Los Angeles",
                },
                "postal": {"code": "custom postal code"},
                "subdivisions": [
                    {
                        "iso_code": "ABC",
                        "names": {"en": "Absolute Basic Class"},
                    }
                ],
            }
        },
    )
    write_database(
        base_dir / "test_country.mmdb",
        "GeoLite2-Country",
        {
            "8.8.8.8/32": {
                "country": {
                    "iso_code": "US",
                    "names": {"en": "United States"},
                }
            }
        },
    )


if __name__ == "__main__":
    main()
