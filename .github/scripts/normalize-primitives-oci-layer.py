#!/usr/bin/env python3
import pathlib
import sys


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: normalize-primitives-oci-layer.py LAYER")

    path = pathlib.Path(sys.argv[1])
    archive = bytearray(path.read_bytes())
    if len(archive) % 512 != 0:
        raise SystemExit("OCI layer is not block aligned")

    offset = 0
    entries = 0
    while offset + 512 <= len(archive):
        header = archive[offset : offset + 512]
        if not any(header):
            break
        try:
            size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
        except ValueError as error:
            raise SystemExit("OCI layer has an invalid size field") from error

        header[329:337] = b"0000000\0"
        header[337:345] = b"0000000\0"
        header[148:156] = b"        "
        checksum = sum(header)
        if checksum > 0o777777:
            raise SystemExit("OCI layer checksum is out of range")
        header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
        archive[offset : offset + 512] = header
        offset += 512 + ((size + 511) // 512) * 512
        entries += 1

    if entries == 0 or any(archive[offset:]) or len(archive) - offset < 1024:
        raise SystemExit("OCI layer has an invalid terminator")
    path.write_bytes(archive)


if __name__ == "__main__":
    main()
