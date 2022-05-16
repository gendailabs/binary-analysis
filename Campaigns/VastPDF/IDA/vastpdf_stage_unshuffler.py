"""IDA Python script to decode obfuscated strings from the "VastPDF" second stage.

This script was written to handle the "VastPDF" second stage for macOS platforms. The
version analysed had an md5 of 5919fbc9152772e0962f4caad53f211a.

This script annotates all xrefs to an obfuscated string, and the address of the string
itself, with the unobfuscated value as a comment. This script also prints a JSON
document which contains all xrefs, the start and end of the obfuscated data, and the
unobfuscated string to the output window.
"""

import json
import re
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

import ida_bytes
from numpy import int8, int32, uint8, uint64

# Mask via 0x1000085C0 of "VastPDF" [macOS] (MD5: fcccbab43a9d556281f19cc73c73f329)
# fmt: off
SHUFFLE_MASK = bytearray([
    0x0, 0x4, 0x8, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
])
# fmt: on


@dataclass
class ObfuscatedString:
    """Container for obfuscated strings."""

    addr_start: int
    addr_end: int
    addr_xrefs: List[int]

    unshuffled: bytearray
    obfuscated: bytearray
    decoded: bytearray


def defang_scheme(scheme: str) -> str:
    """Attempts to defang a URI scheme."""
    if len(scheme) > 2:
        half = round(len(scheme) / 2)
        return f"{scheme[:1]}{'x'*half}{scheme[half + 1:]}"
    else:
        return f"{scheme[0]}x"


def defang_fqdn(fqdn: str) -> str:
    """Defangs an FQDN."""
    return fqdn.replace(".", "[.]")


def defang_uri(uri: str) -> str:
    """Attempts to defang a URI."""
    parsed = urlparse(uri)

    # Replace the relevant portions of the URI with the defanged counterparts.
    defanged = parsed._replace(
        scheme=defang_scheme(parsed.scheme),
        netloc=defang_fqdn(parsed.netloc),
    )

    return defanged.geturl()


def extract_fqdn(uri: str) -> str:
    """Attempts to extract and return a (defanged) FQDN from URI."""
    parsed = urlparse(uri)

    # Replace the relevant portions of the URI with the defanged counterparts.
    defanged = parsed._replace(
        scheme=defang_scheme(parsed.scheme),
        netloc=defang_fqdn(parsed.netloc),
    )

    return defanged.netloc


def pshufb(data, mask):
    """
    Naive implementation of the pshufb SSE intrinsic.

        PSHUFB: __m128i _mm_shuffle_epi8 (__m128i a, __m128i b)
    """
    result = bytearray(0x10)

    for i in range(0, 15):
        if mask[i] & 0x80 == 0x80:
            result[i] = 0x0
        else:
            try:
                result[i] = data[mask[i] & 0x0F]
            except IndexError:
                pass

    return result


def shift(buffer, offset):
    """Shift based on function at 0x100002330"""
    return uint64(
        ((int32(int8(buffer[0])) - offset) * 0x1A) + (int32(buffer[1])) - offset
    )


# Process the obfuscated string at the current address.
payload = None
candidate = None
addr = get_screen_ea()

while True:
    # Treat addresses with xrefs as the start of a new obfuscated string.
    if ida_bytes.has_xref(ida_bytes.get_flags(addr)):
        # Close out any previous objects, and track it.
        if candidate:
            candidate.addr_end = addr - 0x1
            payload = candidate
            break

        # Extract / record xrefs.
        xrefs = []

        for xref in XrefsTo(addr):
            xrefs.append(xref.frm)

        candidate = ObfuscatedString(
            addr_start=addr,
            addr_xrefs=xrefs,
            addr_end=None,
            obfuscated=bytearray(),
            unshuffled=bytearray(),
            decoded=bytearray(),
        )

    # Append the byte to the "open" object, if present.
    if candidate:
        candidate.obfuscated.append(ida_bytes.get_byte(addr))

    addr += 0x1


# Unshuffle the payload.
offset = 0x0
width = int(len(SHUFFLE_MASK))
adjust = int(len(SHUFFLE_MASK) / 0x4)

while offset < len(payload.obfuscated):
    xmm0 = SHUFFLE_MASK
    if offset + width > len(payload.obfuscated):
        xmm1 = payload.obfuscated[offset : len(payload.obfuscated)]
    else:
        xmm1 = payload.obfuscated[offset : offset + width]

    addr = int(offset / adjust)
    payload.unshuffled[addr : addr + adjust] = pshufb(xmm1, xmm0)[0:adjust]
    offset += width

# Unobfuscate.
repeat = 0x1
counter = 0x1

while len(payload.unshuffled) > counter:
    character = payload.unshuffled[counter]

    if character <= 0x5A:
        repeat = shift(payload.unshuffled[counter - 1 : counter + 1], 0x41)
    else:
        target = uint8(shift(payload.unshuffled[counter - 1 : counter + 1], 0x61))
        target = int8(target - 0x3D)  # 0x12693 % 0x6e

        if target < 0:
            target = int32(target + 0xFF)

        for count in range(0, repeat):
            payload.decoded.append(target)

        repeat = 1

    counter += 2

# Attempt to defang URLs. Note: This assumes only a single URL per string.
as_string = str(payload.decoded, "utf-8")

matches = re.findall("(https?://[^\s]+)", as_string)
for match in matches:
    as_string = as_string.replace(match, defang_uri(match))

# Add a comment to the xrefs and the start address containing the decoded payload.
idc.set_cmt(payload.addr_start, as_string, 0)

for addr in payload.addr_xrefs:
    idc.set_cmt(addr, as_string, 0)

# Finally dump the information to the console as JSON for review.
print(
    json.dumps(
        {
            "payload": as_string,
            "start": hex(payload.addr_start),
            "end": hex(payload.addr_end),
            "xrefs": [hex(x) for x in payload.addr_xrefs],
        },
        indent=4,
        sort_keys=True,
    )
)
