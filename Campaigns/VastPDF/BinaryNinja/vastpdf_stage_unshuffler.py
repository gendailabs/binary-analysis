"""BinaryNinja Python script to decode obfuscated strings from the VastPDF second stage.

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

from binaryninja import BinaryReader
from numpy import int8, int32, uint8, uint64

# VastPDF [macOS] [second-stage] (MD5: 5919fbc9152772e0962f4caad53f211a)
# fmt: off
SHUFFLE_MASK = bytearray([
    0x0, 0x4, 0x8, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
])
# fmt: on

# Quick check that we're running in Binja.
try:
    _ = type(here)
    br = BinaryReader(bv)
except NameError:
    raise Exception("Does not appear to be an interactive BinaryNinja session")


@dataclass
class ObfuscatedString:
    """Container for obfuscated strings."""

    address_start: int
    address_end: int
    address_xrefs: List[int]

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
    """Shift based on function at 0x100002330."""
    return uint64(
        ((int32(int8(buffer[0])) - offset) * 0x1A) + (int32(buffer[1])) - offset
    )


# Process the obfuscated string at the current address.
payload = None
candidate = None

while True:
    xrefs = []
    for xref in bv.get_code_refs(here):
        xrefs.append(xref.address)

    # Treat addresses with xrefs as the start of a new obfuscated string.
    if len(xrefs) > 0:
        # Close out any previous objects, and track it.
        if candidate:
            candidate.address_end = int(here) - 0x1
            payload = candidate
            break

        candidate = ObfuscatedString(
            address_start=int(here),
            address_xrefs=xrefs,
            address_end=None,
            obfuscated=bytearray(),
            unshuffled=bytearray(),
            decoded=bytearray(),
        )

    # Append the byte to the "open" object, if present.
    if candidate:
        candidate.obfuscated.append(br.read8(here))

    here += 0x1


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

# Attempt to defang URLs.
payload.decoded = str(payload.decoded, "utf-8")

matches = re.findall("(https?://[^\s]+)", payload.decoded)
for match in matches:
    payload.decoded = payload.decoded.replace(match, defang_uri(match))

# Add the unobfuscated string as a comment to all xrefs and the start address of the
# shuffled string.
bv.set_comment_at(payload.address_start, payload.decoded)

for addr in payload.address_xrefs:
    bv.set_comment_at(addr, payload.decoded)

# Finally dump the information to the console as JSON for review.
print(
    json.dumps(
        {
            "payload": payload.decoded,
            "start": hex(payload.address_start),
            "end": hex(payload.address_end),
            "xrefs": [hex(xref) for xref in payload.address_xrefs],
        },
        indent=4,
        sort_keys=True,
    )
)

# Skip backwards to the starting address.
here = payload.address_start
