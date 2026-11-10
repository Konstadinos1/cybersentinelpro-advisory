"""Detection of invisible-character and ASCII-smuggling payloads.

Attackers hide instructions from human reviewers using characters that
render as nothing: zero-width joiners, bidirectional overrides, and the
Unicode Tags block (U+E0000-U+E007F), which mirrors ASCII one-to-one and
is read by many tokenisers even though no UI displays it.
"""

from __future__ import annotations

from dataclasses import dataclass

TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F
TAG_ASCII_OFFSET = 0xE0000

ZERO_WIDTH_CODEPOINTS = frozenset(
    {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD, 0x180E}
)
BIDI_CONTROL_CODEPOINTS = frozenset(
    {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F}
)
VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


@dataclass(frozen=True)
class HiddenCharacterReport:
    """Summary of invisible characters found in one string."""

    zero_width_count: int
    bidi_control_count: int
    tag_character_count: int
    variation_selector_count: int
    decoded_tag_payload: str

    @property
    def total(self) -> int:
        return (
            self.zero_width_count
            + self.bidi_control_count
            + self.tag_character_count
            + self.variation_selector_count
        )


def _is_tag_character(codepoint: int) -> bool:
    return TAG_BLOCK_START <= codepoint <= TAG_BLOCK_END


def _is_variation_selector(codepoint: int) -> bool:
    return any(low <= codepoint <= high for low, high in VARIATION_SELECTOR_RANGES)


def is_hidden_character(character: str) -> bool:
    """True when the character is invisible in normal rendering."""
    codepoint = ord(character)
    return (
        codepoint in ZERO_WIDTH_CODEPOINTS
        or codepoint in BIDI_CONTROL_CODEPOINTS
        or _is_tag_character(codepoint)
        or _is_variation_selector(codepoint)
    )


def decode_tag_payload(text: str) -> str:
    """Recover the ASCII message hidden in Unicode Tag characters."""
    decoded = [
        chr(ord(character) - TAG_ASCII_OFFSET)
        for character in text
        if _is_tag_character(ord(character)) and 0x20 <= ord(character) - TAG_ASCII_OFFSET < 0x7F
    ]
    return "".join(decoded)


def inspect_hidden_characters(text: str) -> HiddenCharacterReport:
    """Count each class of invisible character and decode any tag payload."""
    codepoints = [ord(character) for character in text]
    return HiddenCharacterReport(
        zero_width_count=sum(cp in ZERO_WIDTH_CODEPOINTS for cp in codepoints),
        bidi_control_count=sum(cp in BIDI_CONTROL_CODEPOINTS for cp in codepoints),
        tag_character_count=sum(_is_tag_character(cp) for cp in codepoints),
        variation_selector_count=sum(_is_variation_selector(cp) for cp in codepoints),
        decoded_tag_payload=decode_tag_payload(text),
    )


def strip_hidden_characters(text: str) -> str:
    """Remove invisible characters so pattern rules see what the model sees."""
    return "".join(character for character in text if not is_hidden_character(character))
