"""Image CAPTCHA generation for in-Discord verification.

Be realistic about this: modern OCR and AI models can read image CAPTCHAs.
This stops cheap raid bots and scripted joins, which are most of the threat to
a friends' server, but not a determined human. That's why it's paired with the
account-age check and moderator review.
"""

from __future__ import annotations

import hmac
import io
import secrets

from PIL import Image, ImageDraw, ImageFilter, ImageFont

# Characters people confuse (0/O, 1/I/L, 5/S, 8/B) are left out so real users
# don't fail on ambiguity.
CAPTCHA_ALPHABET = "ACDEFGHJKMNPQRTUVWXYZ234679"
CAPTCHA_LENGTH = 6
IMAGE_WIDTH = 360
IMAGE_HEIGHT = 120

# Clipboard Cleaner theme colours. Glyphs and the thin crossing lines share
# the same two light colours on purpose: if the noise were darker than the
# text, a bot could delete it with a single brightness threshold.
BACKGROUND_COLOUR = (0x18, 0x18, 0x25)  # backgroundCLR
GLYPH_COLOURS = ((0xDD, 0xDD, 0xDD), (0xE9, 0x45, 0x60))  # tooltip-fg, OnBtnBackgroundCLR (accent)
SPECKLE_COLOURS = ((0x2A, 0x2A, 0x3E), (0x33, 0x33, 0x55), (0x44, 0x44, 0x5A))  # dividerCLR, spinbox-border, OffBtnForegroundCLR


def generateCode() -> str:
    # `secrets` rather than `random`: random's output is predictable once
    # enough of it has been observed, so it must never be used for challenges.
    return "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(CAPTCHA_LENGTH))


def codesMatch(expectedCode: str, submittedCode: str) -> bool:
    cleanedCode = "".join(submittedCode.split()).upper()
    return hmac.compare_digest(expectedCode.encode(), cleanedCode.encode())


def randomBetween(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def renderCaptcha(code: str) -> bytes:
    image = Image.new("RGB", (IMAGE_WIDTH, IMAGE_HEIGHT), BACKGROUND_COLOUR)
    draw = ImageDraw.Draw(image)

    for _ in range(600):
        draw.point(
            (randomBetween(0, IMAGE_WIDTH - 1), randomBetween(0, IMAGE_HEIGHT - 1)),
            fill=secrets.choice(SPECKLE_COLOURS),
        )

    font = ImageFont.load_default(size=64)
    slotWidth = IMAGE_WIDTH // (len(code) + 1)
    for index, character in enumerate(code):
        glyph = Image.new("RGBA", (90, 100), (0, 0, 0, 0))
        ImageDraw.Draw(glyph).text((15, 10), character, font=font, fill=(*secrets.choice(GLYPH_COLOURS), 255))
        glyph = glyph.rotate(randomBetween(-28, 28), resample=Image.Resampling.BICUBIC, expand=False)
        positionX = slotWidth // 2 + index * slotWidth + randomBetween(-6, 6)
        positionY = randomBetween(-4, 22)
        image.paste(glyph, (positionX, positionY), glyph)

    # Lines go on after the glyphs so they cross through them.
    for _ in range(6):
        startPoint = (randomBetween(0, IMAGE_WIDTH), randomBetween(0, IMAGE_HEIGHT))
        endPoint = (randomBetween(0, IMAGE_WIDTH), randomBetween(0, IMAGE_HEIGHT))
        draw.line([startPoint, endPoint], fill=secrets.choice(GLYPH_COLOURS), width=1)

    image = image.filter(ImageFilter.SMOOTH)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()
