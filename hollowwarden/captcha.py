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
    image = Image.new("RGB", (IMAGE_WIDTH, IMAGE_HEIGHT), (24, 26, 32))
    draw = ImageDraw.Draw(image)

    for _ in range(8):
        lineColour = (randomBetween(70, 140), randomBetween(70, 140), randomBetween(70, 140))
        startPoint = (randomBetween(0, IMAGE_WIDTH), randomBetween(0, IMAGE_HEIGHT))
        endPoint = (randomBetween(0, IMAGE_WIDTH), randomBetween(0, IMAGE_HEIGHT))
        draw.line([startPoint, endPoint], fill=lineColour, width=randomBetween(1, 3))

    font = ImageFont.load_default(size=64)
    slotWidth = IMAGE_WIDTH // (len(code) + 1)
    for index, character in enumerate(code):
        glyph = Image.new("RGBA", (90, 100), (0, 0, 0, 0))
        glyphColour = (randomBetween(170, 255), randomBetween(170, 255), randomBetween(170, 255), 255)
        ImageDraw.Draw(glyph).text((15, 10), character, font=font, fill=glyphColour)
        glyph = glyph.rotate(randomBetween(-28, 28), resample=Image.Resampling.BICUBIC, expand=False)
        positionX = slotWidth // 2 + index * slotWidth + randomBetween(-6, 6)
        positionY = randomBetween(-4, 22)
        image.paste(glyph, (positionX, positionY), glyph)

    for _ in range(600):
        dotColour = (randomBetween(60, 200), randomBetween(60, 200), randomBetween(60, 200))
        draw.point((randomBetween(0, IMAGE_WIDTH - 1), randomBetween(0, IMAGE_HEIGHT - 1)), fill=dotColour)

    image = image.filter(ImageFilter.SMOOTH)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()
