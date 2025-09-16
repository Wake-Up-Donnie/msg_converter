#!/usr/bin/env python3
"""Regression test ensuring generated PDF layout matches the reference output."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from io import BytesIO
import base64

from pypdf import PdfReader

# Ensure backend modules are importable when running directly
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from lambda_function import (  # type: ignore  # pylint: disable=import-error
    convert_eml_to_pdf,
    convert_msg_bytes_to_eml_bytes_with_attachments,
)

REFERENCE_PDF_B64 = PROJECT_ROOT / "correct_pdf_output_format" / "correct-format.b64"
SAMPLE_MSG = PROJECT_ROOT / "test_msg_files" / "test-messege-How it looks as a message.msg"


def _collect_page_streams(pdf_bytes: bytes) -> tuple[list[bytes], PdfReader]:
    """Return the decompressed content stream for each page in ``pdf_bytes``."""
    reader = PdfReader(BytesIO(pdf_bytes))
    streams: list[bytes] = []
    for page in reader.pages:
        contents = page.get_contents()
        if contents is None:
            streams.append(b"")
            continue
        if hasattr(contents, "get_data"):
            data = contents.get_data()
        else:  # ``contents`` can be an iterable of separate stream objects
            data = b"".join(part.get_data() for part in contents if hasattr(part, "get_data"))
        streams.append(data)
    return streams, reader


def test_sample_msg_renders_like_reference() -> None:
    """Convert the sample .msg file and compare PDF layout with the reference output."""
    assert SAMPLE_MSG.exists(), f"Sample .msg file missing: {SAMPLE_MSG}"
    assert REFERENCE_PDF_B64.exists(), (
        "Reference PDF base64 missing. Run the conversion once to regenerate it."
    )

    with SAMPLE_MSG.open("rb") as handle:
        msg_bytes = handle.read()

    eml_bytes, attachments = convert_msg_bytes_to_eml_bytes_with_attachments(msg_bytes)

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
        output_pdf = Path(tmp_file.name)

    try:
        # Ensure the Playwright rendering path is used (not the FPDF fallback)
        os.environ.pop("TEST_MODE", None)
        success = convert_eml_to_pdf(eml_bytes, str(output_pdf), msg_attachments=attachments)
        assert success and output_pdf.exists(), "PDF conversion failed to produce output"

        with output_pdf.open("rb") as gen_handle:
            generated_bytes = gen_handle.read()

        reference_bytes = base64.b64decode(REFERENCE_PDF_B64.read_text())

        generated_streams, generated_reader = _collect_page_streams(generated_bytes)
        reference_streams, reference_reader = _collect_page_streams(reference_bytes)

        assert len(generated_reader.pages) == len(
            reference_reader.pages
        ), "Page count mismatch between generated and reference PDFs"

        diffs = [
            index + 1
            for index, (gen, ref) in enumerate(zip(generated_streams, reference_streams))
            if gen != ref
        ]
        assert not diffs, f"PDF content streams differ on page(s): {diffs}"

        for page_num, (gen_page, ref_page) in enumerate(
            zip(generated_reader.pages, reference_reader.pages), start=1
        ):
            assert (
                gen_page.mediabox == ref_page.mediabox
            ), f"Media box mismatch on page {page_num}"
    finally:
        try:
            output_pdf.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    test_sample_msg_renders_like_reference()
