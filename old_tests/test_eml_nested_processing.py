import os
import sys
import email
from email.policy import default

# Ensure backend modules are on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from lambda_function import extract_body_and_images_from_email


def test_eml_nested_processing():
    """Verify that an EML file can be parsed without errors."""

    eml_path = "test_eml_files/Demoss, D JCSD 8.07.25.eml"
    with open(eml_path, "rb") as f:
        eml_content = f.read()

    msg = email.message_from_bytes(eml_content, policy=default)
    body, images, attachments = extract_body_and_images_from_email(msg)

    # Basic sanity checks
    assert isinstance(body, str)
    assert isinstance(images, (list, dict))
    assert isinstance(attachments, list)

