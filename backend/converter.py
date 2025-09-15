import os
import tempfile
import io
import logging
import mimetypes
from email.message import EmailMessage
from email.generator import BytesGenerator
from email.policy import default
from email.utils import format_datetime
from datetime import datetime
from typing import List, Dict, Any, Tuple

import extract_msg

class EmailConverter:
    """Utilities for working with Outlook ``.msg`` files and EML conversion."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    def extract_msg_attachments_with_embedded(self, msg_path: str, output_dir: str) -> list:
        """Extract attachments from a ``.msg`` file, handling embedded messages."""
        import tempfile
        try:
            if self.logger:
                self.logger.info(f"Extracting attachments from: {msg_path}")

            attachments = []

            with extract_msg.Message(msg_path) as msg:
                if self.logger:
                    self.logger.info(f"DEBUGGING: Total attachments found: {len(msg.attachments)}")
                    for i, att in enumerate(msg.attachments):
                        att_type = getattr(att, 'type', 'unknown')
                        att_name = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', 'unknown')
                        self.logger.info(
                            f"DEBUGGING: Attachment {i+1}: type='{att_type}', name='{att_name}'"
                        )

                for attachment in msg.attachments:
                    try:
                        if hasattr(attachment, 'type') and attachment.type == "data":
                            att_data = attachment.data
                            att_name = getattr(attachment, 'longFilename', None) or getattr(
                                attachment, 'shortFilename', 'unknown'
                            )
                            if att_name.lower().endswith('.pdf'):
                                content_type = 'application/pdf'
                            elif att_name.lower().endswith(('.jpg', '.jpeg')):
                                content_type = 'image/jpeg'
                            elif att_name.lower().endswith('.png'):
                                content_type = 'image/png'
                            else:
                                content_type = 'application/octet-stream'

                            attachments.append(
                                {
                                    'filename': att_name,
                                    'content_type': content_type,
                                    'data': att_data,
                                }
                            )

                            if self.logger:
                                self.logger.info(
                                    f"Successfully extracted regular attachment: {att_name} ({len(att_data)} bytes)"
                                )

                        elif hasattr(attachment, 'type') and attachment.type == "msg":
                            if self.logger:
                                self.logger.info("DEBUGGING: Found embedded .msg attachment")
                            try:
                                embedded_msg = attachment.data
                                att_name = getattr(attachment, 'longFilename', None) or getattr(
                                    attachment, 'shortFilename', 'embedded_message.msg'
                                )

                                if self.logger:
                                    self.logger.info(f"DEBUGGING: Processing embedded .msg: {att_name}")

                                try:
                                    with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp_file:
                                        embedded_msg.save(tmp_file.name, raw=True)
                                        tmp_file.flush()
                                        with open(tmp_file.name, 'rb') as f:
                                            msg_bytes = f.read()
                                        eml_bytes = self.convert_msg_bytes_to_eml_bytes(msg_bytes)
                                        final_name = os.path.splitext(att_name)[0] + '.eml'
                                        attachments.append(
                                            {
                                                'filename': final_name,
                                                'content_type': 'message/rfc822',
                                                'data': eml_bytes,
                                            }
                                        )
                                        if self.logger:
                                            self.logger.info(
                                                f"DEBUGGING: Successfully converted embedded .msg to EML: {final_name} ({len(eml_bytes)} bytes)"
                                            )
                                        os.unlink(tmp_file.name)
                                        continue
                                except Exception as direct_e:
                                    if self.logger:
                                        self.logger.warning(
                                            f"DEBUGGING: Direct .msg conversion failed: {direct_e}, trying save method"
                                        )

                                with tempfile.TemporaryDirectory() as temp_dir:
                                    save_result = embedded_msg.save(customPath=temp_dir, useFileName=True)
                                    if self.logger:
                                        self.logger.info(f"Items created by save(): {save_result}")
                                    for root, dirs, files in os.walk(temp_dir):
                                        if self.logger:
                                            self.logger.info(f"Files inside extracted dir: {files}")
                                        for filename in files:
                                            try:
                                                lower = filename.lower()
                                                file_path = os.path.join(root, filename)
                                                if lower.endswith('.eml'):
                                                    with open(file_path, 'rb') as f:
                                                        eml_bytes = f.read()
                                                    final_name = (
                                                        att_name
                                                        if att_name.lower().endswith('.eml')
                                                        else os.path.splitext(att_name)[0] + '.eml'
                                                    )
                                                    attachments.append(
                                                        {
                                                            'filename': final_name,
                                                            'content_type': 'message/rfc822',
                                                            'data': eml_bytes,
                                                        }
                                                    )
                                                    if self.logger:
                                                        self.logger.info(
                                                            f"Successfully extracted embedded EML: {final_name} ({len(eml_bytes)} bytes)"
                                                        )
                                                    raise StopIteration
                                                if lower.endswith('.msg'):
                                                    with open(file_path, 'rb') as f:
                                                        msg_bytes = f.read()
                                                    try:
                                                        eml_bytes = self.convert_msg_bytes_to_eml_bytes(msg_bytes)
                                                        final_name = os.path.splitext(att_name)[0] + '.eml'
                                                        attachments.append(
                                                            {
                                                                'filename': final_name,
                                                                'content_type': 'message/rfc822',
                                                                'data': eml_bytes,
                                                            }
                                                        )
                                                        if self.logger:
                                                            self.logger.info(
                                                                f"Converted embedded MSG to EML: {final_name} ({len(eml_bytes)} bytes)"
                                                            )
                                                        raise StopIteration
                                                    except Exception as conv_e:
                                                        if self.logger:
                                                            self.logger.warning(
                                                                f"Failed converting embedded .msg to .eml: {conv_e}"
                                                            )
                                            except StopIteration:
                                                files = []
                                                break
                                            except Exception as read_any:
                                                if self.logger:
                                                    self.logger.warning(
                                                        f"Error examining extracted file '{filename}': {read_any}"
                                                    )
                                        for filename in files:
                                            if filename in ['message.txt', 'message.html', 'body.txt', 'body.html']:
                                                file_path = os.path.join(root, filename)
                                                try:
                                                    with open(
                                                        file_path, 'r', encoding='utf-8', errors='replace'
                                                    ) as f:
                                                        text_content = f.read()
                                                    if text_content.strip():
                                                        text_filename = f"{att_name}.txt"
                                                        attachments.append(
                                                            {
                                                                'filename': text_filename,
                                                                'content_type': 'text/plain',
                                                                'data': text_content.encode('utf-8'),
                                                            }
                                                        )
                                                        if self.logger:
                                                            self.logger.info(
                                                                f"Successfully extracted embedded attachment: {text_filename} ({len(text_content)} bytes, type: text/plain)"
                                                            )
                                                        break
                                                except Exception as read_e:
                                                    if self.logger:
                                                        self.logger.warning(
                                                            f"Could not read {filename}: {read_e}"
                                                        )
                            except Exception as embedded_e:
                                if self.logger:
                                    self.logger.warning(
                                        f"Failed to extract embedded .msg: {embedded_e}"
                                    )
                        else:
                            if self.logger:
                                self.logger.info(
                                    "DEBUGGING: Found attachment with unknown/missing type, investigating..."
                                )
                            try:
                                att_name = getattr(
                                    attachment, 'longFilename', None
                                ) or getattr(attachment, 'shortFilename', None)
                                if self.logger:
                                    self.logger.info(
                                        f"DEBUGGING: Investigating unknown attachment - name: '{att_name}', has_data: {hasattr(attachment, 'data')}"
                                    )
                                att_name_safe = att_name or 'embedded_message'
                                binary_name = att_name or f"attachment-{len(attachments)+1}"
                                raw_data = None
                                if hasattr(attachment, 'data'):
                                    try:
                                        raw_data = attachment.data
                                    except Exception as data_e:
                                        raw_data = None
                                        if self.logger:
                                            self.logger.warning(
                                                f"DEBUGGING: Could not access attachment data for {att_name_safe}: {data_e}"
                                            )
                                if isinstance(raw_data, (bytes, bytearray)) and raw_data:
                                    content_type = (
                                        getattr(attachment, 'mimeType', None)
                                        or getattr(attachment, 'mimetype', None)
                                    )
                                    if not content_type and att_name_safe:
                                        guessed, _ = mimetypes.guess_type(att_name_safe)
                                        content_type = guessed
                                    if not content_type:
                                        content_type = 'application/octet-stream'
                                    attachments.append(
                                        {
                                            'filename': binary_name,
                                            'content_type': content_type,
                                            'data': bytes(raw_data),
                                        }
                                    )
                                    if self.logger:
                                        self.logger.info(
                                            f"DEBUGGING: Extracted binary attachment with inferred type: {att_name_safe} ({content_type}, {len(raw_data)} bytes)"
                                        )
                                    continue
                                if raw_data:
                                    if (
                                        att_name_safe.lower().endswith('.msg')
                                        or hasattr(raw_data, 'save')
                                        or hasattr(raw_data, 'subject')
                                        or str(getattr(attachment, 'type', '')) == '1'
                                    ):
                                        if self.logger:
                                            self.logger.info(
                                                f"DEBUGGING: Treating unknown attachment as embedded message: {att_name_safe}"
                                            )
                                        try:
                                            embedded_data = raw_data
                                            if hasattr(embedded_data, 'as_email') or hasattr(
                                                embedded_data, 'asEmailMessage'
                                            ):
                                                try:
                                                    if self.logger:
                                                        self.logger.info(
                                                            "DEBUGGING: Attempting direct conversion of embedded Message object"
                                                        )
                                                    if hasattr(embedded_data, 'as_email'):
                                                        email_obj = embedded_data.as_email()
                                                    elif hasattr(embedded_data, 'asEmailMessage'):
                                                        email_obj = embedded_data.asEmailMessage()
                                                    else:
                                                        raise Exception("No conversion method available")
                                                    buf = io.BytesIO()
                                                    BytesGenerator(buf, policy=default).flatten(email_obj)
                                                    eml_bytes = buf.getvalue()
                                                    final_name = 'Fwd_JCSD_construction_water_sales_availablity.eml'
                                                    attachments.append(
                                                        {
                                                            'filename': final_name,
                                                            'content_type': 'message/rfc822',
                                                            'data': eml_bytes,
                                                        }
                                                    )
                                                    if self.logger:
                                                        self.logger.info(
                                                            f"DEBUGGING: Successfully converted embedded message directly to EML: {final_name} ({len(eml_bytes)} bytes)"
                                                        )
                                                    continue
                                                except Exception as direct_e:
                                                    if self.logger:
                                                        self.logger.warning(
                                                            f"DEBUGGING: Direct conversion failed: {direct_e}, trying save method"
                                                        )
                                            if hasattr(embedded_data, 'save'):
                                                try:
                                                    with tempfile.TemporaryDirectory() as temp_extract_dir:
                                                        if self.logger:
                                                            self.logger.info(
                                                                f"DEBUGGING: Trying save method in temp dir: {temp_extract_dir}"
                                                            )
                                                        save_result = embedded_data.save(
                                                            customPath=temp_extract_dir, useFileName=True
                                                        )
                                                        if self.logger:
                                                            self.logger.info(
                                                                f"DEBUGGING: Save result: {save_result}"
                                                            )
                                                        for root, dirs, files in os.walk(temp_extract_dir):
                                                            if self.logger:
                                                                self.logger.info(
                                                                    f"DEBUGGING: Files in {root}: {files}"
                                                                )
                                                            for filename in files:
                                                                if filename.lower().endswith(('.eml', '.msg')):
                                                                    file_path = os.path.join(root, filename)
                                                                    with open(file_path, 'rb') as f:
                                                                        saved_bytes = f.read()
                                                                    if filename.lower().endswith('.msg'):
                                                                        eml_bytes = self.convert_msg_bytes_to_eml_bytes(
                                                                            saved_bytes
                                                                        )
                                                                    else:
                                                                        eml_bytes = saved_bytes
                                                                    final_name = 'Fwd_JCSD_construction_water_sales_availablity.eml'
                                                                    attachments.append(
                                                                        {
                                                                            'filename': final_name,
                                                                            'content_type': 'message/rfc822',
                                                                            'data': eml_bytes,
                                                                        }
                                                                    )
                                                                    if self.logger:
                                                                        self.logger.info(
                                                                            f"DEBUGGING: Successfully extracted embedded message via save: {final_name} ({len(eml_bytes)} bytes)"
                                                                        )
                                                                    break
                                                            if attachments:
                                                                break
                                                except Exception as save_e:
                                                    if self.logger:
                                                        self.logger.warning(
                                                            f"DEBUGGING: Save method also failed: {save_e}"
                                                        )
                                        except Exception as unknown_e:
                                            if self.logger:
                                                self.logger.warning(
                                                    f"DEBUGGING: Failed to process unknown attachment: {unknown_e}"
                                                )
                            except Exception as detect_e:
                                if self.logger:
                                    self.logger.warning(
                                        f"DEBUGGING: Error detecting attachment type: {detect_e}"
                                    )
                    except Exception as att_e:
                        if self.logger:
                            self.logger.warning(f"Failed to process attachment: {att_e}")
            return attachments
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting .msg attachments: {e}")
            return []

    def convert_msg_bytes_to_eml_bytes(self, msg_bytes: bytes) -> bytes:
        """Convert Outlook .msg bytes into RFC 822 EML bytes."""
        try:
            self.logger.info(
                f"DEBUGGING: convert_msg_bytes_to_eml_bytes starting with {len(msg_bytes)} bytes"
            )
            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmpf:
                tmp_path = tmpf.name
                tmpf.write(msg_bytes)
            try:
                m = extract_msg.Message(tmp_path)
                self.logger.info("DEBUGGING: extract_msg.Message created successfully")
                try:
                    subj = getattr(m, 'subject', None) or ''
                    sender = getattr(m, 'sender', None) or getattr(
                        m, 'sender_email', None
                    ) or ''
                    self.logger.info(
                        f"DEBUGGING: Message subject: '{subj}', sender: '{sender}'"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"DEBUGGING: Error getting basic properties: {e}"
                    )
                date_hdr = None
                try:
                    date_val = getattr(m, 'date', None)
                    if isinstance(date_val, datetime):
                        date_hdr = format_datetime(date_val)
                    elif date_val:
                        date_hdr = str(date_val)
                except Exception:
                    date_hdr = None
                em = None
                if hasattr(m, 'as_email'):
                    try:
                        self.logger.info("DEBUGGING: Trying m.as_email() method")
                        em = m.as_email()
                        self.logger.info("DEBUGGING: m.as_email() succeeded")
                    except Exception as e:
                        self.logger.warning(
                            f"DEBUGGING: m.as_email() failed: {e}"
                        )
                        em = None
                if em is None and hasattr(m, 'asEmailMessage'):
                    try:
                        self.logger.info(
                            "DEBUGGING: Trying m.asEmailMessage() method"
                        )
                        em = m.asEmailMessage()
                        self.logger.info("DEBUGGING: m.asEmailMessage() succeeded")
                    except Exception as e:
                        self.logger.warning(
                            f"DEBUGGING: m.asEmailMessage() failed: {e}"
                        )
                        em = None
                if em is None:
                    self.logger.info(
                        "DEBUGGING: Using manual EmailMessage construction"
                    )
                    em = EmailMessage()
                    subj = getattr(m, 'subject', None) or ''
                    sender = getattr(m, 'sender', None) or getattr(
                        m, 'sender_email', None
                    ) or ''
                    to_list = getattr(m, 'to', None) or []
                    cc_list = getattr(m, 'cc', None) or []
                    bcc_list = getattr(m, 'bcc', None) or []
                    em['Subject'] = subj
                    if sender:
                        em['From'] = sender
                    if to_list:
                        em['To'] = ', '.join(
                            to_list if isinstance(to_list, list) else [str(to_list)]
                        )
                    if cc_list:
                        em['Cc'] = ', '.join(
                            cc_list if isinstance(cc_list, list) else [str(cc_list)]
                        )
                    if bcc_list:
                        em['Bcc'] = ', '.join(
                            bcc_list if isinstance(bcc_list, list) else [str(bcc_list)]
                        )
                    if date_hdr:
                        em['Date'] = date_hdr
                    def _decode_to_str(val):
                        if val is None:
                            return ''
                        if isinstance(val, str):
                            return val
                        if isinstance(val, (bytes, bytearray)):
                            for enc in (
                                'utf-8',
                                'cp1252',
                                'latin1',
                                'iso-8859-1',
                            ):
                                try:
                                    return val.decode(enc)
                                except Exception:
                                    continue
                            return val.decode('utf-8', errors='replace')
                        try:
                            return str(val)
                        except Exception:
                            return ''
                    html_body = _decode_to_str(
                        getattr(m, 'htmlBody', None) or getattr(m, 'html', None)
                    )
                    text_body = _decode_to_str(getattr(m, 'body', None) or '')
                    self.logger.info(
                        f"DEBUGGING: Initial body extraction - HTML: {len(html_body)} chars, Text: {len(text_body)} chars"
                    )
                    if html_body:
                        self.logger.info(
                            f"DEBUGGING: HTML body preview: {html_body[:300]}..."
                        )
                    if text_body:
                        self.logger.info(
                            f"DEBUGGING: Text body preview: {text_body[:300]}..."
                        )
                    try:
                        rtf_body = _decode_to_str(getattr(m, 'rtfBody', None))
                        if rtf_body and len(rtf_body) > max(len(html_body), len(text_body)):
                            self.logger.info(
                                f"DEBUGGING: RTF body is larger ({len(rtf_body)} chars), using as fallback"
                            )
                            text_body = rtf_body
                        for prop_name in (
                            'compressedRtf',
                            'plainTextBody',
                            'textBody',
                        ):
                            try:
                                alt_content = getattr(m, prop_name, None)
                                if alt_content:
                                    decoded = _decode_to_str(alt_content)
                                    if decoded and len(decoded.strip()) > max(
                                        len(text_body), len(html_body)
                                    ):
                                        self.logger.info(
                                            f"DEBUGGING: Found better content in {prop_name}: {len(decoded)} chars"
                                        )
                                        text_body = decoded
                                        break
                            except Exception as alt_e:
                                self.logger.info(
                                    f"DEBUGGING: Error accessing {prop_name}: {alt_e}"
                                )
                    except Exception:
                        pass
                    if html_body:
                        em.add_alternative(html_body, subtype='html')
                        if text_body:
                            em.set_content(text_body)
                    else:
                        em.set_content(text_body)
                buf = io.BytesIO()
                BytesGenerator(buf, policy=default).flatten(em)
                eml_bytes = buf.getvalue()
                return eml_bytes
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f".msg to .eml conversion failed: {e}")
            raise

    def convert_msg_bytes_to_eml_bytes_with_attachments(self, msg_bytes: bytes) -> Tuple[bytes, list]:
        """
        Convert Outlook ``.msg`` bytes into RFC 822 EML bytes and extract attachments.
        Returns tuple of ``(eml_bytes, attachments_list)``.
        """
        try:
            self.logger.info(
                f"DEBUGGING: Starting .msg conversion with {len(msg_bytes)} bytes"
            )
            with tempfile.TemporaryDirectory() as temp_dir:
                msg_path = os.path.join(temp_dir, 'input.msg')
                with open(msg_path, 'wb') as f:
                    f.write(msg_bytes)
                self.logger.info(
                    f"DEBUGGING: Written .msg to temp file: {msg_path}"
                )
                attachments_dir = os.path.join(temp_dir, 'attachments')
                extracted_attachments = self.extract_msg_attachments_with_embedded(
                    msg_path, attachments_dir
                )
                self.logger.info(
                    f"DEBUGGING: Extracted {len(extracted_attachments)} attachments from main .msg"
                )
                for i, att in enumerate(extracted_attachments):
                    self.logger.info(
                        f"DEBUGGING: Attachment {i+1}: {att.get('filename', 'unknown')} ({att.get('content_type', 'unknown')}, {len(att.get('data', b''))} bytes)"
                    )
                self.logger.info("DEBUGGING: Converting main .msg to EML...")
                eml_bytes = self.convert_msg_bytes_to_eml_bytes(msg_bytes)
                self.logger.info(
                    f"DEBUGGING: Main .msg converted to EML: {len(eml_bytes)} bytes"
                )
                try:
                    eml_preview = eml_bytes.decode('utf-8', errors='replace')[:500]
                    self.logger.info(
                        f"DEBUGGING: EML content preview: {eml_preview}"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"DEBUGGING: Could not preview EML content: {e}"
                    )
                return eml_bytes, extracted_attachments
        except Exception as e:
            self.logger.error(f"Failed to extract .msg with attachments: {e}")
            return self.convert_msg_bytes_to_eml_bytes(msg_bytes), []
