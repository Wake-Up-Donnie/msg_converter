import os
import html
import base64
import tempfile
import zipfile
import subprocess
import shutil


class DocumentConverter:
    """Handle document and email conversions used by the Lambda handlers."""

    def __init__(self, logger, html_to_pdf_fn=None, eml_to_pdf_fn=None):
        self.logger = logger
        self.html_to_pdf = html_to_pdf_fn
        self.eml_to_pdf = eml_to_pdf_fn

    def convert_doc_with_pypandoc_and_images(self, doc_data: bytes, ext: str) -> str:
        """Convert .doc/.docx to HTML using pypandoc with enhanced image handling."""
        try:
            import pypandoc

            extracted_images = []
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(doc_data)
                tmp.flush()
                tmp_path = tmp.name

            try:
                if ext.lower() == '.docx':
                    try:
                        with zipfile.ZipFile(tmp_path, 'r') as docx_zip:
                            media_files = [f for f in docx_zip.namelist() if f.startswith('word/media/')]
                            for media_file in media_files:
                                try:
                                    img_data = docx_zip.read(media_file)
                                    if img_data:
                                        filename = os.path.basename(media_file)
                                        if filename.lower().endswith('.png'):
                                            content_type = 'image/png'
                                        elif filename.lower().endswith(('.jpg', '.jpeg')):
                                            content_type = 'image/jpeg'
                                        elif filename.lower().endswith('.gif'):
                                            content_type = 'image/gif'
                                        elif filename.lower().endswith('.bmp'):
                                            content_type = 'image/bmp'
                                        else:
                                            content_type = 'image/png'

                                        b64_data = base64.b64encode(img_data).decode('utf-8')
                                        data_url = f"data:{content_type};base64,{b64_data}"
                                        extracted_images.append({
                                            'filename': filename,
                                            'data_url': data_url,
                                            'size': len(img_data),
                                            'type': content_type
                                        })
                                except Exception as e:
                                    self.logger.warning(f"Failed to extract image {media_file}: {e}")
                                    continue
                    except Exception as ze:
                        self.logger.info(f"Could not extract images from .docx ZIP: {ze}")

                try:
                    html_content = pypandoc.convert_file(tmp_path, 'html')
                except OSError:
                    pypandoc.download_pandoc()
                    html_content = pypandoc.convert_file(tmp_path, 'html')

                if extracted_images and html_content:
                    import re

                    image_map = {}
                    for img in extracted_images:
                        filename = img['filename']
                        base_name = os.path.splitext(filename)[0]
                        possible_refs = [
                            filename,
                            f"word/media/{filename}",
                            f"media/{filename}",
                            base_name,
                            f"image{len(image_map) + 1}",
                        ]
                        for ref in possible_refs:
                            image_map[ref] = img['data_url']

                    def replace_img_src(match):
                        full_tag = match.group(0)
                        src_match = re.search(r'src=["\']([^"\']+)["\']', full_tag)
                        if src_match:
                            original_src = src_match.group(1)
                            for ref, data_url in image_map.items():
                                if ref.lower() in original_src.lower() or original_src.lower() in ref.lower():
                                    return full_tag.replace(original_src, data_url)
                        return full_tag

                    html_content = re.sub(r'<img[^>]*>', replace_img_src, html_content, flags=re.IGNORECASE)

                    if not re.search(r'<img[^>]*>', html_content, re.IGNORECASE) and extracted_images:
                        images_html = '<div style="margin-top:20px;"><h4>Document Images:</h4>'
                        for img in extracted_images:
                            images_html += f'<img src="{img["data_url"]}" alt="{img["filename"]}" style="max-width:100%;margin:10px 0;" />'
                        images_html += '</div>'
                        html_content += images_html

                if html_content:
                    styled_html = f"""
                    <style>
                        img {{
                            max-width: 100%;
                            height: auto;
                            display: block;
                            margin: 8px 0;
                        }}
                        .doc-image {{
                            max-width: 100%;
                            height: auto;
                        }}
                    </style>
                    {html_content}
                    """

                    if extracted_images:
                        total_size = sum(img['size'] for img in extracted_images)
                        image_types = list(set(img['type'] for img in extracted_images))
                        self.logger.info(
                            f"pypandoc extracted {len(extracted_images)} images (total size: {total_size} bytes, types: {image_types})"
                        )
                    else:
                        self.logger.info("No images found in document")

                    return styled_html

                return html_content or ""
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"Error in convert_doc_with_pypandoc_and_images: {e}")
            raise

    def convert_docx_to_html_with_images(self, docx_data: bytes) -> str:
        """Convert .docx to HTML with embedded images as data URLs."""
        try:
            import mammoth
            import base64
            import io

            extracted_images = []

            def convert_image(image):
                try:
                    image_bytes = image.open().read()
                    content_type = getattr(image, 'content_type', None)
                    if not content_type:
                        if image_bytes.startswith(b'\x89PNG'):
                            content_type = 'image/png'
                        elif image_bytes.startswith(b'\xff\xd8\xff'):
                            content_type = 'image/jpeg'
                        elif image_bytes.startswith(b'GIF'):
                            content_type = 'image/gif'
                        elif image_bytes.startswith(b'RIFF') and b'WEBP' in image_bytes[:20]:
                            content_type = 'image/webp'
                        elif image_bytes.startswith(b'BM'):
                            content_type = 'image/bmp'
                        else:
                            content_type = 'image/png'

                    b64_data = base64.b64encode(image_bytes).decode('utf-8')
                    data_url = f"data:{content_type};base64,{b64_data}"

                    extracted_images.append({
                        'size': len(image_bytes),
                        'type': content_type,
                        'alt_text': getattr(image, 'alt_text', '') or 'Image from Word document'
                    })

                    return {
                        "src": data_url,
                        "alt": getattr(image, 'alt_text', '') or 'Image from Word document'
                    }
                except Exception as e:
                    self.logger.warning(f"Failed to convert image: {e}")
                    return {}

            convert_options = {
                'convert_image': mammoth.images.img_element(convert_image),
                'ignore_empty_paragraphs': False,
                'preserve_empty_paragraphs': True
            }

            with io.BytesIO(docx_data) as docx_stream:
                result = mammoth.convert_to_html(docx_stream, **convert_options)
                html_content = result.value
                if result.messages:
                    for msg in result.messages:
                        if msg.type == 'warning':
                            self.logger.warning(f"Mammoth warning: {msg.message}")
                        elif msg.type == 'error':
                            self.logger.error(f"Mammoth error: {msg.message}")

            styled_html = f"""
            <style>
                img {{
                    max-width: 100%;
                    height: auto;
                    display: block;
                    margin: 8px 0;
                }}
                .word-image {{
                    max-width: 100%;
                    height: auto;
                }}
            </style>
            {html_content}
            """

            if extracted_images:
                total_size = sum(img['size'] for img in extracted_images)
                image_types = list(set(img['type'] for img in extracted_images))
                self.logger.info(
                    f"Mammoth extracted {len(extracted_images)} images (total size: {total_size} bytes, types: {image_types})"
                )
            else:
                self.logger.info("No images found in .docx document")

            return styled_html

        except Exception as e:
            self.logger.error(f"Error in convert_docx_to_html_with_images: {e}")
            raise

    def convert_office_to_pdf(self, data: bytes, ext: str) -> bytes | None:
        """Convert .doc/.docx bytes to PDF bytes."""
        src_path = None
        out_dir = None
        pdf_path = None
        try:
            try:
                if shutil.which('libreoffice'):
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as src:
                        src.write(data)
                        src.flush()
                        src_path = src.name
                    out_dir = tempfile.mkdtemp()
                    cmd = [
                        'libreoffice',
                        '--headless',
                        '--convert-to',
                        'pdf',
                        src_path,
                        '--outdir',
                        out_dir,
                    ]
                    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    pdf_path = os.path.join(out_dir, os.path.splitext(os.path.basename(src_path))[0] + '.pdf')
                    with open(pdf_path, 'rb') as f:
                        return f.read()
                else:
                    self.logger.info("libreoffice not found - using pypandoc fallback")
            except Exception as e:
                self.logger.warning(f"DOC/DOCX conversion failed: {e}")

            try:
                html_content = None
                lower_ext = ext.lower()

                try:
                    html_content = self.convert_doc_with_pypandoc_and_images(data, ext)
                    if html_content:
                        self.logger.info("pypandoc conversion successful with potential image extraction")
                except Exception as pe:
                    self.logger.warning(f"pypandoc conversion failed: {pe}")

                if not html_content and lower_ext == '.docx':
                    try:
                        import mammoth  # type: ignore
                        html_content = self.convert_docx_to_html_with_images(data)
                        self.logger.info("mammoth conversion successful with image extraction")
                    except Exception as me:
                        self.logger.warning(f"mammoth conversion failed: {me}")

                if not html_content and lower_ext == '.doc':
                    try:
                        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                            tmp.write(data)
                            tmp.flush()
                            tmp_path = tmp.name
                        try:
                            result = subprocess.run(
                                ['antiword', tmp_path],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            text = result.stdout.decode('utf-8', 'replace')
                            html_content = f"<pre>{html.escape(text)}</pre>"
                        finally:
                            try:
                                os.remove(tmp_path)
                            except Exception:
                                pass
                    except Exception as te:
                        self.logger.warning(f"antiword conversion failed: {te}")

                if html_content and self.html_to_pdf:
                    tmp_pdf_fd, tmp_pdf_path = tempfile.mkstemp(suffix='.pdf')
                    os.close(tmp_pdf_fd)
                    try:
                        self.html_to_pdf(html_content, tmp_pdf_path)
                        with open(tmp_pdf_path, 'rb') as f:
                            return f.read()
                    finally:
                        try:
                            os.remove(tmp_pdf_path)
                        except Exception:
                            pass
            except Exception as fe:
                self.logger.warning(f"Fallback DOC/DOCX conversion failed: {fe}")
            return None
        finally:
            for p in (src_path, pdf_path):
                if p and os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            if out_dir:
                try:
                    shutil.rmtree(out_dir)
                except Exception:
                    pass

    def eml_bytes_to_pdf_bytes(self, eml_bytes: bytes) -> bytes | None:
        """Convert EML bytes to PDF bytes using convert_eml_to_pdf helper."""
        try:
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
                pdf_path = tmp_pdf.name
            ok = False
            if self.eml_to_pdf:
                ok = self.eml_to_pdf(eml_bytes, pdf_path)
            if ok and os.path.exists(pdf_path):
                with open(pdf_path, 'rb') as f:
                    return f.read()
            return None
        except Exception as e:
            self.logger.warning(f"EML to PDF conversion failed: {e}")
            return None
        finally:
            try:
                if 'pdf_path' in locals() and os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass

