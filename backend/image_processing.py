import base64
import html
import io
import logging
import os
import re
from typing import Dict, List, Tuple

from bs4 import BeautifulSoup

from html_processing import append_html_after_body_content


logger = logging.getLogger(__name__)

IMAGE_ATTACHMENT_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tif', '.tiff', '.webp', '.heic', '.heif'
)

SUPPORTED_INLINE_IMAGE_TYPES = {
    'image/png',
    'image/jpeg',
    'image/jpg',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/svg+xml',
}


def convert_tiff_to_png_bytes(image_bytes: bytes) -> tuple[bytes, str]:
    from PIL import Image

    with Image.open(io.BytesIO(image_bytes)) as im:
        frames = getattr(im, "n_frames", 1)
        if frames and frames > 1:
            logger.info("[PDF][TIFF] multi-frame TIFF detected; using first frame")
            im.seek(0)
        if im.mode not in ("RGB", "RGBA"):
            logger.info("[PDF][TIFF] converting mode %s -> RGBA", im.mode)
            im = im.convert("RGBA")
        out = io.BytesIO()
        im.save(out, format="PNG", optimize=True)
        return out.getvalue(), "image/png"


def looks_like_image(content_type: str | None, filename: str | None) -> bool:
    ctype = (content_type or '').lower()
    if ctype.startswith('image/'):
        return True
    if filename and filename.lower().endswith(IMAGE_ATTACHMENT_EXTENSIONS):
        return True
    return False


def ensure_displayable_image_bytes(
    img_bytes,
    content_type,
    source_name: str | None = None,
) -> Tuple[bytes | None, str | None]:
    if not isinstance(img_bytes, (bytes, bytearray)) or not img_bytes:
        return None, content_type

    payload_bytes = bytes(img_bytes)
    normalized_ct = (content_type or '').lower()
    name_lower = (source_name or '').lower()
    if normalized_ct in (
        'image/tiff',
        'image/tif',
        'image/x-tiff',
    ) or name_lower.endswith(('.tif', '.tiff')):
        logger.warning(
            "[PDF][TIFF] converting TIFF attachment to PNG for inline rendering"
        )
        try:
            converted_bytes, converted_type = convert_tiff_to_png_bytes(payload_bytes)
            return converted_bytes, converted_type
        except Exception as tiff_err:
            logger.exception(
                "[PDF][TIFF] conversion failed; leaving as-is: %s", tiff_err
            )

    if normalized_ct in SUPPORTED_INLINE_IMAGE_TYPES:
        return payload_bytes, normalized_ct or 'image/png'

    label = source_name or 'inline image'
    try:
        from PIL import Image
    except Exception as import_err:
        logger.warning(
            "Unable to import Pillow for converting %s (%s); rendering may fail: %s",
            label,
            normalized_ct or 'unknown',
            import_err,
        )
        return payload_bytes, content_type or 'application/octet-stream'

    try:
        with Image.open(io.BytesIO(payload_bytes)) as pil_img:
            try:
                if getattr(pil_img, 'n_frames', 1) > 1:
                    pil_img.seek(0)
            except Exception:
                pass

            if pil_img.mode in ('P', 'PA', 'LA', 'RGBA'):
                pil_img = pil_img.convert('RGBA')
            elif pil_img.mode not in ('RGB', 'L'):
                pil_img = pil_img.convert('RGB')

            buffer = io.BytesIO()
            save_mode = 'PNG'
            pil_img.save(buffer, format=save_mode)
            converted = buffer.getvalue()
            logger.info(
                "Converted inline image %s from %s to image/png for browser rendering",
                label,
                normalized_ct or 'unknown',
            )
            return converted, 'image/png'
    except Exception as convert_err:
        logger.warning(
            "Failed to convert inline image %s (%s) to PNG: %s",
            label,
            normalized_ct or 'unknown',
            convert_err,
        )
    return payload_bytes, content_type or 'application/octet-stream'


def convert_image_bytes_to_pdf(image_bytes: bytes, source_name: str | None = None) -> Tuple[bytes | None, int]:
    if not isinstance(image_bytes, (bytes, bytearray)) or not image_bytes:
        return None, 0

    try:
        from PIL import Image, ImageSequence
    except Exception as import_err:
        logger.warning(
            "Image->PDF conversion requires Pillow; skipping %s: %s",
            source_name or 'image attachment',
            import_err,
        )
        return None, 0

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            frames = []
            try:
                iterator = ImageSequence.Iterator(img)
            except Exception:
                iterator = [img]

            for frame in iterator:
                converted = frame.convert('RGB') if frame.mode != 'RGB' else frame.copy()
                frames.append(converted.copy())

            if not frames:
                frames.append(img.convert('RGB'))

            buffer = io.BytesIO()
            first = frames[0]
            rest = frames[1:]
            if rest:
                first.save(buffer, format='PDF', save_all=True, append_images=rest)
            else:
                first.save(buffer, format='PDF')

            for f in frames:
                try:
                    f.close()
                except Exception:
                    pass

            pdf_data = buffer.getvalue()
            page_count = 1 + len(rest)
            return pdf_data, page_count
    except Exception as convert_err:
        logger.warning(
            "Failed to convert image attachment %s to PDF: %s",
            source_name or 'image attachment',
            convert_err,
        )
        return None, 0


def normalize_lookup_key(s: str) -> str:
    try:
        import unicodedata

        x = unicodedata.normalize('NFKC', s or "")
        x = x.replace("\u200B", "").replace("\uFEFF", "").replace("\u2060", "").replace("\u00AD", "")
        x = re.sub(r"\s+", "", x)
        return x
    except Exception:
        return s or ""


def normalize_url(u: str) -> str:
    try:
        import unicodedata
        import urllib.parse

        s = u or ""
        parsed = urllib.parse.urlsplit(s)
        path = urllib.parse.unquote(parsed.path or "")
        query = urllib.parse.unquote(parsed.query or "")
        path = unicodedata.normalize('NFKC', path)
        query = unicodedata.normalize('NFKC', query)
        zap = dict.fromkeys(map(ord, "\u200B\uFEFF\u2060\u00AD"), None)
        path = path.translate(zap)
        query = query.translate(zap)
        path = re.sub(r"\s+", "", path)
        query = re.sub(r"\s+", "", query)
        new = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            urllib.parse.quote(path, safe="/:@-._~!$&'()*+,;="),
            urllib.parse.quote(query, safe="=&:@-._~!$'()*+,;"),
            parsed.fragment
        ))
        return new
    except Exception:
        return (u or "").replace("\u200B", "").replace("\uFEFF", "").replace("\u2060", "").replace("\u00AD", "")


def inline_image_attachments_into_body(
    body_html: str,
    attachment_list: List[Dict],
    source_label: str,
) -> Tuple[str, List[Dict], List[str]]:
    if not attachment_list:
        return body_html, attachment_list, []

    remaining: List[Dict] = []
    inline_figures: List[str] = []
    inlined_names: List[str] = []

    for att in attachment_list:
        fname = att.get('filename') or ''
        ctype = att.get('content_type') or ''
        data = att.get('data')
        if not looks_like_image(ctype, fname) or not isinstance(data, (bytes, bytearray)):
            remaining.append(att)
            continue

        display_bytes, usable_type = ensure_displayable_image_bytes(data, ctype, fname)
        payload = display_bytes or bytes(data)
        if not payload:
            remaining.append(att)
            continue

        try:
            b64 = base64.b64encode(payload).decode('utf-8')
        except Exception as b64_err:
            logger.warning(
                "Failed to base64 inline image attachment %s (%s): %s",
                fname,
                usable_type or ctype or 'image',
                b64_err,
            )
            remaining.append(att)
            continue

        alt_text = html.escape(fname or 'image attachment')
        data_url = f"data:{usable_type or ctype or 'image/png'};base64,{b64}"
        figure_html = (
            f'<figure class="inline-attachment" data-source="{html.escape(source_label)}">'
            f'<img src="{data_url}" alt="{alt_text}">' \
            f'<figcaption>{alt_text}</figcaption></figure>'
        )
        inline_figures.append(figure_html)
        inlined_names.append(fname or 'image attachment')

    if inline_figures:
        wrapper = (
            '<div class="image-attachments">'
            + ''.join(inline_figures)
            + '</div>'
        )
        body_html = append_html_after_body_content(body_html, wrapper)
    return body_html, remaining, inlined_names


def replace_image_references(html_content: str, images: Dict[str, str]) -> str:
    try:
        used_data_urls = set()
        stats = {"sanitized": 0, "inlined": 0}

        norm_images: Dict[str, str] = {}
        for k, v in (images or {}).items():
            if not k:
                continue
            norm_images[k] = v
            nk = normalize_lookup_key(str(k))
            norm_images[nk] = v
            kl = str(k).lower()
            if kl.startswith('http://') or kl.startswith('https://'):
                try:
                    norm_images[normalize_url(str(k))] = v
                except Exception:
                    pass

        def sanitize_url(u: str) -> str:
            try:
                return normalize_url(u or "")
            except Exception:
                return u or ""

        def fetch_image_as_data_url(url: str) -> str | None:
            try:
                import urllib.request
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                      "(KHTML, like Gecko) Chrome/118 Safari/537.36",
                        "Accept": "image/*"
                    }
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    ctype = resp.headers.get("Content-Type", "")
                    if not ctype.lower().startswith("image/"):
                        return None
                    max_bytes = 5 * 1024 * 1024
                    data = resp.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        return None
                    b64 = base64.b64encode(data).decode("utf-8")
                    return f"data:{ctype};base64,{b64}"
            except Exception:
                return None

        inline_remote_env = str(os.environ.get("INLINE_REMOTE_IMAGES", "true")).lower()
        inline_remote = inline_remote_env not in ("0", "false", "no", "off")

        def candidates_for(key: str):
            key = (key or '').strip()
            cands = []
            if not key:
                return cands
            cands.append(key)

            low = key.lower()
            raw = key[4:] if low.startswith('cid:') else key

            if '@' in raw:
                base_at = raw.split('@', 1)[0]
                if base_at:
                    cands.append(base_at)
                    if low.startswith('cid:'):
                        cands.append(f'cid:{base_at}')

            if low.startswith('cid:'):
                cands.append(raw)

            try:
                fname = key.split('?', 1)[0].split('#', 1)[0].split('/')[-1]
                if fname and fname != key:
                    cands.append(fname)
                    if '@' in fname:
                        fname_base = fname.split('@', 1)[0]
                        if fname_base and fname_base != fname:
                            cands.append(fname_base)
                            if low.startswith('cid:'):
                                cands.append(f'cid:{fname_base}')
            except Exception:
                pass

            return cands

        def replace_img_tag(m):
            tag = m.group(0)
            msrc = re.search(r'src\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if not msrc:
                return tag
            orig = (msrc.group(2) or "").strip()

            for lookup in (orig, sanitize_url(orig)):
                for c in candidates_for(lookup):
                    if c in norm_images:
                        data_url = norm_images[c]
                        used_data_urls.add(data_url)
                        return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)

            low = orig.lower()
            if low.startswith("http://") or low.startswith("https://"):
                sanitized = sanitize_url(orig)
                if inline_remote:
                    inlined = fetch_image_as_data_url(sanitized)
                    if inlined:
                        stats["inlined"] += 1
                        return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{inlined}"', tag, flags=re.IGNORECASE | re.DOTALL)
                if sanitized and sanitized != orig:
                    stats["sanitized"] += 1
                    return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{sanitized}"', tag, flags=re.IGNORECASE | re.DOTALL)
                return tag

            return tag

        html_new = re.sub(r'<img\b[^>]*>', replace_img_tag, html_content, flags=re.IGNORECASE)

        def replace_vml_tag(m):
            tag = m.group(0)
            msrc = re.search(r'src\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if msrc:
                orig = (msrc.group(2) or '').strip()
                for lookup in (orig, sanitize_url(orig)):
                    for c in candidates_for(lookup):
                        if c in norm_images:
                            data_url = norm_images[c]
                            used_data_urls.add(data_url)
                            tag = re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)
                            break
            mhref = re.search(r'o:href\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if mhref:
                orig = (mhref.group(2) or '').strip()
                for lookup in (orig, sanitize_url(orig)):
                    for c in candidates_for(lookup):
                        if c in norm_images:
                            data_url = norm_images[c]
                            used_data_urls.add(data_url)
                            tag = re.sub(r'o:href\s*=\s*(["\'])([\s\S]*?)\1', f'o:href="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)
                            break
            return tag

        html_new = re.sub(r'<v:imagedata\b[^>]*>', replace_vml_tag, html_new, flags=re.IGNORECASE)

        def css_url_replacer(m):
            orig = (m.group(2) or '').strip().strip('\'"')
            if not orig:
                return m.group(0)
            low = orig.lower()
            if low.startswith('data:'):
                return m.group(0)
            for lookup in (orig, sanitize_url(orig)):
                for c in candidates_for(lookup):
                    if c in norm_images:
                        data_url = norm_images[c]
                        used_data_urls.add(data_url)
                        return f'url("{data_url}")'
            if low.startswith('http://') or low.startswith('https://'):
                sanitized = sanitize_url(orig)
                if sanitized and sanitized != orig:
                    return f'url("{sanitized}")'
            return m.group(0)

        html_new = re.sub(r'url\(\s*(["\']?)([\s\S]*?)\1\s*\)', css_url_replacer, html_new, flags=re.IGNORECASE)

        fname_pat = r'(?:[A-Za-z0-9_\-]{6,}|[A-F0-9\-]{12,})\.(?:jpg|jpeg|png|gif|bmp|webp)'
        html_new = re.sub(rf'<(p|div|span)[^>]*>\s*{fname_pat}\s*</\1>', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'<li[^>]*>\s*{fname_pat}\s*</li>', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'<a[^>]*>\s*{fname_pat}\s*</a>\s*(?:<br\s*/?>)?', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'(^|[>\n\r])\s*{fname_pat}\s*(?:<br\s*/?>)?\s*(?=[<\n\r]|$)', r'\1', html_new, flags=re.IGNORECASE)

        unique_data_urls = []
        seen = set()
        for v in images.values():
            if v not in seen:
                seen.add(v)
                unique_data_urls.append(v)

        to_append = [u for u in unique_data_urls if u not in used_data_urls and u not in html_new]
        if to_append:
            imgs = ''.join([f'<img src="{u}" alt="attachment" class="inline-image" />' for u in to_append])
            appended_block = '<div class="image-attachments unreferenced-inline-images">' + imgs + '</div>'
            html_new = append_html_after_body_content(html_new, appended_block)

        try:
            soup_dbg = BeautifulSoup(html_new, "lxml")
            img_tags = soup_dbg.find_all("img")
            total_imgs = len(img_tags)
            missing_cids: List[str] = []
            non_file_imgs: List[str] = []
            file_imgs = 0
            data_imgs = 0
            remote_http = 0
            for tag in img_tags:
                src = (tag.get("src") or "").strip()
                if not src:
                    continue
                if src.startswith("cid:"):
                    missing_cids.append(src)
                elif src.startswith("file://"):
                    file_imgs += 1
                elif src.startswith("data:"):
                    data_imgs += 1
                elif src.startswith(("http://", "https://")):
                    remote_http += 1
                else:
                    non_file_imgs.append(src)

            mapped_to_file = file_imgs + data_imgs
            other_src = len(non_file_imgs)
            logger.info(
                "[PDF][CID] images: total=%d mapped_to_file=%d missing_cid=%d other_src=%d data_src=%d remote_http=%d",
                total_imgs,
                mapped_to_file,
                len(missing_cids),
                other_src,
                data_imgs,
                remote_http,
            )
            if missing_cids:
                logger.warning(
                    "[PDF][CID] unresolved cid srcs: %s", missing_cids[:10]
                )
            if non_file_imgs:
                logger.warning(
                    "[PDF][IMG] non-file/non-http srcs: %s", non_file_imgs[:10]
                )
        except Exception as cid_dbg_err:
            logger.warning(
                "[PDF][CID] image mapping inspection failed: %s", cid_dbg_err
            )

        return html_new
    except Exception as e:
        logger.warning(f"Error replacing image references: {str(e)}")
        return html_content
