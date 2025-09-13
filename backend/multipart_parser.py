import re
import uuid
from typing import Any, Dict
from logging import Logger


class MultipartParser:
    """Decode multipart/form-data payloads with graceful fallbacks."""

    def __init__(self, logger: Logger):
        self.logger = logger

    def parse(self, body: bytes, content_type: str) -> Dict[str, Any]:
        boundary = self._extract_boundary(content_type or "", body or b"")
        if boundary:
            self.logger.info("Multipart: using manual parser with extracted boundary")
            return self.parse_manual(body, boundary)

        try:
            try:
                from multipart import MultipartParser as MP, parse_options_header
            except ImportError:
                try:
                    from multipart import MultipartParser as MP, parse_options_header
                except ImportError:
                    import multipart
                    MP = multipart.MultipartParser
                    parse_options_header = multipart.parse_options_header

            ctype, params = parse_options_header(content_type or "")
            boundary = params.get("boundary")
            if ctype != "multipart/form-data" or not boundary:
                self.logger.warning("No boundary in Content-Type; using single-file fallback")
                return self.parse_single_file_fallback(body, content_type)

            parser = MP(body, boundary)
            files: Dict[str, Any] = {}
            for part in parser.parts():
                disp = part.headers.get(b"Content-Disposition", b"").decode("utf-8", "replace")
                _, opts = parse_options_header(disp)
                name = (opts.get("name") or "").strip('"')
                filename = opts.get("filename")
                if filename:
                    files[name or "file"] = {
                        "filename": filename.strip('"'),
                        "content": part.raw,
                        "content_type": part.headers.get(b"Content-Type", b"application/octet-stream").decode("utf-8", "replace"),
                    }
                else:
                    files[name] = part.text
            return files
        except Exception as e:
            self.logger.warning(f"multipart parser failed: {e}")
            if "boundary=" in (content_type or ""):
                try:
                    boundary = content_type.split("boundary=", 1)[1].split(";", 1)[0].strip()
                    return self.parse_manual(body, boundary)
                except Exception as e2:
                    self.logger.error(f"Manual parsing also failed: {e2}")
            return self.parse_single_file_fallback(body, content_type)

    def parse_manual(self, body: bytes, boundary: str) -> Dict[str, Any]:
        boundary_bytes = f"--{boundary}".encode("utf-8")
        parts = body.split(boundary_bytes)

        files: Dict[str, Any] = {}
        for part in parts[1:-1]:
            if not part.strip():
                continue

            if b"\r\n\r\n" in part:
                headers_section, content = part.split(b"\r\n\r\n", 1)
            elif b"\n\n" in part:
                headers_section, content = part.split(b"\n\n", 1)
            else:
                continue

            content = content.rstrip(b"\r\n--")

            headers = {}
            for line in headers_section.decode("utf-8", errors="replace").split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            content_disposition = headers.get("content-disposition", "")
            if "name=" in content_disposition:
                name = content_disposition.split("name=", 1)[1].split(";", 1)[0].strip('"')
                if "filename=" in content_disposition:
                    filename = content_disposition.split("filename=", 1)[1].split(";", 1)[0].strip('"')
                    files[name] = {
                        "filename": filename,
                        "content": content,
                        "content_type": headers.get("content-type", "application/octet-stream"),
                    }
                else:
                    files[name] = content.decode("utf-8", errors="replace")

        try:
            best_key = None
            for k, v in files.items():
                if isinstance(v, dict) and 'content' in v:
                    ct = str(v.get('content_type', '')).lower()
                    fn = str(v.get('filename', ''))
                    if ct == 'message/rfc822' or fn.lower().endswith('.eml'):
                        best_key = k
                        break
            if best_key and 'file' not in files:
                files['file'] = files[best_key]
        except Exception as e:
            self.logger.warning(f"Failed to select best multipart file part: {e}")

        return files

    def parse_single_file_fallback(self, body: bytes, content_type: str) -> Dict[str, Any]:
        self.logger.info("Using single file fallback parser")
        try:
            if (body or b"").lstrip().startswith(b"--") or b"WebKitFormBoundary" in (body or b""):
                boundary = self._extract_boundary(content_type or "", body or b"")
                if boundary:
                    self.logger.info("Fallback: detected multipart body, attempting manual parse via sniffed boundary")
                    files = self.parse_manual(body, boundary)
                    if isinstance(files, dict) and isinstance(files.get("file"), dict):
                        return files
        except Exception as e:
            self.logger.warning(f"Fallback multipart sniff failed: {e}")

        filename = "uploaded_file.eml"
        try:
            body_str = body.decode('utf-8', errors='replace')
            if any(h in body_str[:1000] for h in ['From:', 'To:', 'Subject:', 'Date:']):
                filename = f"upload_{uuid.uuid4().hex[:8]}.eml"
        except Exception:
            pass

        return {
            "file": {
                "filename": filename,
                "content": body,
                "content_type": content_type if "eml" in (content_type or "") else "message/rfc822",
            }
        }

    def _extract_boundary(self, content_type: str, body: bytes) -> str | None:
        try:
            m = re.search(r'boundary=(?:"?)([^;"\s]+)', content_type or "", re.IGNORECASE)
            if m:
                b = m.group(1).strip()
                if b:
                    return b

            sample = (body or b"")[:4096]
            if sample.startswith(b"--"):
                line_end = sample.find(b"\r\n")
                if line_end == -1:
                    line_end = sample.find(b"\n")
                if line_end != -1 and line_end > 2:
                    token = sample[2:line_end].decode("utf-8", "ignore").strip()
                    if token:
                        return token

            m2 = re.search(rb'----WebKitFormBoundary[0-9A-Za-z]+', sample)
            if m2:
                token = m2.group(0).decode("utf-8", "ignore")
                return token.lstrip("-")
        except Exception:
            pass
        return None
