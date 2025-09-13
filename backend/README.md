# Backend Lambda Overview

This backend exposes a message conversion API used by the project.  The code has been
refactored to introduce a few lightweight classes that make the behavior easier to
follow and maintain.

## Key Components

### `EmailConverter`
Located in `converter.py`, this class wraps the heavy lifting required to turn
Outlook `.msg` files into standard EML documents while extracting any embedded
attachments.  The Lambda module exposes thin wrapper functions so existing code
can continue to call `convert_msg_bytes_to_eml_bytes` or
`convert_msg_bytes_to_eml_bytes_with_attachments` without modification.

### `LambdaRouter`
Defined in `router.py`, the router centralizes request dispatching and CORS
handling.  It maps incoming API Gateway paths to the appropriate handler
functions while verifying that Playwright is available for PDF rendering.

### `DocumentConverter`
Found in `document_converter.py`, this class groups together the heavy
document and email conversion helpers.  It powers functions like
`convert_docx_to_html_with_images` and `convert_office_to_pdf` while delegating
HTML-to-PDF rendering back to the Lambda module.

### `RequestParser`
Found in `request_parser.py`, this helper normalizes headers and body
extraction from API Gateway events. Handlers construct an instance to
access lowercase headers, raw body bytes, or parsed JSON without duplicating
boilerplate logic.

### `MultipartParser`
Located in `multipart_parser.py`, this class decodes `multipart/form-data`
payloads and gracefully falls back to single-file uploads when boundaries
are missing. The Lambda handlers use it to process uploaded `.eml` files.

### `lambda_function.py`
The main entry point now simply configures logging, initializes the converter
and router, wires up the parsers, and delegates each invocation to
`LambdaRouter.handle`.  Browser processes are cleaned up after every request.

## Extending

1. Implement new handler functions in `lambda_function.py`.
2. Register them in the `HANDLERS` mapping near the bottom of the file.
3. The router will automatically add the correct CORS headers and invoke your
   handler.

This structure keeps the Lambda entry point compact while isolating complex
conversion logic into well-scoped classes.
