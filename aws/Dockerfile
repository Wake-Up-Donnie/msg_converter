# Lambda Python base (Amazon Linux 2023 / glibc 2.34)
# NOTE: Build scripts force --platform=linux/amd64 to avoid exec format errors when building on Apple Silicon.
ARG TARGETARCH
FROM public.ecr.aws/lambda/python:3.12

# (TARGETARCH is available for conditional logic if ever needed)

# Faster, repeatable builds
ENV PIP_NO_CACHE_DIR=1

# Upgrade pip
RUN pip3 install --upgrade pip

# ---- Python deps ----
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt \
    && pip3 install playwright==1.54.0

# ---- System deps for headless Chromium on Amazon Linux 2023 ----
# AL2023 uses dnf/microdnf (not apt). Install the libraries Chromium needs.
# (Fonts help Playwright render PDFs with text correctly.)
RUN dnf install -y \
      atk \
      at-spi2-atk \
      at-spi2-core \
      cups-libs \
      libdrm \
      libxcb \
      libxkbcommon \
      libX11 \
      libXcomposite \
      libXdamage \
      libXext \
      libXfixes \
      libXrandr \
      mesa-libgbm \
      pango \
      cairo \
      alsa-lib \
      fontconfig \
      dejavu-sans-fonts \
      dejavu-serif-fonts \
      nspr \
      nss \
      nss-util \
    && dnf clean all && rm -rf /var/cache/dnf

# Install Twemoji font instead of Noto Color Emoji to avoid spacing issues
RUN dnf install -y ttf-twemoji || true
# Fallback: manually install Twemoji if package not available
RUN mkdir -p /usr/share/fonts && \
  curl -L -o /usr/share/fonts/ttf-twemoji.ttf \
    https://github.com/twitter/twemoji/raw/master/assets/fonts/TwitterColorEmoji-SVGinOT.ttf && \
  fc-cache -f -v

# ---- Set consistent browser path for Lambda ----
# Removed Noto Color Emoji fallback install since it causes spacing issues

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# ---- Bake the Chromium browser into the image ----
# Do NOT use --with-deps on AL2023; it tries apt-get and fails.
RUN python -m playwright install chromium

# ---- Copy browsers to Lambda-accessible path and set permissions ----
RUN mkdir -p /opt/ms-playwright && \
    cp -r /root/.cache/ms-playwright/* /opt/ms-playwright/ 2>/dev/null || true && \
    python3 -c "import os; [os.chmod(os.path.join(r,f), 0o755) for r,d,files in os.walk('/opt/ms-playwright') for f in files]; [os.chmod(os.path.join(r,d), 0o755) for r,dirs,f in os.walk('/opt/ms-playwright') for d in dirs]; os.chmod('/opt/ms-playwright', 0o755)" 2>/dev/null || true

# ---- Verify browser installation ----
RUN python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); print('Browser path:', p.chromium.executable_path); p.stop()"

# ---- App code ----
COPY backend/ ${LAMBDA_TASK_ROOT}/

# Lambda handler (module.function)
CMD ["lambda_function.lambda_handler"]
