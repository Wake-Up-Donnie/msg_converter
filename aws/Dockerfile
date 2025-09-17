# Lambda base (Amazon Linux)
FROM public.ecr.aws/lambda/python:3.11

# ---------- System packages ----------
# perl, build tools (for CPAN if needed), fonts/libs for wkhtmltopdf, wget, tar, xz
# diskspacecheck=0 sidesteps the false "0 free" overlayfs reading on macOS Docker builds
RUN mkdir -p /tmp/yum-cache \
 && yum --setopt=tsflags=nodocs --setopt=cachedir=/tmp/yum-cache --setopt=diskspacecheck=0 install -y \
    perl \
    perl-CPAN \
    make \
    gcc \
    xorg-x11-fonts-Type1 \
    libX11 \
    libXext \
    libXrender \
    libXrandr \
    libXcursor \
    libXfixes \
    libXdamage \
    libXcomposite \
    libXinerama \
    fontconfig \
    freetype \
    urw-fonts \
    wget \
    tar \
    xz \
 && yum clean all \
 && rm -rf /tmp/yum-cache

# ---------- Install Email::Outlook::Message (provides msgconvert) ----------
# (cpan is interactive by default; force non-interactive)
RUN PERL_MM_USE_DEFAULT=1 cpan -i Email::Outlook::Message

# ---------- Install wkhtmltopdf (Lambda-friendly build) ----------
# 0.12.4 is a commonly used static build that plays nicely in Lambda images
RUN wget -O /tmp/wkhtml.tgz \
  https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz \
 && tar -xJf /tmp/wkhtml.tgz -C /tmp \
 && mv /tmp/wkhtmltox/bin/wkhtmltoimage /usr/local/bin/ \
 && mv /tmp/wkhtmltox/bin/wkhtmltopdf /usr/local/bin/ \
 && chmod +x /usr/local/bin/wkhtmltopdf /usr/local/bin/wkhtmltoimage \
 && rm -rf /tmp/wkhtml*

# ---------- Python deps ----------
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ---------- Function code ----------
COPY backend/ ${LAMBDA_TASK_ROOT}/

# Entrypoint
CMD ["lambda_function.handler"]
