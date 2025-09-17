# Lambda base (Amazon Linux 2023 w/ glibc 2.34)
FROM public.ecr.aws/lambda/python:3.12

# ---------- System packages ----------
# Install the minimal native tooling needed for Perl modules and wkhtmltopdf.
RUN dnf install -y \
    perl \
    make \
    tar \
    xz \
    gzip \
    curl \
    wget \
    fontconfig \
    freetype \
    urw-base35-fonts \
    libX11 \
    libXext \
    libXrender \
    libXrandr \
    libXcursor \
    libXfixes \
    libXdamage \
    libXcomposite \
    libXinerama \
    xorg-x11-fonts-Type1 \
 && dnf clean all \
 && rm -rf /var/cache/dnf

# ---------- Install Email::Outlook::Message (provides msgconvert) ----------
# Use cpanminus to pull the module and its pure-Perl dependencies into /opt/perl.
ENV PERL5LIB=/opt/perl/lib/perl5
ENV PATH=/opt/perl/bin:$PATH
RUN curl -L https://cpanmin.us | perl - --notest --local-lib=/opt/perl App::cpanminus \
 && /opt/perl/bin/cpanm --notest --local-lib=/opt/perl Email::Outlook::Message \
 && ln -s /opt/perl/bin/msgconvert /usr/local/bin/msgconvert

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
