FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/phishlens
COPY pyproject.toml README.md LICENSE ./
COPY phishlens ./phishlens
RUN pip install . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin analyst \
    && mkdir -p /data \
    && chown analyst:analyst /data

USER analyst
WORKDIR /data

ENTRYPOINT ["phishlens"]
CMD ["--help"]
