FROM python:3.8
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV PYTHONIOENCODING UTF-8
ENV PYTHONUNBUFFERED 1
COPY flag readflag /
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/* && \
    useradd challenge && \
    groupadd readflag && \
    chown root:readflag /flag && chmod 0640 /flag && \
    chown root:readflag /readflag && chmod 2755 /readflag && \
    mkdir /app
WORKDIR /app
EXPOSE 1337
CMD ["socat", "tcp-l:1337,reuseaddr,fork", "exec:./pyaucalc.py,su=challenge"]
