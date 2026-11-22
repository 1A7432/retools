# jsvm1-tools: the execution image for jsworker (worker tools) and the jsvm1 grader.
# Built by build.sh, which first fills cache/ (node tarball, wheels, node_modules) so
# that the docker build itself only needs the Debian mirror for python3.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG NODE_DIST
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip xz-utils \
 && rm -rf /var/lib/apt/lists/*

COPY cache/${NODE_DIST}.tar.xz /tmp/node.tar.xz
RUN tar -xJf /tmp/node.tar.xz -C /tmp \
 && cp /tmp/${NODE_DIST}/bin/node /usr/local/bin/node \
 && rm -rf /tmp/node.tar.xz /tmp/${NODE_DIST}

COPY requirements.txt /tmp/requirements.txt
COPY cache/wheels /tmp/wheels
RUN pip3 install --break-system-packages --no-index --find-links /tmp/wheels --no-deps \
        --require-hashes -r /tmp/requirements.txt \
 && apt-get purge -y python3-pip xz-utils && apt-get autoremove -y \
 && rm -rf /tmp/wheels /tmp/requirements.txt /root/.cache

ENV NODE_PATH=/opt/jsre/node_modules TZ=UTC LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1
COPY cache/node_modules /opt/jsre/node_modules
COPY sandbox_hook.py pyrun.py grade_runner.py beautify.js /opt/jsre/
RUN useradd -u 1000 -m worker \
 && mkdir -p /task/public /task/work && chown 1000:1000 /task/work \
 && chmod -R a+rX,go-w /opt/jsre \
 && python3 -c "import Crypto, gmssl; print('pycryptodome', Crypto.__version__)" \
 && node -e "require('@babel/parser'); require('@babel/traverse'); require('@babel/generator'); require('acorn'); require('acorn-walk'); require('astring'); console.log('node', process.version)"

USER 1000:1000
WORKDIR /task/work
