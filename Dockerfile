FROM python:3.12.2 AS build

ENV TZ="Europe/Moscow"

RUN set -ex && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    cmake \
    build-essential \
    libboost-all-dev \
    python3-dev \
    unzip && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

COPY ./cprocsp /cprocsp

WORKDIR /cprocsp

RUN set -ex && \
    tar xvf linux-amd64_deb.tgz && \
    ./linux-amd64_deb/install.sh && \
    apt-get install ./linux-amd64_deb/lsb-cprocsp-devel_*.deb

RUN set -ex && \
    mkdir ./cades-linux-amd64 && \
    tar xvf cades-linux-amd64.tar.gz && \
    apt-get install ./cades-linux-amd64/cprocsp-pki-cades-*amd64.deb

RUN set -ex && \
    unzip pycades.zip && \
    sed -i '2c\SET(Python_INCLUDE_DIR "/usr/local/include/python3.12")' ./pycades_*/CMakeLists.txt

RUN set -ex && \
    cd /cprocsp/pycades_* && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j4

FROM python:3.12.2

COPY --from=build /cprocsp/pycades_*/pycades.so /usr/local/lib/python3.12/site-packages/pycades.so
COPY --from=build /opt/cprocsp /opt/cprocsp/
COPY --from=build /var/opt/cprocsp /var/opt/cprocsp/
COPY --from=build /etc/opt/cprocsp /etc/opt/cprocsp/

RUN set -ex && \
    apt-get update && \
    apt-get install -y --no-install-recommends expect && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ADD scripts/ /scripts
RUN cd /bin && \
    ln -s /opt/cprocsp/bin/amd64/certmgr && \
    ln -s /opt/cprocsp/bin/amd64/cpverify && \
    ln -s /opt/cprocsp/bin/amd64/cryptcp && \
    ln -s /opt/cprocsp/bin/amd64/csptest && \
    ln -s /opt/cprocsp/bin/amd64/csptestf && \
    ln -s /opt/cprocsp/bin/amd64/der2xer && \
    ln -s /opt/cprocsp/bin/amd64/inittst && \
    ln -s /opt/cprocsp/bin/amd64/wipefile && \
    ln -s /opt/cprocsp/sbin/amd64/cpconfig

# FastAPI setup
ENV PYTHONUNBUFFERED=1
ENV PATH=/usr/local/bin:$PATH
ENV LANG=C.UTF-8

RUN mkdir -p /src/static

WORKDIR /src

RUN apt-get update -y && \
    pip install poetry && \
    pip install --upgrade pip

COPY /src /src

RUN poetry install --no-root

RUN poetry run python -c "import site; print(site.getsitepackages()[0])" > /tmp/site_packages_path.txt && \
    cp /usr/local/lib/python3.12/site-packages/pycades.so $(cat /tmp/site_packages_path.txt)/

EXPOSE 80

CMD ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]