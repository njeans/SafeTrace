FROM ubuntu:18.04

#ENV VERSION 2.6.100.51363
#ENV SGX_DOWNLOAD_URL_BASE "https://download.01.org/intel-sgx/linux-2.6/ubuntu18.04-server"
#ENV SGX_LINUX_X64_SDK sgx_linux_x64_sdk_2.6.100.51363.bin
#ENV SGX_LINUX_X64_SDK_URL "$SGX_DOWNLOAD_URL_BASE/$SGX_LINUX_X64_SDK"

ENV sdk_bin https://download.01.org/intel-sgx/linux-2.6/ubuntu18.04-server/sgx_linux_x64_sdk_2.6.100.51363.bin
ENV psw_deb https://download.01.org/intel-sgx/linux-2.6/ubuntu18.04-server/libsgx-enclave-common_2.6.100.51363-bionic1_amd64.deb
ENV psw_dev_deb https://download.01.org/intel-sgx/linux-2.6/ubuntu18.04-server/libsgx-enclave-common-dev_2.6.100.51363-bionic1_amd64.deb
ENV psw_dbgsym_deb https://download.01.org/intel-sgx/linux-2.6/ubuntu18.04-server/libsgx-enclave-common-dbgsym_2.6.100.51363-bionic1_amd64.ddeb

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -q -y \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    curl \
    pkg-config \
    wget

#RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | \
#  tee /etc/apt/sources.list.d/intel-sgx.list
#RUN curl -fsSL  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

RUN mkdir /root/sgx && \
    mkdir /etc/init && \
    wget -O /root/sgx/psw.deb ${psw_deb} && \
    wget -O /root/sgx/psw_dev.deb ${psw_dev_deb} && \
    wget -O /root/sgx/psw_dbgsym.deb ${psw_dbgsym_deb} && \
    wget -O /root/sgx/sdk.bin ${sdk_bin} && \
    cd /root/sgx && \
    dpkg -i /root/sgx/psw.deb && \
    dpkg -i /root/sgx/psw_dev.deb && \
    dpkg -i /root/sgx/psw_dbgsym.deb && \
    chmod +x /root/sgx/sdk.bin && \
    echo -e 'no\n/opt' | /root/sgx/sdk.bin && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    rm -rf /root/sgx/*

# Install Intel SGX SDK for libsgx_urts_sim.so
#RUN wget $SGX_LINUX_X64_SDK_URL               && \
#    chmod u+x $SGX_LINUX_X64_SDK              && \
#    echo -e 'no\n/opt' | ./$SGX_LINUX_X64_SDK && \
#    rm $SGX_LINUX_X64_SDK                     && \
#    echo 'source /opt/sgxsdk/environment' >> /etc/environment
ENV LD_LIBRARY_PATH=/opt/sgxsdk/sdk_libs

RUN apt-get update && apt-get install -q -y \
    libzmq3-dev
ADD safetrace/bin/safetrace-app /usr/local/bin/safetrace-app
