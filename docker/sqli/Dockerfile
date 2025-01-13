FROM ubuntu:latest
MAINTAINER Z0SO

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt update && apt install -y net-tools iputils-ping curl wget git nano php apache2 mariadb-server php-mysql

EXPOSE 80

ENTRYPOINT service apache2 start && /bin/bash
