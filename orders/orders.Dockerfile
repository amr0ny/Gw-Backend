FROM python:3.10-alpine
#RUN apk add curl
RUN apk add build-base
RUN apk add libffi-dev


WORKDIR /usr/src/

COPY ./requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir --upgrade -r requirements.txt

# Добавим вывод содержимого текущей директории перед копированием
RUN ls -la

COPY ./orders/entrypoint.sh ./entrypoint.sh
RUN chmod 755 ./entrypoint.sh
RUN sed -i 's/\r$//g' ./entrypoint.sh

COPY ./orders .
EXPOSE 8000

ENTRYPOINT ["/bin/sh", "/usr/src/entrypoint.sh"]