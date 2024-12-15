FROM python:3.12-alpine

RUN apk add gcc musl-dev linux-headers

RUN addgroup -S uwsgi && adduser -S uwsgi -G uwsgi

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

RUN mkdir /app
WORKDIR /app
COPY ./ /app

RUN chown -R uwsgi:uwsgi /app

USER uwsgi

CMD ["uwsgi", "app.ini"]