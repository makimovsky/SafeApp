FROM python:3.12-alpine

RUN apk add nginx gcc musl-dev linux-headers

#COPY ./nginx/default /etc/nginx/sites-available/default
#RUN nginx

COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

RUN mkdir /app
WORKDIR /app
COPY ./src /app