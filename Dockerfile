FROM ruby:2.1.10

RUN apt-get update -qq \
&& apt-get install -y build-essential libxml2 libxslt-dev libxml2-dev

ADD . /code/Ruby-Docker
WORKDIR /code/Ruby-Docker

RUN  bundle install

CMD ["bash"]
