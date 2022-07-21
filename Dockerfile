FROM ruby:2.1.10

RUN apt-get update -qq && apt-get install -y build-essential libxml2 libxml2-dev

WORKDIR /right_aws

COPY Gemfile Gemfile.lock /right_aws/

RUN bundle install --system
