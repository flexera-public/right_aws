RightAws
    by RightScale, Inc.
    www.RightScale.com 

== DESCRIPTION:

RightAws::Ec2 is a Ruby library for the Amazon EC2 (Elastic Compute Cloud)
service.

RightAws::S3 and RightAws::S3Interface are Ruby libraries for the Amazon S3
(Simple Storage Service) service.

RightAws::Sqs and RightAws::SqsInterface is a Ruby library for the Amazon SQS (Simple Queue Service)
service.

  
All RightAws interfaces work in one of two ways:
1) They use a single persistent HTTP connection per
process or 2) per Ruby thread. Foir example, it doesn't matter how many RightAws::S3
objects you create, they all use the same per-program or per-thread
connection. The purpose of sharing the connection is to keep a single
persistent HTTP connection open to avoid paying connection
overhead on every request. However, if you have multiple concurrent
threads, you may want or need an HTTP connection per thread to enable
concurrent requests to S3. The way this plays out in practice is:
1) If you have a non-multithreaded Ruby program, use the non-multithreaded setting for Gem.
2) If you have a multi-threaded Ruby program, use the multithreaded setting to enable
concurrent requests to S3 (SQS, EC2).
3) For running under Mongrel/Rails, use thhe non-multithreaded setting for Gem even though
Mongrel is multithreaded.  This is because only one Rails handler is invoked at
any time (i.e. it acts like a single-threaded program)

By default, Ec2/S3/Sqs interface instances are created in single-threaded mode.  Set
"params[:multi_thread]" to "true" in the initialization arguments to use
multithreaded mode.

== FEATURES/PROBLEMS:

- Full programmmatic access to Ec2, S3, and Sqs
- Robust network-level retry layer (using Rightscale::HttpConnection).  This includes
  socket connect and read timeouts and retries.
- Robust HTTP-level retry layer.  Certain (user-adjustable) HTTP errors are
  classified as temporary errors.  These errors are automaticallly retried
  over exponentially increasing intervals.  The number of retries is
  user-configurable.
- Support for large S3 list operations.  Buckets and key subfolders containing
  many (> 1000) keys are listed in entirety.  Operations based on list (like
  bucket clear) work on arbitrary numbers of keys.
- Support for streaming PUTs to S3 if the data source is a file.
- Support for streaming GETs from S3.
- Interfaces for HTML link generation.

Known Problems:

- Amazon recently (8/07) changed the semantics of the SQS service.  A
  new queue may not be created within 60 seconds of the destruction of any
  older queue with the same name.  Certain methods of RightAws::Sqs and
  RightAws::SqsInterface will fail with the message:
  "AWS.SimpleQueueService.QueueDeletedRecently: You must wait 60 seconds after deleting a queue before you can create another with the same name."
  
== SYNOPSIS:





== REQUIREMENTS:

RightAws requires activesupport and RightScale's right_http_connection gem.

== INSTALL:

sudo gem install

== LICENSE:

Copyright (c) 2007 RightScale, Inc. 

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
