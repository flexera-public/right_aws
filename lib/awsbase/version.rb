module RightAws #:nodoc:
  module VERSION #:nodoc:
    MAJOR = 2  unless defined?(MAJOR)
    MINOR = 1  unless defined?(MINOR)
    TINY  = 1  unless defined?(TINY)

    STRING = [MAJOR, MINOR, TINY].join('.') unless defined?(STRING)
  end
end
