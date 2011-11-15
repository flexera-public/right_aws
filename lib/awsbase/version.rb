module RightAws #:nodoc:
  module VERSION #:nodoc:
    MAJOR = 3  unless defined?(MAJOR)
    MINOR = 0  unless defined?(MINOR)
    TINY  = 0  unless defined?(TINY)

    STRING = [MAJOR, MINOR, TINY].join('.') unless defined?(STRING)
  end
end
