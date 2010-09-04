# If ActiveSupport is loaded, then great - use it.  But we don't 
# want a dependency on it, so if it's not present, define the few
# extensions that we want to use...
unless defined?(ActiveSupport::CoreExtensions) || defined?(ActiveSupport::Inflector)
  # These are ActiveSupport-;like extensions to do a few handy things in the gems
  # Derived from ActiveSupport, so the AS copyright notice applies:
  #
  #
  #
  # Copyright (c) 2005 David Heinemeier Hansson
  #
  # Permission is hereby granted, free of charge, to any person obtaining
  # a copy of this software and associated documentation files (the
  # "Software"), to deal in the Software without restriction, including
  # without limitation the rights to use, copy, modify, merge, publish,
  # distribute, sublicense, and/or sell copies of the Software, and to
  # permit persons to whom the Software is furnished to do so, subject to
  # the following conditions:
  #
  # The above copyright notice and this permission notice shall be
  # included in all copies or substantial portions of the Software.
  #
  # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  # LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  # WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  #++
  #
  #
  class String #:nodoc:

    # Constantize tries to find a declared constant with the name specified
    # in the string. It raises a NameError when the name is not in CamelCase
    # or is not initialized.
    #
    # Examples
    #   "Module".constantize #=> Module
    #   "Class".constantize #=> Class
    def constantize()
      unless /\A(?:::)?([A-Z]\w*(?:::[A-Z]\w*)*)\z/ =~ self
        raise NameError, "#{self.inspect} is not a valid constant name!"
      end

      Object.module_eval("::#{$1}", __FILE__, __LINE__)
    end

    def camelize()
      self.dup.split(/_/).map{ |word| word.capitalize }.join('')
    end

  end


  class Object #:nodoc:
    # "", "   ", nil, [], and {} are blank
    def blank?
      if respond_to?(:empty?) && respond_to?(:strip)
        empty? or strip.empty?
      elsif respond_to?(:empty?)
        empty?
      else
        !self
      end
    end
  end

  class NilClass #:nodoc:
    def blank?
      true
    end
  end

  class FalseClass #:nodoc:
    def blank?
      true
    end
  end

  class TrueClass #:nodoc:
    def blank?
      false
    end
  end

  class Array #:nodoc:
    alias_method :blank?, :empty?
  end

  class Hash #:nodoc:
    alias_method :blank?, :empty?
    
    # Return a new hash with all keys converted to symbols.
    def symbolize_keys
      inject({}) do |options, (key, value)|
        options[key.to_sym] = value
        options
      end
    end
  end

  class String #:nodoc:
    def blank?
      empty? || strip.empty?
    end
  end

  class Numeric #:nodoc:
    def blank?
      false
    end
  end
end
