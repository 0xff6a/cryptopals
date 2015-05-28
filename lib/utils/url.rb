module URL
  module_function

  ELEMENT_DELIM = '&'
  VALUE_DELIM   = '='
  EMAIL_REGEXP  = /\A[^@]+@([^@\.]+\.)+[^@\.]+\z/

  def kv_parse(url_s)
    elements = url_s.split(ELEMENT_DELIM)

    Hash[elements.map { |el| 
      k,v = el.split(VALUE_DELIM)
      [ k.to_sym, v ]
    }]
  end

  def profile_for(email)
    raise ArgumentError, 'Invalid email' unless email =~ EMAIL_REGEXP

    {
      email: CGI.escape(email).gsub('%40', '@'),
      uid:   email.hash % 1000,
      role:  'user'
    }
  end
end