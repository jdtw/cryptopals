;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :depends-on (#:babel
               #:babel-streams
               #:cffi)
  :serial t
  :components ((:file "package")
               (:file "strings")
               (:file "chi")
               (:file "xor")
               (:file "bcrypt")
               (:file "cryptopals")))
