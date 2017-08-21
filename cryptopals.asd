;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :depends-on (#:babel
               #:babel-streams
               #:cffi
               #:alexandria)
  :serial t
  :components ((:file "package")
               (:file "strings")
               (:file "chi")
               (:file "block")
               (:file "xor")
               (:file "bcrypt")
               (:file "aes")
               (:file "cryptopals")))
