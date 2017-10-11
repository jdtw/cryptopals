;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :depends-on (#:babel
               #:babel-streams
               #:cffi
               #:alexandria
               #:str
               #:nibbles)
  :serial t
  :components ((:file "package")
               (:file "bytes")
               (:file "strings")
               (:file "chi")
               (:file "block")
               (:file "xor")
               (:file "bcrypt")
               (:file "aes")
               (:file "cookie")
               (:file "cbc-bitflipping")
               (:file "padding-oracle")
               (:file "aes-ctr")
               (:file "cryptopals")))
