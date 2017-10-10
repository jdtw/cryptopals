;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :depends-on (#:babel
               #:babel-streams
               #:cffi
               #:alexandria
               #:str)
  :serial t
  :components ((:file "package")
               (:file "strings")
               (:file "chi")
               (:file "block")
               (:file "xor")
               (:file "bcrypt")
               (:file "aes")
               (:file "cookie")
               (:file "cbc-bitflipping")
               (:file "padding-oracle")
               (:file "cryptopals")))
