;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :depends-on (#:babel
               #:babel-streams)
  :serial t
  :components ((:file "package")
               (:file "strings")
               (:file "cryptopals")))
