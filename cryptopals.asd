;;;; cryptopals.asd

(asdf:defsystem #:cryptopals
  :description "Cryptopals Solutions"
  :author "John Wood <j@jdtw.us>"
  :license "MIT"
  :serial t
  :components ((:file "package")
               (:file "cryptopals")))
