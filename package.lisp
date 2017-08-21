;;;; package.lisp

(defpackage #:cryptopals
  (:use #:cl #:cffi)
  (:nicknames #:cp)
  (:import-from #:alexandria
                #:define-constant
                #:with-gensyms)
  (:import-from #:babel
                #:string-to-octets
                #:octets-to-string
                #:character-decoding-error)
  (:import-from #:babel-streams
                #:make-in-memory-input-stream
                #:make-in-memory-output-stream
                #:get-output-stream-sequence
                #:with-input-from-sequence
                #:with-output-to-sequence)
  (:export #:bytes->ascii
           #:ascii->bytes
           #:bytes->hex
           #:hex->bytes
           #:bytes->base64
           #:base64->bytes
           #:read-base64-file
           #:read-hex-line-file
           #:blockify
           #:fixed-xor
           #:*frequencies*
           #:break-single-byte-xor
           #:repeating-xor
           #:hamming-distance
           #:find-xor-keysize
           #:break-repeating-xor
           #:gen-random
           #:encrypt-aes-128-ecb
           #:decrypt-aes-128-ecb
           #:detect-aes-128-ecb
           #:pad-pkcs7
           #:unpad-pkcs7
           #:encrypt-aes-128-cbc
           #:decrypt-aes-128-cbc
           #:encryption-oracle
           #:make-oracle))
