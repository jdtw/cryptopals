;;;; package.lisp

(defpackage #:cryptopals
  (:use #:cl)
  (:nicknames #:cp)
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
           #:fixed-xor
           #:break-single-byte-xor
           #:repeating-xor
           #:hamming-distance
           #:find-xor-keysize
           #:break-repeating-xor))
