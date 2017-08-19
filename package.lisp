;;;; package.lisp

(defpackage #:cryptopals
  (:use #:cl)
  (:import-from #:babel
                #:string-to-octets
                #:octets-to-string)
  (:import-from #:babel-streams
                #:make-in-memory-input-stream
                #:make-in-memory-output-stream
                #:get-output-stream-sequence
                #:with-input-from-sequence
                #:with-output-to-sequence)
  (:export #:bytes->utf8
           #:utf8->bytes
           #:bytes->hex
           #:hex->bytes
           #:bytes->base64
           #:base64->bytes))
