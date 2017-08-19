;;;; xor.lisp

(in-package #:cryptopals)

(defun fixed-xor (b1 b2)
  (let ((len (length b1)))
    (unless (= len (length b2)) (error "b2 is not of length ~a" len))
    (map '(vector (unsigned-byte 8) *) #'logxor b1 b2)))
