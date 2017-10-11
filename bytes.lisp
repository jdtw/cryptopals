;;;; bytes.lisp

(in-package #:cryptopals)

(defun map-bytes (func sequence &rest more-sequences)
  (apply #'map '(vector (unsigned-byte 8) *) func sequence more-sequences))

(defun concat-bytes (&rest sequences)
  (declare (optimize speed))
  (apply #'concatenate '(vector (unsigned-byte 8) *) sequences))

(defun mappend-bytes (func sequence &rest more-sequences)
  (apply #'concat-bytes (apply #'mapcar func sequence more-sequences)))
