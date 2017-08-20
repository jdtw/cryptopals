;;;; xor.lisp

(in-package #:cryptopals)

(defun fixed-xor (b1 b2)
  (let ((len (length b1)))
    (unless (= len (length b2)) (error "b2 is not of length ~a" len))
    (map '(vector (unsigned-byte 8) *) #'logxor b1 b2)))

(defun fixed-xor2 (stream key buffer &optional (start 0))
  (dotimes (i (length key))
    (write-byte (logxor (aref key i)
                        (aref buffer (+ start i)))
                stream)))

(defun break-single-byte-xor (bytes &key (take 5))
  (subseq
   (mapcar
    (lambda (x)
      (list (second x) (bytes->ascii (third x) :ignore-errors t)))
    (sort
     (loop for k from 0 to 255
           for candidate = (map '(vector (unsigned-byte 8) *)
                                (lambda (b) (logxor b k))
                                bytes)
           collect (list (chi-squared candidate) k candidate))
     #'< :key #'first))
   0 take))
