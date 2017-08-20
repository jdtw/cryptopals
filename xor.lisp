;;;; xor.lisp

(in-package #:cryptopals)

(defun fixed-xor (b1 b2)
  (let ((len (length b1)))
    (unless (= len (length b2)) (error "b2 is not of length ~a" len))
    (map '(vector (unsigned-byte 8) *) #'logxor b1 b2)))

(defun break-single-byte-xor (bytes &key (take 5))
  (mapcar
   (lambda (x)
     (list :score (first x)
           :key (second x)
           :string (bytes->ascii (third x) :ignore-errors t)))
   (subseq
    (sort
     (loop for k from 0 to 255
           for candidate = (map '(vector (unsigned-byte 8) *)
                                (lambda (b) (logxor b k))
                                bytes)
           collect (list (chi-squared candidate) k candidate))
     #'< :key #'first)
    0 take)))

(defun repeating-xor (key bytes)
  (with-output-to-sequence (stream :element-type '(unsigned-byte 8))
    (loop with key-len = (length key)
          with buffer-len = (length bytes)
          for pos = 0 then (+ pos key-len)
          while (< pos buffer-len) do
            (write-sequence
             (if (< (- buffer-len pos) key-len)
                 (fixed-xor (subseq key 0 (- buffer-len pos))
                            (subseq bytes pos buffer-len))
                 (fixed-xor key (subseq bytes pos (+ pos key-len))))
             stream))))
