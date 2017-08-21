;;;; aes.lisp

(in-package #:cryptopals)

(defun decrypt-aes-128-ecb (secret bytes)
  (with-aes-ecb-algorithm (alg)
    (with-symmetric-key (key alg secret)
      (decrypt key bytes))))

(defun detect-aes-128-ecb (bytes)
  (labels ((detector (blocks matches)
             (cond
               ((null blocks) matches)
               (t (loop for b in (cdr blocks)
                        do (when (equalp (car blocks) b)
                             (incf matches)))
                  (detector (cdr blocks) matches)))))
    (detector (blockify 16 bytes) 0)))

(defun pad-pkcs7 (block-len bytes)
  (let ((delta (- block-len (length bytes))))
    (when (< delta 0) (error "buffer is longer than the block length"))
    (with-output-to-sequence (padded :element-type '(unsigned-byte 8)
                                     :initial-buffer-size block-len)
      (write-sequence bytes padded)
      (write-sequence (make-array delta :element-type '(unsigned-byte 8)
                                        :initial-element delta)
                      padded))))
