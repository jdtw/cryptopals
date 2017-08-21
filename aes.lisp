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
