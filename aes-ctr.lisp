;;;; aes-ctr.lisp

(in-package #:cryptopals)

;; key=YELLOW SUBMARINE
;; nonce=0
;; format=64 bit unsigned little endian nonce,
;;        64 bit little endian block count (byte count / 16)

(defclass aes-ctr ()
  ((secret :initarg :secret
           :initform (gen-random 16)
           :accessor aes-ctr-secret)
   (nonce :initarg :nonce
          :type '(unsigned-byte 64)
          :initform 0
          :accessor aes-ctr-nonce)
   (counter :initarg :counter
            :type '(unsigned-byte 64)
            :initform 0
            :accessor aes-ctr-counter)))

(defun reset-counter (aes-ctr)
  (setf (aes-ctr-counter aes-ctr) 0))

(defun key-stream (aes-ctr)
  (let* ((bytes (with-output-to-sequence
                    (stream :element-type '(unsigned-byte 8)
                            :initial-buffer-size 16)
                  (write-ub64/le (aes-ctr-nonce aes-ctr) stream)
                  (write-ub64/le (aes-ctr-counter aes-ctr) stream)))
         (key-stream (encrypt-aes-128-ecb (aes-ctr-secret aes-ctr) bytes)))
    (incf (aes-ctr-counter aes-ctr))
    key-stream))

(defun crypt-aes-ctr (aes-ctr bytes)
  (mappend-bytes (lambda (b) (xor-bytes b (key-stream aes-ctr)))
                 (blockify bytes)))
