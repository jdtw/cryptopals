;;;; padding-oracle.lisp

(in-package #:cryptopals)

(defclass cbc-padding-oracle ()
  ((secret :initform (gen-random 16) :accessor oracle-secret)))

(defun make-padding-oracle ()
  (make-instance 'cbc-padding-oracle))

(defun oracle-encrypt (oracle plaintext)
  (let ((iv (gen-random 16))
        (bytes (base64->bytes plaintext)))
    (values iv (encrypt-aes-128-cbc (oracle-secret oracle)
                                    iv
                                    bytes))))

(defun oracle-decrypt (oracle iv ciphertext)
  (let ((bytes (decrypt-aes-128-cbc (oracle-secret oracle) iv ciphertext)))
    (bytes->ascii (unpad-pkcs7 bytes) :ignore-errors t)))

(defclass broken-char ()
  ((plaintext :initarg :plaintext
              :accessor broken-char-plaintext
              :type '(unsigned-byte 8))
   (original :initarg :original
             :accessor broken-char-original
             :type '(unsigned-byte 8))))

(defun make-broken-char (plaintext original)
  (assert (and plaintext original))
  (make-instance 'broken-char
                 :plaintext plaintext
                 :original original))

(defun broken-char-pad (broken-char pad)
  (logxor (broken-char-original broken-char)
          (broken-char-plaintext broken-char)
          pad))

(defun break-byte (oracle iv block known pad candidate)
  (handler-case
      (let* ((original (aref iv (- 16 pad)))
             (x (logxor original candidate pad))
             (xarr (make-array 1 :initial-element x))
             (padding (map-bytes (lambda (bc)
                                   (broken-char-pad bc pad))
                                 (reverse known)))
             (iv (concat-bytes (subseq iv 0 (- 16 pad))
                               xarr
                               padding)))
        (oracle-decrypt oracle iv block)
        (make-broken-char candidate original))
    (invalid-padding-error () nil)))

(defun break-cbc-block (oracle iv block &key (max-byte #x7e))
  (loop with known = (make-array 0 :element-type 'broken-char
                                   :fill-pointer 0
                                   :adjustable t)
        for pad from 1 to 16
        do (loop for b from max-byte downto pad
                 for broken = (break-byte oracle iv block known pad b)
                 until broken
                 finally (progn (assert broken)
                                (vector-push-extend broken known)))
        finally (return (reverse (map-bytes #'broken-char-plaintext known)))))

(defun break-cbc-with-padding-oracle (oracle iv ciphertext)
  (let* ((blocks (blockify ciphertext))
         (decryption (loop with iv = iv
                           for block in blocks
                           collect
                           (let ((decryption (break-cbc-block oracle iv block)))
                             (setf iv block)
                             decryption))))
    (bytes->ascii (unpad-pkcs7 (apply #'concat-bytes decryption)))))
