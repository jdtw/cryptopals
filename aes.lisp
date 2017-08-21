;;;; aes.lisp

(in-package #:cryptopals)

(defun decrypt-aes-128-ecb (secret bytes)
  (with-aes-ecb-algorithm (alg)
    (with-symmetric-key (key alg secret)
      (decrypt key bytes))))

(defun encrypt-aes-128-ecb (secret bytes)
  (with-aes-ecb-algorithm (alg)
    (with-symmetric-key (key alg secret)
      (encrypt key bytes))))

(defun encrypt-aes-128-cbc (secret iv bytes)
  (with-output-to-sequence (stream :element-type '(unsigned-byte 8)
                                   :initial-buffer-size (length bytes))
    (with-aes-ecb-algorithm (alg)
      (with-symmetric-key (key alg secret)
        (let ((blocks (blockify 16 bytes :pad t)) (ciphertext iv))
          (dolist (plaintext blocks)
            (write-sequence
             (setf ciphertext (encrypt key (fixed-xor plaintext ciphertext)))
             stream)))))))

(defun decrypt-aes-128-cbc (secret iv bytes)
  (with-output-to-sequence (stream :element-type '(unsigned-byte 8)
                                   :initial-buffer-size (length bytes))
    (with-aes-ecb-algorithm (alg)
      (with-symmetric-key (key alg secret)
        (let ((blocks (blockify 16 bytes)) (xor iv))
          (dolist (ciphertext blocks)
            (write-sequence (fixed-xor (decrypt key ciphertext) xor) stream)
            (setf xor ciphertext)))))))

(defun detect-aes-128-ecb (bytes)
  (labels ((detector (blocks matches)
             (cond
               ((null blocks) matches)
               (t (loop for b in (cdr blocks)
                        do (when (equalp (car blocks) b)
                             (incf matches)))
                  (detector (cdr blocks) matches)))))
    (detector (blockify 16 bytes) 0)))
