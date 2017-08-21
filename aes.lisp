;;;; aes.lisp

(in-package #:cryptopals)

(defmacro with-aes-128 ((stream-var key-var blocks-var secret bytes &key pad)
                        &body body)
  (with-gensyms (secret-var bytes-var alg-var)
    `(let ((,secret-var ,secret) (,bytes-var ,bytes))
       (with-output-to-sequence (,stream-var
                                 :element-type '(unsigned-byte 8)
                                 :initial-buffer-size (length ,bytes-var))
         (with-aes-ecb-algorithm (,alg-var)
           (with-symmetric-key (,key-var ,alg-var ,secret-var)
             (let ((,blocks-var (blockify 16 ,bytes-var :pad ,pad)))
               ,@body)))))))

(defun decrypt-aes-128-ecb (secret bytes)
  (with-aes-128 (stream key blocks secret bytes)
    (dolist (ciphertext blocks)
      (write-sequence (decrypt key ciphertext) stream))))

(defun encrypt-aes-128-ecb (secret bytes)
  (with-aes-128 (stream key blocks secret bytes :pad t)
    (dolist (plaintext blocks)
      (write-sequence (encrypt key plaintext) stream))))

(defun encrypt-aes-128-cbc (secret iv bytes)
  (with-aes-128 (stream key blocks secret bytes :pad t)
    (let ((ciphertext iv))
      (dolist (plaintext blocks)
        (write-sequence
         (setf ciphertext (encrypt key (fixed-xor plaintext ciphertext)))
         stream)))))

(defun decrypt-aes-128-cbc (secret iv bytes)
  (with-aes-128 (stream key blocks secret bytes)
    (let ((xor iv))
      (dolist (ciphertext blocks)
        (write-sequence (fixed-xor (decrypt key ciphertext) xor) stream)
        (setf xor ciphertext)))))

(defun detect-aes-128-ecb (bytes)
  (labels ((detector (blocks matches)
             (cond
               ((null blocks) matches)
               (t (loop for b in (cdr blocks)
                        do (when (equalp (car blocks) b)
                             (incf matches)))
                  (detector (cdr blocks) matches)))))
    (let ((matches (detector (blockify 16 bytes) 0)))
      (if (= matches 0) nil matches))))

(defun encryption-oracle (bytes)
  (let ((bytes (concatenate '(vector (unsigned-byte 8) *)
                            (gen-random (+ (random 6) 5))
                            bytes
                            (gen-random (+ (random 6) 5))))
        (secret (gen-random 16)))
    (if (= (random 2) 0)
        (values (encrypt-aes-128-ecb secret bytes) t)
        (values (encrypt-aes-128-cbc secret (gen-random 16) bytes) nil))))
