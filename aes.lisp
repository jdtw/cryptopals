;;;; aes.lisp

(in-package #:cryptopals)

(defun concat-bytes (&rest sequences)
  (apply #'concatenate '(vector (unsigned-byte 8) *) sequences))

(defmacro with-aes-128 ((stream-var key-var blocks-var secret bytes &key pad)
                        &body body)
  (with-gensyms (secret-var bytes-var alg-var)
    `(let ((,secret-var ,secret) (,bytes-var ,bytes))
       (with-output-to-sequence (,stream-var
                                 :element-type '(unsigned-byte 8)
                                 :initial-buffer-size (length ,bytes-var))
         (with-aes-ecb-algorithm (,alg-var)
           (with-symmetric-key (,key-var ,alg-var ,secret-var)
             (let ((,blocks-var (blockify ,bytes-var :pad ,pad)))
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
    (let ((matches (detector (blockify bytes) 0)))
      (if (= matches 0) nil matches))))

(defun encryption-oracle (bytes)
  (let ((bytes (concat-bytes (gen-random (+ (random 6) 5))
                             bytes
                             (gen-random (+ (random 6) 5))))
        (secret (gen-random 16)))
    (if (= (random 2) 0)
        (values (encrypt-aes-128-ecb secret bytes) t)
        (values (encrypt-aes-128-cbc secret (gen-random 16) bytes) nil))))

(defun make-oracle (&optional bytes-to-append)
  (let ((secret (gen-random 16)))
    (values
     (lambda (input)
       (encrypt-aes-128-ecb
        secret
        (concat-bytes input (or bytes-to-append #()))))
     secret)))

(defun make-oracle-dictionary (oracle initial-bytes &key (block-size 16))
  (loop with dict = (make-hash-table :test #'equal)
        for i from 0 to 255
        for bytes = (concat-bytes initial-bytes
                                  (make-array 1 :initial-element i))
        for encrypted = (funcall oracle bytes)
        for block = (nth-block 0 encrypted :block-size block-size)
        do (setf (gethash (bytes->hex block) dict) i)
        finally (return dict)))

(defun break-aes-ecb-with-oracle (oracle &key (block-size 16))
  (let ((block-count (length (blockify (funcall oracle #())
                                       :block-size block-size)))
        (bytes (make-array (1- block-size) :element-type '(unsigned-byte 8)
                                           :initial-element 0
                                           :adjustable t
                                           :fill-pointer t)))
    (dotimes (b block-count (subseq bytes (1- block-size)))
      (dotimes (i block-size)
        (let* ((db (* b block-size))
               (dict (make-oracle-dictionary
                      oracle
                      (subseq bytes (+ db i) (+ db i (1- block-size)))
                      :block-size block-size))
               (encryption (funcall
                            oracle
                            (subseq bytes i (1- block-size))))
               (result (gethash (bytes->hex (nth-block b encryption)) dict)))
          (cond
            (result (vector-push-extend result bytes))
            ;; If we failed to find a result in the hash table, and
            ;; the last value was 1, it means we've most likely hit
            ;; PKCS#7 padding. We're done.
            ((= (vector-pop bytes) 1) (return-from break-aes-ecb-with-oracle
                                        (subseq bytes (1- block-size))))
            (t (error "oracle decryption error"))))))))
