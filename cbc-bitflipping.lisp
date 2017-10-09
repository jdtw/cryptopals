;;;; cbc-bitflipping.lisp

(in-package #:cryptopals)

(defun escape-illegal-chars (str)
  (str:replace-all "=" "%3D" (str:replace-all ";" "%3B" str)))

(defun unescape-illegal-chars (str)
  (str:replace-all "%3D" "=" (str:replace-all "%3B" ";" str)))

(defun user-data (str)
  (str:concat
   "comment1=cooking%20MCs;userdata="
   (escape-illegal-chars str)
   ";comment2=%20like%20a%20pound%20of%20bacon"))

(defun encrypt-user-data (secret iv str)
  (let* ((data (user-data str))
         (bytes (ascii->bytes data)))
    (encrypt-aes-128-cbc secret iv bytes)))

(defun parse-data (data)
  (mapcar (lambda (pair) (apply #'cons pair))
          (mapcar (lambda (s)
                    (let ((split (split "=" s)))
                      (cond
                        ((= (length split) 1) (append split (list "")))
                        ((= (length split) 2) split)
                        (t (error "unexpected split length")))))
                  (split ";" data))))

(defun data-lookup (thing alist)
  (cdr (assoc thing alist :test #'string=)))

(defun decrypt-and-parse-data (secret iv encrypted)
  (let* ((bytes (decrypt-aes-128-cbc secret iv encrypted))
         (string (bytes->ascii (unpad-pkcs7 bytes) :ignore-errors t)))
    (parse-data string)))

(defun cbc-flip (buffer index plaintext desired)
  (setf (aref buffer index)
        (logxor (aref buffer index)
                (char-code plaintext)
                (char-code desired))))
