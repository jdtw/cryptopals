;;;; cookie.lisp

(in-package #:cryptopals)

(defun parse-cookie (cookie)
  (mapcar (lambda (pair) (apply #'cons pair))
          (mapcar (lambda (s)
                    (let ((split (split "=" s)))
                      (cond
                        ((= (length split) 1) (append split (list "")))
                        ((= (length split) 2) split)
                        (t (error "unexpected split length")))))
                  (split "&" cookie))))

(defun make-cookie (alist)
  (join "&" (mapcar (lambda (pair)
                      (join "=" (list (car pair) (cdr pair))))
                    alist)))

(defun cookie-lookup (thing alist)
  (cdr (assoc thing alist :test #'string=)))

(defun profile-role (alist)
  (cookie-lookup "role" alist))

(defun make-profiler (role &optional (seed 0))
  (let ((uid seed))
    (lambda (email)
      (when (or (find #\& email) (find #\= email))
        (error "Invalid email"))
      (list (cons "email" email)
            (cons "uid" (1- (incf uid)))
            (cons "role" role)))))

(defun profile-for (profiler email)
  (make-cookie (funcall profiler email)))

(defun make-encrypted-user-profiler (secret &optional (seed 0))
  (let ((profiler (make-profiler "user" seed)))
    (lambda (email)
      (let* ((cookie (profile-for profiler email))
             (bytes (string-to-octets cookie :encoding :ascii)))
        (encrypt-aes-128-ecb secret bytes)))))

(defun decrypt-and-parse-profile (secret encrypted)
  (let* ((bytes (decrypt-aes-128-ecb secret encrypted))
         (string (octets-to-string (unpad-pkcs7 bytes) :encoding :ascii)))
    (parse-cookie string)))
