;;;; strings.lisp

(in-package #:cryptopals)

(defconstant +ascii-hex+ '((#\0 . #x0) (#\1 . #x1) (#\2 . #x2) (#\3 . #x3)
                           (#\4 . #x4) (#\5 . #x5) (#\6 . #x6) (#\7 . #x7)
                           (#\8 . #x8) (#\9 . #x9) (#\a . #xa) (#\b . #xb)
                           (#\c . #xc) (#\d . #xd) (#\e . #xe) (#\f . #xf)))
(defun char->num (c)
  (let ((n (assoc c +ascii-hex+ :test #'char-equal)))
    (when (null n) (error "~a is not a hex character" c))
    (cdr n)))

(defun ascii-hex->bytes (hex)
  (let ((char-count (length hex)))
    (when (oddp char-count) (error "Odd-length hex string"))
    (let* ((byte-count (/ char-count 2))
           (bytes (make-array byte-count :element-type '(unsigned-byte 8))))
      (dotimes (i byte-count bytes)
        (setf (aref bytes i)
              (logior (ash (char->num (char hex (* i 2))) 4)
                      (char->num (char hex (1+ (* i 2))))))))))
