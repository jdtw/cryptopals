;;;; strings.lisp

(in-package #:cryptopals)

;;; Hex encoding

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

(defun bytes->ascii-hex (bytes)
  (with-output-to-string (s)
    (loop for b across bytes do (format s "~x" b))))


;;; Base64 encoding

(defconstant +base64-encoding+ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
(defun encode-3-bytes (stream bytes start end)
  (multiple-value-bind (b1 b2 b3 pad3 pad4)
      (let ((rel-length (- end start)))
        (cond
          ((<= rel-length 0) (return-from encode-3-bytes nil))
          ((= rel-length 1) (values (aref bytes start) 0 0 t t))
          ((= rel-length 2) (values (aref bytes start)
                                    (aref bytes (+ start 1))
                                    0 nil t))
          (t (values (aref bytes start)
                     (aref bytes (+ start 1))
                     (aref bytes (+ start 2)) nil nil))))
    (let ((c1 (ldb (byte 6 2) b1))
          (c2 (logior (ash (ldb (byte 2 0) b1) 4) (ldb (byte 4 4) b2)))
          (c3 (if pad3 64 (logior (ash (ldb (byte 4 0) b2) 2)
                                  (ldb (byte 2 6) b3))))
          (c4 (if pad4 64 (ldb (byte 6 0) b3))))
      (dolist (c (list c1 c2 c3 c4) t)
        (princ (char +base64-encoding+ c) stream)))))

(defun base64-encode (bytes)
  (with-output-to-string (s)
    (loop with len = (length bytes)
          for pos = 0 then (+ pos 3)
          until (null (encode-3-bytes s bytes pos len)))))
