;;;; strings.lisp

(in-package #:cryptopals)

;;; ASCII encoding
;;; Note: Cheat and use babel here. I can't bring myself to hack this together
;;;       myself with char-code and code-char.

(defun ascii->bytes (string)
  (string-to-octets string :encoding :ascii))

(defun bytes->ascii (bytes &key ignore-errors)
  (octets-to-string bytes :encoding :ascii :errorp (not ignore-errors)))

;;; Hex encoding

(define-constant +ascii-hex+
    '((#\0 . #x0) (#\1 . #x1) (#\2 . #x2) (#\3 . #x3)
      (#\4 . #x4) (#\5 . #x5) (#\6 . #x6) (#\7 . #x7)
      (#\8 . #x8) (#\9 . #x9) (#\a . #xa) (#\b . #xb)
      (#\c . #xc) (#\d . #xd) (#\e . #xe) (#\f . #xf))
  :test #'equal)

(defun char->num (c)
  (let ((n (assoc c +ascii-hex+ :test #'char-equal)))
    (when (null n) (error "~a is not a hex character" c))
    (cdr n)))

(defun hex->bytes (hex)
  (let ((char-count (length hex)))
    (when (oddp char-count) (error "Odd-length hex string"))
    (let* ((byte-count (/ char-count 2))
           (bytes (make-array byte-count :element-type '(unsigned-byte 8))))
      (dotimes (i byte-count bytes)
        (setf (aref bytes i)
              (logior (ash (char->num (char hex (* i 2))) 4)
                      (char->num (char hex (1+ (* i 2))))))))))

(defun bytes->hex(bytes)
  (with-output-to-string (s)
    (loop for b across bytes do (format s "~2,'0x" b))))

;;; Base64 encoding

(define-constant +base64-encoding+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  :test #'string=)
(defun encode-3-bytes (stream bytes start end)
  (multiple-value-bind (b1 b2 b3)
      (let ((rel-length (- end start)))
        (cond
          ((<= rel-length 0) (error "start >= end"))
          ((= rel-length 1) (values (aref bytes start) nil nil))
          ((= rel-length 2) (values (aref bytes start) (aref bytes (+ start 1)) nil))
          (t (values (aref bytes start)
                     (aref bytes (+ start 1))
                     (aref bytes (+ start 2))))))
    (let ((c1 (ldb (byte 6 2) b1))
          (c2 (logior (ash (ldb (byte 2 0) b1) 4)
                      (ldb (byte 4 4) (or b2 0))))
          (c3 (if b2 (logior (ash (ldb (byte 4 0) b2) 2)
                             (ldb (byte 2 6) (or b3 0)))
                  64))
          (c4 (if b3 (ldb (byte 6 0) b3) 64)))
      (dolist (c (list c1 c2 c3 c4) t)
        (princ (char +base64-encoding+ c) stream)))))

(defun bytes->base64 (bytes)
  (with-output-to-string (s)
    (loop with len = (length bytes)
          for pos = 0 then (+ pos 3)
          until (>= pos len)
          do (encode-3-bytes s bytes pos len))))

(defparameter *base64-lookup* (make-hash-table))
(dotimes (i 64 (values))
  (setf (gethash (char +base64-encoding+ i) *base64-lookup*) i))
(defun base64-lookup (string pos)
  (gethash (char string pos) *base64-lookup*))

(defun decode-4-chars (stream string start)
  (flet ((write-or (a b) (write-byte (logior a b) stream)))
    (let ((cs (mapcar (lambda (d) (base64-lookup string (+ start d))) '(0 1 2 3))))
      (write-or (ash (first cs) 2) (ldb (byte 2 4) (second cs)))
      (when (third cs)
        (write-or (ash (ldb (byte 4 0) (second cs)) 4)
                  (ldb (byte 4 2) (third cs))))
      (when (fourth cs)
        (write-or (ash (ldb (byte 2 0) (third cs)) 6)
                  (ldb (byte 6 0) (fourth cs)))))))

(defun base64->bytes (string)
  (with-output-to-sequence (s)
    (loop with len = (length string)
          for pos = 0 then (+ pos 4)
          until (>= pos len)
          do (decode-4-chars s string pos))))

;;; Reading files

(defun read-base64-file (pathspec)
  (with-output-to-sequence (stream :element-type '(unsigned-byte 8))
    (with-open-file (in pathspec)
      (loop for line = (read-line in nil)
            while line do (write-sequence (base64->bytes line) stream)))))

(defun read-hex-line-file (pathspec)
  (with-open-file (in pathspec)
    (loop for line = (read-line in nil)
          while line collect (hex->bytes line))))
