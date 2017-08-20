;;;; chi.lisp

(in-package #:cryptopals)

;; Letter frequencies (including space). NUL is used as a penalty
;; for strange punctuation.
(defconstant +frequencies+
  '((#\a . 0.0651738d0) (#\b . 0.0124248d0) (#\c . 0.0217339d0)
    (#\d . 0.0349835d0) (#\e . 0.1041442d0) (#\f . 0.0197881d0)
    (#\g . 0.0158610d0) (#\h . 0.0492888d0) (#\i . 0.0558094d0)
    (#\j . 0.0009033d0) (#\k . 0.0050529d0) (#\l . 0.0331490d0)
    (#\m . 0.0202124d0) (#\n . 0.0564513d0) (#\o . 0.0596302d0)
    (#\p . 0.0137645d0) (#\q . 0.0008606d0) (#\r . 0.0497563d0)
    (#\s . 0.0515760d0) (#\t . 0.0729357d0) (#\u . 0.0225134d0)
    (#\v . 0.0082903d0) (#\w . 0.0171272d0) (#\x . 0.0013692d0)
    (#\y . 0.0145984d0) (#\z . 0.0007836d0) (#\Space . 0.1918182d0)
    (#\Nul . 0.001d0)))

(define-condition non-graphic-char (error) ())

(defun count-letters (string)
  (loop with table = (make-hash-table)
        with count = 0
        for c across string do
          (let ((inc
                  (cond
                    ((alpha-char-p c) (char-downcase c))
                    ((member c '(#\Space #\Newline #\Tab)) #\Space)
                    ((not (graphic-char-p c)) (error 'non-graphic-char))
                    ((not (member c '(#\' #\" #\, #\. #\- #\? #\!))) #\Nul))))
            (when inc
              (incf (gethash inc table 0))
              (incf count)))
        finally (return (values table count))))

(defun chi-squared (candidate)
  (handler-case
      (multiple-value-bind (table len)
          (count-letters (bytes->ascii candidate))
        (if (zerop len)
            most-positive-double-float
            (loop for e in +frequencies+
                  summing (let ((ec (* (cdr e) len))
                                (c (gethash (car e) table 0)))
                            (/ (expt (- c ec) 2) ec)))))
    (character-decoding-error () most-positive-double-float)
    (non-graphic-char () most-positive-double-float)))
