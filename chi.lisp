;;;; chi.lisp

(in-package #:cryptopals)

(defconstant +frequencies+
  '((#\e . 0.12702d0) (#\t . 0.09056d0) (#\a . 0.08167d0) (#\o . 0.07507d0)
    (#\i . 0.06966d0) (#\n . 0.06749d0) (#\s . 0.06327d0) (#\h . 0.06094d0)
    (#\r . 0.05987d0) (#\d . 0.04253d0) (#\l . 0.04025d0) (#\c . 0.02782d0)
    (#\u . 0.02758d0) (#\m . 0.02406d0) (#\w . 0.0236d0) (#\f . 0.02228d0)
    (#\g . 0.02015d0) (#\y . 0.01974d0) (#\p . 0.01929d0) (#\b . 0.01492d0)
    (#\v . 0.00978d0) (#\k . 0.00772d0) (#\j . 0.00153d0) (#\x . 0.0015d0)
    (#\q . 9.5d-4) (#\z . 7.4d-4)))

(defun count-letters (string)
  (loop with table = (make-hash-table)
        for c across string
        when (alpha-char-p c)
          do (incf (gethash (char-downcase c) table 0))
        finally (return table)))

(defun chi-squared (candidate)
  (loop with len = (length candidate)
        with counts = (count-letters (bytes->utf8 candidate))
        for e in +frequencies+
        summing (let ((ec (* (cdr e) len))
                      (c (gethash (car e) counts 0)))
                  (format t "~a: ec: ~a c: ~a -> ~a~%"  (car e) ec c
                          (/ (expt (- c ec) 2) ec))
                  (/ (expt (- c ec) 2) ec))))
