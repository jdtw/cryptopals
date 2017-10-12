;;;; mt19937.lisp

;;;; Solution based on pseudocode from
;;;; https://en.wikipedia.org/wiki/Mersenne_Twister

(in-package #:cryptopals)

;; The coefficients for MT19937
(defconstant +w+ 32)
(defconstant +n+ 624)
(defconstant +m+ 397)
(defconstant +a+ #x9908b0df)
(defconstant +u+ 11)
(defconstant +d+ #xffffffff)
(defconstant +s+ 7)
(defconstant +b+ #x9d2c5680)
(defconstant +t+ 15)
(defconstant +c+ #xefc60000)
(defconstant +l+ 18)
(defconstant +f+ 1812433253)
(defconstant +lower-mask+ #x7fffffff)
(defconstant +upper-mask+ #x80000000)

(defclass mt19937 ()
  ((state :initform (make-array +n+ :element-type '(unsigned-byte 32))
          :accessor mt-state)
   (index :initarg :seed :initform (1+ +n+) :accessor mt-index)))

(defun seed-mt (mt seed)
  "Initialize the generator from a seed"
  (with-slots (state index) mt
    (setf index +n+
          (aref state 0) seed)
    (loop
      for i from 1 to (1- +n+)
      for prev = (aref state (1- i)) do
        (setf (aref state i)
              (logand #xffffffff
                      (+ (* +f+ (logxor prev (ash prev (- (- +w+ 2))))) i)))))
  mt)

(defun mt19937 (seed)
  (let ((mt (make-instance 'mt19937)))
    (seed-mt mt seed)))

(defun extract-number (mt)
  "Extract a tempered value based on INDEX calling TWIST every n numbers"
  (with-slots (state index) mt
    (assert (<= index +n+) nil "Generator was never seeded")
    (when (= index +n+) (twist mt))
    (let ((y (aref state index)))
      (xorf y (logand (ash y (- +u+)) +d+))
      (xorf y (logand (ash y +s+) +b+))
      (xorf y (logand (ash y +t+) +c+))
      (xorf y (ash y (- +l+)))
      (incf index)
      (logand #xffffffff y))))

(defun twist (mt)
  "Generate the next n values from the series x_i"
  (with-slots (state index) mt
    (loop for i below +n+ do
      (let* ((x (+ (logand (aref state i) +upper-mask+)
                   (logand (aref state (mod (1+ i) +n+)) +lower-mask+)))
             (xa (ash x -1)))
        (unless (= (mod x 2) 0) (xorf xa +a+))
        (setf (aref state i) (logxor (aref state (mod (+ i +m+) +n+)) xa)
              index 0)))))
