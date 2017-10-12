;;;; mt19937.lisp

(in-package #:cryptopals)

;; The coefficients for MT19937 are:
;; (w, n, m, r) = (32, 624, 397, 31)
(defconstant +w+ 32)
(defconstant +n+ 624)
(defconstant +m+ 397)
(defconstant +r+ 31)
;; a = 9908B0DF16
(defconstant +a+ #x9908b0df)
;; (u, d) = (11, FFFFFFFF16)
(defconstant +u+ 11)
(defconstant +d+ #xffffffff)
;; (s, b) = (7, 9D2C568016)
(defconstant +s+ 7)
(defconstant +b+ #x9d2c5680)
;; (t, c) = (15, EFC6000016)
(defconstant +t+ 15)
(defconstant +c+ #xefc60000)
;; l = 18
(defconstant +l+ 18)
(defconstant +f+ 1812433253)

;; // Create a length n array to store the state of the generator
;; int[0..n-1] MT
;; int index := n+1
(defclass mt19937 ()
  ((state :initform (make-array +n+ :element-type '(unsigned-byte 32))
          :accessor mt-state)
   (index :initarg :seed :initform (1+ +n+) :accessor mt-index)))
;; const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
(defconstant +lower-mask+ #x7fffffff)
;; const int upper_mask = lowest w bits of (not lower_mask)
(defconstant +upper-mask+ #x80000000)

;; // Initialize the generator from a seed
;; function seed_mt(int seed) {
;;     index := n
;;     MT[0] := seed
;;     for i from 1 to (n - 1) { // loop over each element
;;         MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
;;     }
;; }
(defun seed-mt (mt seed)
  "Initialize the generator from a seed"
  (with-slots (state index) mt
    (setf index +n+)
    (setf (aref state 0) seed)
    (loop for i from 1 to (1- +n+)
          for prev = (aref state (1- i)) do
            (setf (aref state i)
                  (logand #xffffffff
                          (+ i (* +f+ (logxor prev (ash prev -30)))))))))
;; // Extract a tempered value based on MT[index]
;; // calling twist() every n numbers
;; function extract_number() {
;;     if index >= n {
;;         if index > n {
;;           error "Generator was never seeded"
;;           // Alternatively, seed with constant value; 5489 is used in reference C code[49]
;;         }
;;         twist()
;;     }
;;
;;     int y := MT[index]
;;     y := y xor ((y >> u) and d)
;;     y := y xor ((y << s) and b)
;;     y := y xor ((y << t) and c)
;;     y := y xor (y >> l)
;;
;;     index := index + 1
;;     return lowest w bits of (y)
;; }
(defun extract-number (mt)
  "Extract a tempered value based on MT[index] calling twist() every n numbers"
  (with-slots (state index) mt
    (assert (<= index +n+) nil "Generator was never seeded")
    (when (= index +n+) (twist mt))

    (let ((y (aref state index)))
      (setf y (logxor y (logand (ash y (- 0 +u+)) +d+))
            y (logxor y (logand (ash y +s+) +b+))
            y (logxor y (logand (ash y +t+) +c+))
            y (logxor y (ash y (- 0 +l+)))
            index (1+ index))
      (logand #xffffffff y))))

;; // Generate the next n values from the series x_i
;; function twist() {
;;     for i from 0 to (n-1) {
;;         int x := (MT[i] and upper_mask)
;;                   + (MT[(i+1) mod n] and lower_mask)
;;         int xA := x >> 1
;;         if (x mod 2) != 0 { // lowest bit of x is 1
;;             xA := xA xor a
;;         }
;;         MT[i] := MT[(i + m) mod n] xor xA
;;     }
;;     index := 0
;; }
(defun twist (mt)
  (with-slots (state index) mt
    (loop for i below +n+ do
      (let* ((x (+ (logand (aref state i) +upper-mask+)
                   (logand (aref state (mod (1+ i) +n+)) +lower-mask+)))
             (xa (ash x -1)))
        (unless (= (mod x 2) 0) (setf xa (logxor xa +a+)))
        (setf (aref state i) (logxor (aref state (mod (+ i +m+) +n+))
                                     xa)
              index 0)))))
