;;;; xor.lisp

(in-package #:cryptopals)

(defun map-bytes (func sequence &rest more-sequences)
  (apply #'map '(vector (unsigned-byte 8) *) func sequence more-sequences))

(defun blocker (size bytes)
  (let ((len (length bytes)) (pos 0))
    (lambda ()
      (cond ((= pos len) nil)
            ((< (- len pos) size)
             (subseq bytes pos (setf pos len)))
            (t (subseq bytes pos (setf pos (+ pos size))))))))

(defun fixed-xor (b1 b2)
  (let ((len (length b1)))
    (unless (= len (length b2)) (error "b2 is not of length ~a" len))
    (map-bytes #'logxor b1 b2)))

(defun break-single-byte-xor (bytes &key (take 5))
  (mapcar
   (lambda (x)
     (list :score (first x)
           :key (second x)
           :string (bytes->ascii (third x) :ignore-errors t)))
   (subseq
    (sort
     (loop for k from 0 to 255
           for candidate = (map-bytes (lambda (b) (logxor b k)) bytes)
           collect (list (chi-squared candidate) k candidate))
     #'< :key #'first)
    0 take)))

(defun repeating-xor (key bytes)
  (with-output-to-sequence (stream :element-type '(unsigned-byte 8))
    (loop with key-len = (length key)
          with blocker = (blocker key-len bytes)
          for block = (funcall blocker)
          while block do
            (write-sequence
             (if (< (length block) key-len)
                 (fixed-xor (subseq key 0 (length block)) block)
                 (fixed-xor key block))
             stream))))

(defun hamming-distance (b1 b2)
  (reduce #'+ (map-bytes  #'logcount (fixed-xor b1 b2))))

(defun find-xor-keysize (bytes &optional (block-count 10))
  (cdar (sort (loop for ks from 2 to 40
                    for blocker = (blocker ks bytes)
                    for blocks = (loop repeat (1+ block-count)
                                       collect (funcall blocker))
                    collect
                    (cons (/ (reduce #'+ (mapcar (lambda (b)
                                                   (/ (hamming-distance
                                                       (car blocks) b) ks))
                                                 (cdr blocks)))
                             block-count)
                          ks))
              #'< :key #'car)))
