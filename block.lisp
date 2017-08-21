;;;; block.lisp

(in-package #:cryptopals)

(defun pad-pkcs7 (bytes &key (block-size 16))
  (let ((delta (- block-size (length bytes))))
    (when (< delta 0) (error "buffer is longer than the block length"))
    (with-output-to-sequence (padded :element-type '(unsigned-byte 8)
                                     :initial-buffer-size block-size)
      (write-sequence bytes padded)
      (write-sequence (make-array delta :element-type '(unsigned-byte 8)
                                        :initial-element delta)
                      padded))))

(defun unpad-pkcs7 (bytes)
  (let ((len (length bytes)))
    (if (> len 0)
        (let ((delta (aref bytes (- len 1))))
          (if (and (<= delta len)
                   (every (lambda (b) (= b delta))
                          (subseq bytes (- len delta) len)))
              (subseq bytes 0 (- len delta))
              bytes))
        bytes)))

(defun blocker (bytes &key (block-size 16) pad)
  (let ((len (length bytes)) (pos 0))
    (lambda ()
      (cond ((= pos len) nil)
            ((< (- len pos) block-size)
             (let ((short-block (subseq bytes pos (setf pos len))))
               (if pad
                   (pad-pkcs7 short-block :block-size block-size)
                   short-block)))
            (t (subseq bytes pos (setf pos (+ pos block-size))))))))

(defun blockify (bytes &key (block-size 16) pad)
  (loop with blocker = (blocker bytes :block-size block-size :pad pad)
        for block = (funcall blocker)
        while block collect block))

(defun nth-block (n bytes &key (block-size 16))
  (subseq bytes (* n block-size) (* (1+ n) block-size)))
