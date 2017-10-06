;;;; block.lisp

(in-package #:cryptopals)

(defun pad-pkcs7 (bytes &key (block-size 16))
  (let ((pad (- block-size (mod (length bytes) block-size))))
    (concat-bytes bytes (make-array pad :element-type '(unsigned-byte 8)
                                        :initial-element pad))))

(define-condition invalid-padding-error (error) ())

(defun unpad-pkcs7 (bytes &key (block-size 16))
  (let ((len (length bytes)))
    (unless (= (mod len block-size) 0)
      (error 'invalid-padding-error))
    (if (> len 0)
        (let ((pad (aref bytes (- len 1))))
          (if (and (<= pad block-size)
                   (every (lambda (b) (= b pad))
                          (subseq bytes (- len pad) len)))
              (subseq bytes 0 (- len pad))
              (error 'invalid-padding-error)))
        bytes)))

(defun blocker (bytes &key (block-size 16) pad)
  (let* ((bytes (if pad (pad-pkcs7 bytes) bytes))
         (len (length bytes))
         (pos 0))
    (lambda ()
      (cond
        ((= pos len) nil)
        ((< (- len pos) block-size) (subseq bytes pos (setf pos len)))
        (t (subseq bytes pos (setf pos (+ pos block-size))))))))

(defun blockify (bytes &key (block-size 16) pad)
  (loop with blocker = (blocker bytes :block-size block-size :pad pad)
        for block = (funcall blocker)
        while block collect block))

(defun nth-block (n bytes &key (block-size 16))
  (subseq bytes (* n block-size) (* (1+ n) block-size)))

(defun (setf nth-block) (new-block block-index bytes)
  (let* ((block-size (length new-block))
         (offset (* block-size block-index)))
    (dotimes (i block-size (subseq bytes offset (+ offset block-size)))
      (setf (aref bytes (+ offset i)) (aref new-block i)))))
