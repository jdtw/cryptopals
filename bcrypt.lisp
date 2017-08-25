;;;; bcrypt.lisp

(in-package #:cryptopals)

(define-foreign-library bcrypt
    (:windows "bcrypt"))

(use-foreign-library bcrypt)

;;; NTSTATUS errors

(define-foreign-type ntstatus-type ()
  ()
  (:actual-type :long)
  (:simple-parser ntstatus))

(define-condition ntstatus-error (error)
  ((ntstatus :initarg :ntstatus :reader ntstatus))
  (:report (lambda (e s) (format s "NTSTATUS: ~a" (ntstatus e)))))

(defmethod translate-from-foreign (status (type ntstatus-type))
  (when (< status 0) (error 'ntstatus-error :ntstatus status))
  (values))

;;; Handles

(defclass bcrypt-handle ()
  ((pointer :initform (foreign-alloc :pointer :initial-element (null-pointer))
            :accessor pointer-to-handle))
  (:documentation "Base type for all bcrypt handles. the ~POINTER~ member
represents the C type ~BCRYPT_HANDLE*~"))

(defgeneric close-bcyrpt-handle (handle)
  (:documentation "Closes a bcrypt-handle. ~BCryptDestroyKey~ for a key handle,
~BCryptDestroySecret~ for a secret handle, etc."))

(defgeneric free-bcrypt-handle (handle)
  (:documentation "Frees the foreign memory allocated for the ~pointer~ slot.
The bcrypt-handle object is not safe to use after freeing it."))

(defgeneric get-bcrypt-handle (handle)
  (:documentation "Returns the handle, representing the C type ~BCRYPT_HANDLE~"))

(define-foreign-type bcrypt-handle-type ()
  ()
  (:actual-type :pointer)
  (:simple-parser bcrypt-handle))

(defmethod translate-to-foreign (handle (type bcrypt-handle-type))
  (get-bcrypt-handle handle))

(defmethod get-bcrypt-handle ((handle bcrypt-handle))
  (sb-sys:sap-ref-sap (pointer-to-handle handle) 0))

(defmethod free-bcrypt-handle ((handle bcrypt-handle))
  (foreign-free (pointer-to-handle handle))
  (setf (pointer-to-handle handle) (null-pointer)))

(defclass bcrypt-key-handle (bcrypt-handle) ())
(defmethod close-bcrypt-handle ((handle bcrypt-key-handle))
  (bcrypt-destroy-key handle))

(defclass bcrypt-alg-handle (bcrypt-handle) ())
(defmethod close-bcrypt-handle ((handle bcrypt-alg-handle))
  (bcrypt-close-algorithm-provider handle 0))

(defclass bcrypt-null-handle (bcrypt-handle) ((pointer)))
(defmethod close-bcrypt-handle ((handle bcrypt-null-handle)) (values))
(defmethod free-bcrypt-handle ((handle bcrypt-null-handle)) (values))
(defmethod get-bcrypt-handle ((handle bcrypt-null-handle))
  (declare (ignore handle))
  (null-pointer))
(defun null-handle () (make-instance 'bcrypt-null-handle))

;;; Constants

(define-constant +bcrypt-aes-algorithm+ "AES" :test #'string=)
(define-constant +bcrypt-chaining-mode+ "ChainingMode" :test #'string=)
(define-constant +bcrypt-block-length+ "BlockLength" :test #'string=)
(define-constant +bcrypt-key-length+ "KeyLength" :test #'string=)
(define-constant +bcrypt-initialization-vector+ "IV" :test #'string=)
(define-constant +bcrypt-chain-mode-ecb+ "ChainingModeECB" :test #'string=)
(defconstant +bcrypt-pad-none+ #x00000001)
(defconstant +bcrypt-use-system-preferred-rng+ 2)

;;; Functions

(defcfun ("BCryptOpenAlgorithmProvider" bcrypt-open-algorithm-provider) ntstatus
  (alg (:pointer bcrypt-handle))
  (alg-id (:string :encoding :utf-16le))
  (implementation (:string :encoding :utf-16le))
  (flags :ulong))

(defcfun ("BCryptCloseAlgorithmProvider" bcrypt-close-algorithm-provider) ntstatus
  (alg bcrypt-handle)
  (flags :ulong))

(defcfun ("BCryptGetProperty" bcrypt-get-property) ntstatus
  (obj bcrypt-handle)
  (property (:string :encoding :utf-16le))
  (output :pointer)
  (output-byte-count :ulong)
  (result-byte-count (:pointer :ulong))
  (flags :ulong))

(defcfun ("BCryptSetProperty" bcrypt-set-property) ntstatus
  (obj bcrypt-handle)
  (property (:string :encoding :utf-16le))
  (input :pointer)
  (input-byte-count :ulong)
  (flags :ulong))

(defcfun ("BCryptGenerateSymmetricKey" bcrypt-generate-symmetric-key) ntstatus
  (alg bcrypt-handle)
  (key (:pointer bcrypt-handle))
  (key-object :pointer)
  (key-object-byte-count :ulong)
  (secret :pointer)
  (secret-byte-count :ulong)
  (flags :ulong))

(defcfun ("BCryptDestroyKey" bcrypt-destroy-key) ntstatus
  (key bcrypt-handle))

(defcfun ("BCryptGenRandom" bcrypt-gen-random) ntstatus
  (alg bcrypt-handle)
  (buffer :pointer)
  (buffer-byte-count :ulong)
  (flags :ulong))

(defcfun ("BCryptEncrypt" bcrypt-encrypt) ntstatus
  (key bcrypt-handle)
  (input :pointer)
  (input-byte-count :ulong)
  (padding-info :pointer)
  (iv :pointer)
  (iv-byte-count :ulong)
  (output :pointer)
  (output-byte-count :ulong)
  (result-byte-count (:pointer :ulong))
  (flags :ulong))

(defcfun ("BCryptDecrypt" bcrypt-decrypt) ntstatus
  (key bcrypt-handle)
  (input :pointer)
  (input-byte-count :ulong)
  (padding-info :pointer)
  (iv :pointer)
  (iv-byte-count :ulong)
  (output :pointer)
  (output-byte-count :ulong)
  (result-byte-count (:pointer :ulong))
  (flags :ulong))

(defun set-string-property (handle property string)
  (with-foreign-string (input string :encoding :utf-16le)
    (bcrypt-set-property handle
                         property
                         input
                         (* (1+ (length string)) 2)
                         0)))

(defun get-string-property (handle property)
  (with-foreign-object (byte-count :ulong)
    (bcrypt-get-property handle
                         property
                         (null-pointer)
                         0
                         byte-count
                         0)
    (with-foreign-object (buffer :uchar (mem-ref byte-count :ulong))
      (bcrypt-get-property handle
                           property
                           buffer
                           (mem-ref byte-count :ulong)
                           byte-count
                           0)
      (foreign-string-to-lisp buffer :encoding :utf-16le))))

(defun set-ulong-property (handle property ulong)
  (with-foreign-object (input :ulong)
    (setf (mem-ref input :ulong) ulong)
    (bcrypt-set-property handle
                         property
                         input
                         (foreign-type-size :ulong)
                         0)))

(defun get-ulong-property (handle property)
  (with-foreign-objects ((buffer :ulong) (byte-count :ulong))
    (bcrypt-get-property handle
                         property
                         buffer
                         (foreign-type-size :ulong)
                         byte-count
                         0)
    (assert (= (mem-ref byte-count :ulong) (foreign-type-size :ulong)))
    (mem-ref buffer :ulong)))

(defun set-buffer-property (handle property buffer)
  (with-foreign-array (input buffer `(:array :uint8 ,(length buffer)))
    (bcrypt-set-property handle
                         property
                         input
                         (length buffer)
                         0)))

(defun get-buffer-property (handle property)
  (with-foreign-object (byte-count :ulong)
    (bcrypt-get-property handle
                         property
                         (null-pointer)
                         0
                         byte-count
                         0)
    (let ((result (make-shareable-byte-vector (mem-ref byte-count :ulong))))
      (with-pointer-to-vector-data (output result)
        (bcrypt-get-property handle
                             property
                             output
                             (mem-ref byte-count :ulong)
                             byte-count
                             0))
      result)))

(defun set-property (handle property value)
  (ecase property
    (:chaining-mode (set-string-property handle
                                         +bcrypt-chaining-mode+
                                         (ecase value
                                           (:ecb +bcrypt-chain-mode-ecb+))))
    (:iv (set-buffer-property handle +bcrypt-initialization-vector+ value))
    (:key-length (set-ulong-property handle +bcrypt-key-length+ value))))

(defun get-property (handle property)
  (ecase property
    (:block-length (get-ulong-property handle +bcrypt-block-length+))
    (:key-length (get-ulong-property handle +bcrypt-key-length+))
    (:chaining-mode (get-string-property handle +bcrypt-chaining-mode+))
    (:iv (get-buffer-property handle +bcrypt-initialization-vector+))))

(defclass crypt ()
  ((algorithm :accessor crypt-algorithm
              :initform (make-instance 'bcrypt-alg-handle))
   (key :accessor crypt-key
        :initform (make-instance 'bcrypt-key-handle))
   (buffer :accessor crypt-buffer
           :initform nil)
   (buffer-size :accessor crypt-buffer-size
                :initform 0)
   (byte-count :accessor crypt-byte-count
               :initform (foreign-alloc :ulong :initial-element 0))
   (input-buffer :accessor crypt-input-buffer
                 :initform nil)
   (input-buffer-size :accessor crypt-input-buffer-size
                      :initform 0
                      :type (unsigned-byte 32))))

(defun crypt-open-aes256-ecb (crypt secret)
  (let ((success nil) (secret-len (length secret)))
    (unwind-protect
         (progn
           (bcrypt-open-algorithm-provider
            (pointer-to-handle (crypt-algorithm crypt))
            +bcrypt-aes-algorithm+
            (null-pointer)
            0)
           (set-property (crypt-algorithm crypt) :chaining-mode :ecb)
           (with-foreign-array (input secret `(:array :uint8 ,secret-len))
             (bcrypt-generate-symmetric-key
              (crypt-algorithm crypt)
              (pointer-to-handle (crypt-key crypt))
              (null-pointer)
              0
              input
              secret-len
              0))
           (setf success t))
      (unless success
        (when (not (null-pointer-p (get-bcrypt-handle (crypt-algorithm crypt))))
          (close-bcrypt-handle (crypt-algorithm crypt)))
        (when (not (null-pointer-p (get-bcrypt-handle (crypt-key crypt))))
          (close-bcrypt-handle (crypt-key crypt)))))))

(defun crypt-copy-input-buffer (crypt input input-length)
  (declare (type (unsigned-byte 32) input-length)
           (type (vector (unsigned-byte 8) *) input)
           (optimize speed))
  (when (< (crypt-input-buffer-size crypt) input-length)
    (when (crypt-input-buffer crypt) (foreign-free (crypt-input-buffer crypt)))
    (setf (crypt-input-buffer crypt) (foreign-alloc :uint8 :count input-length)
          (crypt-input-buffer-size crypt) input-length))
  (dotimes (i input-length)
    (setf (sb-sys:sap-ref-8 (crypt-input-buffer crypt) i) (aref input i))))

(defun crypt-free (crypt)
  (when (not (null-pointer-p (get-bcrypt-handle (crypt-algorithm crypt))))
    (close-bcrypt-handle (crypt-algorithm crypt)))
  (free-bcrypt-handle (crypt-algorithm crypt))
  (when (not (null-pointer-p (get-bcrypt-handle (crypt-key crypt))))
    (close-bcrypt-handle (crypt-key crypt)))
  (free-bcrypt-handle (crypt-key crypt))
  (when (crypt-buffer crypt) (foreign-free (crypt-buffer crypt)))
  (foreign-free (crypt-byte-count crypt)))

(defun en/de-crypt (crypt func input)
  (declare (type (vector (unsigned-byte 8) *) input)
           (type function func)
           (optimize speed))
  (let ((input-len (length input)))
    (crypt-copy-input-buffer crypt input input-len)
    (funcall func
             (crypt-key crypt)
             (crypt-input-buffer crypt)
             input-len
             (null-pointer)
             (null-pointer)
             0
             (null-pointer)
             0
             (crypt-byte-count crypt)
             0)
    (let ((size (sb-sys:sap-ref-32 (crypt-byte-count crypt) 0)))
      (when (< (crypt-buffer-size crypt) size)
        (when (crypt-buffer crypt) (foreign-free (crypt-buffer crypt)))
        (setf (crypt-buffer crypt) (foreign-alloc :uint8 :count size)
              (crypt-buffer-size crypt) size)))
    (funcall func
             (crypt-key crypt)
             (crypt-input-buffer crypt)
             input-len
             (null-pointer)
             (null-pointer)
             0
             (crypt-buffer crypt)
             (mem-ref (crypt-byte-count crypt) :ulong)
             (crypt-byte-count crypt)
             0)
    (sb-sys:sap-ref-octets (crypt-buffer crypt)
                           0
                           (sb-sys:sap-ref-32 (crypt-byte-count crypt) 0))))

(declaim (inline decrypt))
(defun decrypt (crypt input)
  (en/de-crypt crypt #'bcrypt-decrypt input))

(declaim (inline encrypt))
(defun encrypt (crypt input)
  (en/de-crypt crypt #'bcrypt-encrypt input))

(defun gen-random (size)
  (let ((random (make-shareable-byte-vector size)))
    (with-pointer-to-vector-data (out random)
      (bcrypt-gen-random (null-handle)
                         out
                         size
                         +bcrypt-use-system-preferred-rng+))
    random))
