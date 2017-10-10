;;;; padding-oracle.lisp

(in-package #:cryptopals)

(defparameter *plaintexts*
  '("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"))

(defclass cbc-padding-oracle ()
  ((secret :initform (gen-random 16) :accessor oracle-secret)))

(defun oracle-encrypt (oracle)
  "The first function should select at random one of the 10 strings, generate a
random AES key (which it should save for all future encryptions), pad the string
out to the 16-byte AES block size and CBC-encrypt it under that key, providing
the caller the ciphertext and IV."
  (let ((iv (gen-random 16))
        (bytes (base64->bytes (nth (random 10) *plaintexts*))))
    (values iv (encrypt-aes-128-cbc (oracle-secret oracle)
                                    (oracle-iv oracle)
                                    bytes))))

(defun oracle-decrypt (oracle iv ciphertext)
  "The second function should consume the ciphertext produced by the first
function, decrypt it, check its padding, and return true or false depending on
whether the padding is valid."
  (let ((bytes (decrypt-aes-128-cbc (oracle-secret oracle) iv ciphertext)))
    (bytes->ascii (unpad-pkcs7 bytes) :ignore-errors t)))
