Set 1
=====

Convert hex to base64
---------------------

``` commonlisp
(cp:bytes->base64 (cp:hex->bytes "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
```

Fixed XOR
---------

``` commonlisp
(cp:bytes->hex
 (cp:fixed-xor
  (cp:hex->bytes "1c0111001f010100061a024b53535009181c")
  (cp:hex->bytes "686974207468652062756c6c277320657965")))
```

Single-byte XOR cipher
----------------------

``` commonlisp
(car
 (cp:break-single-byte-xor
  (cp:hex->bytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")))
```

To score English text, I used a Chi-squared test. I had to play with the frequencies a fair amount -- just using a-z was not giving great results. The most important thing I did was to add a penalty for uncommon characters. Common punctuation is ignored, but uncommon punctuation is penalized (see the `#\Nul` frequency below).

``` commonlisp
cp:*frequencies*
```

Detect single-character XOR
---------------------------

``` commonlisp
(flet ((top-score (hex)
         (first (cp:break-single-byte-xor (cp:hex->bytes hex)))))
  (let ((scores (with-open-file (in "4.txt")
                  (loop for l = (read-line in nil)
                        while l collect (nconc (list :line l)
                                               (top-score l))))))
    (car (sort scores #'< :key (lambda (x) (getf x :score))))))
```

Implement repeating-key XOR
---------------------------

``` commonlisp
(cp:bytes->hex
 (cp:repeating-xor (cp:ascii->bytes "ICE")
                   (cp:ascii->bytes "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal")))
```

Break repeating-key XOR
-----------------------

Test our hamming distance calculation:

``` commonlisp
(cp:hamming-distance (cp:ascii->bytes "this is a test")
                     (cp:ascii->bytes "wokka wokka!!!"))
```

Now, attempt to find the key size of the XOR'd challenge text. My `FIND-XOR-KEYSIZE` implementation averages `BLOCK-COUNT` blocks. Looking at the output, it converges on a key size of 29 bytes, which is what we'll use to try and break the cipher.

``` commonlisp
(loop with bytes = (cp:read-base64-file "6.txt")
      for i from 1 to 20
      collect (cp:find-xor-keysize bytes :block-count i))
```

And now try to actually break repeating XOR.

``` commonlisp
(let ((bytes (cp:read-base64-file "6.txt")))
  (cp:bytes->ascii
   (cp:break-repeating-xor
    (cp:find-xor-keysize bytes)
    bytes)))
```

AES in ECB mode
---------------

``` commonlisp
(cp:bytes->ascii
 (cp:decrypt-aes-128-ecb
  (cp:ascii->bytes "YELLOW SUBMARINE")
  (cp:read-base64-file "7.txt")))
```

Detect AES in ECB mode
----------------------

To detect collisions, `DETECT-AES-128-ECB` breaks each line up into blocks and compares each block against the others, looking for blocks that are equal. It returns the number of equal blocks if ECB is detected, or `NIL` otherwise.

``` commonlisp
(let ((lines (cp:read-hex-line-file "8.txt")))
  (remove-if #'null (mapcar (lambda (line)
                              (cons (cp:detect-aes-128-ecb line)
                                    (cp:bytes->hex line)))
                            lines)
             :key #'car))
```

Set 2
=====

Implement PKCS\#7 padding
-------------------------

``` commonlisp
(cp:pad-pkcs7 (cp:ascii->bytes "YELLOW SUBMARINE") :block-size 20)
```

Implement CBC mode
------------------

``` commonlisp
(cp:bytes->ascii
 (cp:unpad-pkcs7
  (cp:decrypt-aes-128-cbc
   (cp:ascii->bytes "YELLOW SUBMARINE")
   (make-array 16 :initial-element 0)
   (cp:read-base64-file "10.txt"))))
```

An ECB/CBC detection oracle
---------------------------

Run `ENCRYPTION-ORACLE` ten times, and collect the results. My oracle returns multiple values -- the encrypted output, and `T` for ECB or `NIL` for CBC. Run the ECB detector on the oracle output, and ensure we correctly detected the ECB encryptions.

``` commonlisp
(let* ((input (make-array (* 16 4) :initial-element (char-code #\A)))
       (runs (loop repeat 10
                   collect (multiple-value-list (cp:encryption-oracle input))))
       (results (mapcar (lambda (r) (cons (second r)
                                          (cp:detect-aes-128-ecb (first r))))
                        runs)))
  (values results (every (lambda (r) (or (and (car r) (cdr r))
                                         (not (or (car r) (cdr r)))))
                         results)))
```

Byte-at-a-time ECB decryption (Simple)
--------------------------------------

### Detect the block size

``` commonlisp
(cp:with-oracle (oracle)
  (loop for i from 1 to 64
        for encrypted = (oracle (make-array (* i 2) :initial-element 97))
        for blocks = (cp:blockify encrypted :block-size i)
        until (equalp (first blocks) (second blocks))
        finally (return i)))
```

### Detect that the function is using ECB

``` commonlisp
(cp:with-oracle (oracle)
  (cp:detect-aes-128-ecb
   (oracle (make-array (* 16 2) :initial-element 97))))
```

### Use oracle to break ECB

``` commonlisp
(let ((unknown (cp:base64->bytes "Um9sbGluJyBpbiBteSA1L
jAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvd
wpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNhe
SBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")))
  (cp:with-oracle (oracle unknown)
    (cp:bytes->ascii (cp:break-aes-ecb-with-oracle #'oracle))))
```
