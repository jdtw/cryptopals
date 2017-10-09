Table of Contents
-----------------

-   [1. Set 1](#orge6dfbaa)
    -   [1.1. Convert hex to base64](#org77784a9)
    -   [1.2. Fixed XOR](#org04a5a9f)
    -   [1.3. Single-byte XOR cipher](#orgd99da0c)
    -   [1.4. Detect single-character XOR](#org3297eeb)
    -   [1.5. Implement repeating-key XOR](#orgff0c82f)
    -   [1.6. Break repeating-key XOR](#org7a6c18a)
    -   [1.7. AES in ECB mode](#org4788a75)
    -   [1.8. Detect AES in ECB mode](#orge4652ee)
-   [2. Set 2](#orgc619bbd)
    -   [2.1. Implement PKCS\#7 padding](#org6e3007a)
    -   [2.2. Implement CBC mode](#orge136f59)
    -   [2.3. An ECB/CBC detection oracle](#org431d7ec)
    -   [2.4. Byte-at-a-time ECB decryption (Simple)](#org1bac13e)
        -   [2.4.1. Detect the block size](#org09e8149)
        -   [2.4.2. Detect that the function is using ECB](#org0691999)
        -   [2.4.3. Use oracle to break ECB](#orgfb5e8fa)
    -   [2.5. ECB cut-and-paste](#org172a72c)
        -   [2.5.1. Write a k=v parsing routine](#orgdf41f19)
        -   [2.5.2. Write a function that encodes a user profile](#orgbdcaa7d)
        -   [2.5.3. Carry out a cut-paste attack](#org1e2aab1)
    -   [2.6. Byte-at-a-time ECB decryption (Harder)](#orgfc75e3c)
    -   [2.7. PKCS\#7 padding validation](#orgc8381b7)
    -   [2.8. CBC bitflipping attacks](#org1abe578)

<span class="section-number-2">1</span> Set 1
---------------------------------------------

### <span class="section-number-3">1.1</span> Convert hex to base64

``` src
(cp:bytes->base64 (cp:hex->bytes "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
```

``` example
"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
```

### <span class="section-number-3">1.2</span> Fixed XOR

``` src
(cp:bytes->hex
 (cp:fixed-xor
  (cp:hex->bytes "1c0111001f010100061a024b53535009181c")
  (cp:hex->bytes "686974207468652062756c6c277320657965")))
```

``` example
"746865206B696420646F6E277420706C6179"
```

### <span class="section-number-3">1.3</span> Single-byte XOR cipher

``` src
(car
 (cp:break-single-byte-xor
  (cp:hex->bytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")))
```

``` example
(:SCORE 44.4112472277668d0 :KEY 88 :STRING "Cooking MC's like a pound of bacon")
```

To score English text, I used a Chi-squared test. I had to play with the frequencies a fair amount – just using a-z was not giving great results. The most important thing I did was to add a penalty for uncommon characters. Common punctuation is ignored, but uncommon punctuation is penalized (see the `#\Nul` frequency below).

``` src
cp:*frequencies*
```

``` example
((#\a . 0.0651738d0) (#\b . 0.0124248d0) (#\c . 0.0217339d0)
 (#\d . 0.0349835d0) (#\e . 0.1041442d0) (#\f . 0.0197881d0) (#\g . 0.015861d0)
 (#\h . 0.0492888d0) (#\i . 0.0558094d0) (#\j . 9.033d-4) (#\k . 0.0050529d0)
 (#\l . 0.033149d0) (#\m . 0.0202124d0) (#\n . 0.0564513d0) (#\o . 0.0596302d0)
 (#\p . 0.0137645d0) (#\q . 8.606d-4) (#\r . 0.0497563d0) (#\s . 0.051576d0)
 (#\t . 0.0729357d0) (#\u . 0.0225134d0) (#\v . 0.0082903d0)
 (#\w . 0.0171272d0) (#\x . 0.0013692d0) (#\y . 0.0145984d0) (#\z . 7.836d-4)
 (#\  . 0.1918182d0) (#\Nul . 0.001d0))
```

### <span class="section-number-3">1.4</span> Detect single-character XOR

``` src
(flet ((top-score (hex)
         (first (cp:break-single-byte-xor (cp:hex->bytes hex)))))
  (let ((scores (with-open-file (in "4.txt")
                  (loop for l = (read-line in nil)
                        while l collect (nconc (list :line l)
                                               (top-score l))))))
    (car (sort scores #'< :key (lambda (x) (getf x :score))))))
```

``` example
(:LINE "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f" :SCORE
 51.34496174418811d0 :KEY 53 :STRING "Now that the party is jumping
")
```

### <span class="section-number-3">1.5</span> Implement repeating-key XOR

``` src
(cp:bytes->hex
 (cp:repeating-xor (cp:ascii->bytes "ICE")
                   (cp:ascii->bytes "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal")))
```

``` example
"0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F"
```

### <span class="section-number-3">1.6</span> Break repeating-key XOR

Test our hamming distance calculation:

``` src
(cp:hamming-distance (cp:ascii->bytes "this is a test")
                     (cp:ascii->bytes "wokka wokka!!!"))
```

``` example
37
```

Now, attempt to find the key size of the XOR'd challenge text. My `FIND-XOR-KEYSIZE` implementation averages `BLOCK-COUNT` blocks. Looking at the output, it converges on a key size of 29 bytes, which is what we'll use to try and break the cipher.

``` src
(loop with bytes = (cp:read-base64-file "6.txt")
      for i from 1 to 20
      collect (cp:find-xor-keysize bytes :block-count i))
```

``` example
(5 5 5 5 5 5 5 29 29 29 29 29 29 29 29 29 29 29 29 29)
```

And now try to actually break repeating XOR.

``` src
(let ((bytes (cp:read-base64-file "6.txt")))
  (cp:bytes->ascii
   (cp:break-repeating-xor
    (cp:find-xor-keysize bytes)
    bytes)))
```

``` example
"I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music
"
```

### <span class="section-number-3">1.7</span> AES in ECB mode

``` src
(cp:bytes->ascii
 (cp:decrypt-aes-128-ecb
  (cp:ascii->bytes "YELLOW SUBMARINE")
  (cp:read-base64-file "7.txt")))
```

``` example
"I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music
"
```

### <span class="section-number-3">1.8</span> Detect AES in ECB mode

To detect collisions, `DETECT-AES-128-ECB` breaks each line up into blocks and compares each block against the others, looking for blocks that are equal. It returns the number of equal blocks if ECB is detected, or `NIL` otherwise.

``` src
(let ((lines (cp:read-hex-line-file "8.txt")))
  (remove-if #'null (mapcar (lambda (line)
                              (cons (cp:detect-aes-128-ecb line)
                                    (cp:bytes->hex line)))
                            lines)
             :key #'car))
```

``` example
((6
  . "D880619740A8A19B7840A8A31C810A3D08649AF70DC06F4FD5D2D69C744CD283E2DD052F6B641DBF9D11B0348542BB5708649AF70DC06F4FD5D2D69C744CD2839475C9DFDBC1D46597949D9C7E82BF5A08649AF70DC06F4FD5D2D69C744CD28397A93EAB8D6AECD566489154789A6B0308649AF70DC06F4FD5D2D69C744CD283D403180C98C8F6DB1F2A3F9C4040DEB0AB51B29933F2C123C58386B06FBA186A"))
```

<span class="section-number-2">2</span> Set 2
---------------------------------------------

### <span class="section-number-3">2.1</span> Implement PKCS\#7 padding

``` src
(cp:pad-pkcs7 (cp:ascii->bytes "YELLOW SUBMARINE") :block-size 20)
```

``` example
#(89 69 76 76 79 87 32 83 85 66 77 65 82 73 78 69 4 4 4 4)
```

### <span class="section-number-3">2.2</span> Implement CBC mode

``` src
(cp:bytes->ascii
 (cp:unpad-pkcs7
  (cp:decrypt-aes-128-cbc
   (cp:ascii->bytes "YELLOW SUBMARINE")
   (make-array 16 :initial-element 0)
   (cp:read-base64-file "10.txt"))))
```

``` example
"I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music
"
```

### <span class="section-number-3">2.3</span> An ECB/CBC detection oracle

Run `ENCRYPTION-ORACLE` ten times, and collect the results. My oracle returns multiple values – the encrypted output, and `T` for ECB or `NIL` for CBC. Run the ECB detector on the oracle output, and ensure we correctly detected the ECB encryptions.

``` src
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

``` example
((T . 3) (T . 3) (NIL) (NIL) (NIL) (NIL) (T . 3) (T . 3) (NIL) (T . 3))
T
```

### <span class="section-number-3">2.4</span> Byte-at-a-time ECB decryption (Simple)

#### <span class="section-number-4">2.4.1</span> Detect the block size

``` src
(cp:with-oracle (oracle)
  (loop for i from 1 to 64
        for encrypted = (oracle (make-array (* i 2) :initial-element 97))
        for blocks = (cp:blockify encrypted :block-size i)
        until (equalp (first blocks) (second blocks))
        finally (return i)))
```

``` example
16
```

#### <span class="section-number-4">2.4.2</span> Detect that the function is using ECB

``` src
(cp:with-oracle (oracle)
  (cp:detect-aes-128-ecb
   (oracle (make-array (* 16 2) :initial-element 97))))
```

``` example
1
```

#### <span class="section-number-4">2.4.3</span> Use oracle to break ECB

``` src
(let ((unknown (cp:base64->bytes "Um9sbGluJyBpbiBteSA1L
jAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvd
wpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNhe
SBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")))
  (cp:with-oracle (oracle unknown)
    (cp:bytes->ascii (cp:break-aes-ecb-with-oracle #'oracle))))
```

``` example
"Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
"
```

### <span class="section-number-3">2.5</span> ECB cut-and-paste

#### <span class="section-number-4">2.5.1</span> Write a k=v parsing routine

``` src
(cp:parse-cookie "foo=bar&baz=qux&zap=zazzle")
```

``` example
(("foo" . "bar") ("baz" . "qux") ("zap" . "zazzle"))
```

#### <span class="section-number-4">2.5.2</span> Write a function that encodes a user profile

``` src
(let ((user-profiler (cp:make-profiler "user")))
  (list (cp:profile-for user-profiler "alice")
        (cp:profile-for user-profiler "bob")
        (cp:profile-for user-profiler "eve")))
```

``` example
("email=alice&uid=0&role=user" "email=bob&uid=1&role=user"
 "email=eve&uid=2&role=user")
```

#### <span class="section-number-4">2.5.3</span> Carry out a cut-paste attack

`MAKE-ENCRYPTED-USER-PROFILER` is just an AES ECB wrapper around `MAKE-PROFILER`. Use carefully crafted email addresses to get blocks that can be combined to create an admin profile.

``` src
(let* ((secret (cp:gen-random 16))
       (profiler (cp:make-encrypted-user-profiler secret 10))
       ;; Bogus email address so that the second block starts
       ;; with "admin": "admin&uid=10&rol"
       (admin (funcall profiler "aaaaaaaaaaadmin"))
       ;; Use a valid thirteen character email address so that
       ;; the second block ends with "role="
       (profile (funcall profiler "attak@jdtw.us"))
       ;; We need a third block to cut-paste from to get the
       ;; right pkcs7 padding
       (padding (funcall profiler "aaaaaaaaa")))
  ;; Now mix and match...
  (setf (nth-block 2 profile) (nth-block 1 admin)
        profile (concat-bytes profile (nth-block 2 padding)))
  (cp:decrypt-and-parse-profile secret profile))
```

``` example
(("email" . "attak@jdtw.us") ("uid" . "11") ("role" . "admin") ("uid" . "10")
 ("rol" . ""))
```

Verify that our parser thinks the profile is an admin.

``` src
(cp:profile-role '(("email" . "attak@jdtw.us")
                   ("uid" . "11")
                   ("role" . "admin")
                   ("uid" . "10")
                   ("rol" . "")))
```

``` example
"admin"
```

### <span class="section-number-3">2.6</span> Byte-at-a-time ECB decryption (Harder)

I modified my original oracle code and added "prefix" versions. The first task is to find the length of the random prefix, which is what `FIND-PREFIX-LENGTH` does.

``` src
(loop for i below 256 do
  (cp:with-oracle (oracle nil (gen-random i))
    (let ((len (cp:find-prefix-length #'oracle)))
      (assert (= i len)))))
```

``` example
NIL
```

And once the prefix-length is known, it's just a matter of updating offsets appropriately. Here we are decrypting the text, using a prefix of a random length:

``` src
(let ((unknown (cp:base64->bytes "Um9sbGluJyBpbiBteSA1L
jAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvd
wpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNhe
SBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))
      (prefix (cp:gen-random (random 255))))
  (cp:with-oracle (oracle unknown prefix)
    (cp:bytes->ascii (cp:break-aes-ecb-with-prefix-oracle #'oracle))))
```

``` example
"Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
"
```

### <span class="section-number-3">2.7</span> PKCS\#7 padding validation

``` src
(cp:bytes->ascii
 (cp:unpad-pkcs7
  (concatenate '(vector (unsigned-byte 8) *)
               (cp:ascii->bytes "ICE ICE BABY")
               #(4 4 4 4))))
```

``` example
"ICE ICE BABY"
```

``` src
(handler-case
    (cp:unpad-pkcs7
     (concatenate '(vector (unsigned-byte 8) *)
                  (cp:ascii->bytes "ICE ICE BABY")
                  #(5 5 5 5)))
  (cp:invalid-padding-error () :invalid-padding))
```

``` example
:INVALID-PADDING
```

``` src
(handler-case
    (cp:unpad-pkcs7
     (concatenate '(vector (unsigned-byte 8) *)
                  (cp:ascii->bytes "ICE ICE BABY")
                  #(1 2 3 4)))
  (cp:invalid-padding-error () :invalid-padding))
```

``` example
:INVALID-PADDING
```

### <span class="section-number-3">2.8</span> CBC bitflipping attacks

The intuition here is that the prior ciphertext block gets XOR'd with the output of the AES s-box. That means, to get the required character, we need to XOR the right ciphertext byte with the known-plaintext byte and the desired byte. That is what the function `CBC-FLIP` does in the code below.

``` src
(let* ((secret (cp:gen-random 16))
       (iv (cp:gen-random 16))
       (user-data "aaaaaaaaaaaaaaaaaaaaaaadminatrue")
       (encrypted (cp:encrypt-user-data secret iv user-data)))
  ;; Flip the 'a' before "admin" to ';' and the 'a' before
  ;; "true" to '='. Hard code the indices, because I'm lazy.
  (cp:cbc-flip encrypted 37 #\a #\;)
  (cp:cbc-flip encrypted 43 #\a #\=)
  (cp:data-lookup "admin" (cp:decrypt-and-parse-data secret iv encrypted)))
```

``` example
"true"
```

Created: 2017-10-08 Sun 21:32

[Validate](http://validator.w3.org/check?uri=referer)
