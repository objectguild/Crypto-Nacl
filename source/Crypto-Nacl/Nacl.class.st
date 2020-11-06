"
Main class for accessing the Nacl library in Pharo.
This library now uses UnifiedFFI for bindings.

See class methods for usage.

Public API and Key Messages

- message one   
- message two 
- (for bonus points) how to create instances.

   One simple example is simply gorgeous.
 
Internal Representation and Key Implementation Points.


    Implementation Points
"
Class {
	#name : #Nacl,
	#superclass : #FFILibrary,
	#category : #'Crypto-Nacl'
}

{ #category : #api }
Nacl class >> apiCryptoBoxCipher: c message: m messageLength: mlen nonce: n pk: pk sk: sk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_box_curve25519xsalsa20poly1305(uchar *c, uchar *m, ulonglong mlen, uchar *n, uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoBoxKeypairPk: pk sk: sk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_box_curve25519xsalsa20poly1305_keypair(uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoBoxOpenMessage: m cipher: c cipherLength: clen nonce: n pk: pk sk: sk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_box_curve25519xsalsa20poly1305_open(uchar *m, uchar *c, ulonglong clen, uchar *n, uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoHashSha512Output: out input: in inputLength: inlen [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_hash_sha512(uchar *out, uchar *in, ulonglong inlen)) 
		module: Nacl
]

{ #category : #'as yet unclassified' }
Nacl class >> apiCryptoPwHashOutput: out input: in inputLength: inlen opsLimit: ops memLimit: mem [
	self assertInitialized.
	^ self
		ffiCall: #( int crypto_pwhash_str(uchar *out , uchar *in , ulonglong inlen , ulonglong ops , size_t mem)) library: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoScalarmultCurve25519BaseTarget: pk source: sk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_scalarmult_curve25519_base(uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSecretboxCipher: c message: m messageLength: mlen nonce: n key: k [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_secretbox_xsalsa20poly1305(uchar *c, uchar *m, ulonglong mlen, uchar *n, uchar *k)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSecretboxOpenMessage: m cipher: c cipherLength: mlen nonce: n key: k [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_secretbox_xsalsa20poly1305_open(uchar *m, uchar *c, ulonglong mlen, uchar *n, uchar *k)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSignBuffer: sm bufferLength: smlen_p message: m length: mlen privateKey: sk [ 
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_sign_ed25519(uchar *sm, ulonglong *smlen_p, uchar *m, ulonglong mlen, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSignKeypairPk: pk sk: sk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_sign_ed25519_keypair(uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSignKeypairPk: pk sk: sk seed: seed [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_sign_ed25519_seed_keypair(uchar *pk, uchar *sk, uchar *seed)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSignOpenBuffer: m bufferLength: mlen_p signedMessage: sm length: smlen publicKey: pk [
	self assertInitialized.
	^ self 
		ffiCall: #(int crypto_sign_ed25519_open(uchar *m, ulonglong *mlen_p, uchar *sm, ulonglong smlen, uchar *pk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiInitialize [
	^ self 
		ffiCall: #(int sodium_init(void)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiRandomBytes: buf length: size [
	"Fills buf with an unpredictable sequence of size bytes.
	See for details: https://libsodium.gitbook.io/doc/generating_random_data"
	self assertInitialized.
	^ self 
		ffiCall: #(void randombytes_buf(void *buf, size_t size))
		module: Nacl
]

{ #category : #api }
Nacl class >> assertInitialized [
	self apiInitialize < 0
		ifTrue: [ NaclError signal: 'Libsodium library couldn''t be initialized, it is not safe to use' ]
]

{ #category : #api }
Nacl class >> box: message nonce: nonce pk: pk sk: sk [
	self deprecated: 'Please use #encryptMessage:withRecipientPublicKey:senderSecretKey:andNonce: instead'.
	^ self encryptMessage: message withRecipientPublicKey: pk senderSecretKey: sk andNonce: nonce
]

{ #category : #api }
Nacl class >> boxBeforeNmBytes [
	^ 32
]

{ #category : #api }
Nacl class >> boxBoxZeroBytes [
	^ 16
]

{ #category : #api }
Nacl class >> boxKeypair [
	self deprecated: 'Please use #generateKeypair instead'.
	^ self generateKeypair
]

{ #category : #api }
Nacl class >> boxKeypairFromSeed: seed [
	self deprecated: 'Please use #deriveKeypairFromSeed: instead'.
	^ self deriveKeypairFromSeed: seed
]

{ #category : #api }
Nacl class >> boxNonce [
	^ self randomBytes: self boxNonceBytes
]

{ #category : #api }
Nacl class >> boxNonceBytes [
	^ 24
]

{ #category : #api }
Nacl class >> boxOpen: ciphertext nonce: nonce pk: pk sk: sk [
	self deprecated: 'Please use #verifyMessage:senderPublicKey:recipientSecretKey:andNonce: instead'.
	^ self verifyCiphertext: ciphertext senderPublicKey: pk recipientSecretKey: sk andNonce: nonce
]

{ #category : #api }
Nacl class >> boxPublicKeyBytes [
	^ 32
]

{ #category : #api }
Nacl class >> boxSecretKeyBytes [
	^ 32
]

{ #category : #api }
Nacl class >> boxZeroBytes [
	^ 32
]

{ #category : #api }
Nacl class >> checkError: message apiResult: n [
	n isZero ifFalse: [NaclError signal: message]
]

{ #category : #api }
Nacl class >> deriveKeypairFromSeed: seed [
	"https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
	Authenticated encryption - Key pair generation
	Deterministically derive a key pair from a single key seed.
	
	WebBrowser openOn: 'https://doc.libsodium.org/public-key_cryptography/authenticated_encryption'	"
	| sk pk |
	sk := (Nacl hash: seed) copyFrom: 1 to: Nacl boxSecretKeyBytes.
	pk := ByteArray new: Nacl boxPublicKeyBytes.
	self apiCryptoScalarmultCurve25519BaseTarget: pk source: sk.
	^ NaclBoxSecretKey skBytes: sk pkBytes: pk
]

{ #category : #api }
Nacl class >> encryptMessage: message withRecipientPublicKey: pk senderSecretKey: sk andNonce: nonce [
	"https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
	Authenticated encryption - Combined mode
	The authentication tag and the encrypted message are stored together (this is usually what you want).
	Encrypts message with recipient's public key, sender's secret key and nonce.
	
	WebBrowser openOn: 'https://doc.libsodium.org/public-key_cryptography/authenticated_encryption'	"
	| c m |
	m := (ByteArray new: self boxZeroBytes), message.
	c := ByteArray new: m size.
	self checkError: 'crypto_box failed' apiResult: (self apiCryptoBoxCipher: c message: m messageLength: m size nonce: nonce pk: pk sk: sk).
	^ c copyFrom: self boxBoxZeroBytes + 1 to: c size
]

{ #category : #api }
Nacl class >> generateKeypair [
	"https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
	Authenticated encryption - Key pair generation
	Randomly generates a secret key and a corresponding public key.
	
	WebBrowser openOn: 'https://doc.libsodium.org/public-key_cryptography/authenticated_encryption'	"
	| pk sk |
	sk := ByteArray new: self boxSecretKeyBytes.
	pk := ByteArray new: self boxPublicKeyBytes.
	self checkError: 'crypto_box_keypair failed' apiResult: (self apiCryptoBoxKeypairPk: pk sk: sk).
	^ NaclBoxSecretKey skBytes: sk pkBytes: pk
]

{ #category : #api }
Nacl class >> hash: aByteArray [
	self deprecated: 'Please use #hashSHA512: instead'.
	^ self hashSHA512: aByteArray
]

{ #category : #api }
Nacl class >> hashBytes [
	self deprecated: 'Please use #hashBytes instead'.
	^ self hashSHA512Bytes
]

{ #category : #api }
Nacl class >> hashSHA512: aByteArray [
	"SHA-2 - SHA-512: https://doc.libsodium.org/advanced/sha-2_hash_function

	The SHA-512 hash function is provided for interoperability with other applications.
	It is not suitable for hashing passwords or deriving keys from passwords. Use one 
	of the password hashing methods instead.
	
	WebBrowser openOn: 'https://doc.libsodium.org/public-key_cryptography/authenticated_encryption'	"
	| result |
	result := ByteArray new: self hashSHA512Bytes.
	self checkError: 'crypto_hash failed' apiResult: (self apiCryptoHashSha512Output: result input: aByteArray inputLength: aByteArray size).
	^ result
]

{ #category : #api }
Nacl class >> hashSHA512Bytes [
	^ 64
]

{ #category : #api }
Nacl class >> hashString: aString [
	self deprecated: 'Please use #hashStringSHA512: instead'.
	^ self hash: aString asUtf8ByteArray
]

{ #category : #api }
Nacl class >> hashStringSHA512: aString [
	^ self hashSHA512: aString asUtf8ByteArray
]

{ #category : #testing }
Nacl class >> isBigEndian [

	^ (Smalltalk at: #EndianDetector) isBigEndian
]

{ #category : #'as yet unclassified' }
Nacl class >> pwHashDefault: password [ 
| result ops mem|
	ops := self pwHashOpslimitInteractive.
	mem := self pwHashMemlimitInteractive.
result := ByteArray new: self pwHashStrBytes.
self checkError: 'crypto hash failed' apiResult: (self apiCryptoPwHashOutput: result input: password inputLength: password size opsLimit: ops memLimit: mem).
^ result 
]

{ #category : #'as yet unclassified' }
Nacl class >> pwHashMemlimitInteractive [
	^ self ffiCall: #(size_t crypto_pwhash_memlimit_interactive()) library: Nacl 
]

{ #category : #'as yet unclassified' }
Nacl class >> pwHashOpslimitInteractive [
	^ self ffiCall: #( size_t crypto_pwhash_opslimit_interactive() ) library: Nacl
]

{ #category : #'as yet unclassified' }
Nacl class >> pwHashStrBytes [
	^ self ffiCall: #( size_t crypto_pwhash_strbytes() ) library: Nacl 
]

{ #category : #'as yet unclassified' }
Nacl class >> pwHashString: aString [
	^ self pwHashDefault: aString asUtf8ByteArray 
]

{ #category : #api }
Nacl class >> randomBytes: n [
	| result |
	result := ByteArray new: n.
	self apiRandomBytes: result length: result size.
	^ result
]

{ #category : #api }
Nacl class >> secretbox: message nonce: nonce key: key [
	| c m |
	m := (ByteArray new: self secretboxZeroBytes), message.
	c := ByteArray new: m size.
	self checkError: 'crypto_secretbox failed' apiResult: (self apiCryptoSecretboxCipher: c message: m messageLength: m size nonce: nonce key: key).
	^ c copyFrom: self secretboxBoxZeroBytes + 1 to: c size
]

{ #category : #api }
Nacl class >> secretboxBoxZeroBytes [
	^ 16
]

{ #category : #api }
Nacl class >> secretboxKey [
	^ NaclSecretboxKey keyBytes: (self randomBytes: self secretboxKeyBytes)
]

{ #category : #api }
Nacl class >> secretboxKeyBytes [
	^ 32
]

{ #category : #api }
Nacl class >> secretboxNonce [
	^ self randomBytes: self secretboxNonceBytes
]

{ #category : #api }
Nacl class >> secretboxNonceBytes [
	^ 24
]

{ #category : #api }
Nacl class >> secretboxOpen: ciphertext nonce: nonce key: key [
	| c m |
	c := (ByteArray new: self secretboxBoxZeroBytes), ciphertext.
	m := ByteArray new: c size.
	self checkError: 'crypto_secretbox_open failed' apiResult: (self apiCryptoSecretboxOpenMessage: m cipher: c cipherLength: c size nonce: nonce key: key).
	^ m copyFrom: self secretboxZeroBytes + 1 to: m size
]

{ #category : #api }
Nacl class >> secretboxZeroBytes [
	^ 32
]

{ #category : #api }
Nacl class >> sign: message privateKey: privateKey [

	| sm smlenBuf smlen |

	sm := ByteArray new: message size + self signBytes.
	smlenBuf := ByteArray new: 8.
	self 
		checkError: 'crypto_sign failed' 
		apiResult: (self apiCryptoSignBuffer: sm bufferLength: smlenBuf message: message length: message size privateKey: privateKey).
	smlen := ((smlenBuf longAt: 5 bigEndian: self isBigEndian) bitShift: 32) + (smlenBuf longAt: 1 bigEndian: self isBigEndian).
	^ sm copyFrom: 1 to: smlen
]

{ #category : #api }
Nacl class >> signBytes [
	^ 64
]

{ #category : #api }
Nacl class >> signKeypair [
	| pk sk |
	sk := ByteArray new: self signSecretKeyBytes.
	pk := ByteArray new: self signPublicKeyBytes.
	self checkError: 'crypto_sign_keypair failed' apiResult: (self apiCryptoSignKeypairPk: pk sk: sk).
	^ NaclSigningKey skBytes: sk pkBytes: pk
]

{ #category : #api }
Nacl class >> signKeypairFromRawSeed: seed [

	| pk sk |
	seed size ~= self signSeedBytes
		ifTrue: [ self error: 'Seed for signing keypair must be ', self signSeedBytes asString,' bytes long.'].
	sk := ByteArray new: self signSecretKeyBytes.
	pk := ByteArray new: self signPublicKeyBytes.
	self checkError: 'crypto_sign_seed_keypair failed' apiResult: (self apiCryptoSignKeypairPk: pk sk: sk seed: seed).
	^ NaclSigningKey skBytes: sk pkBytes: pk
]

{ #category : #api }
Nacl class >> signKeypairFromSeed: bytes [
	^ self signKeypairFromRawSeed: ((self hash: bytes) copyFrom: 1 to: self signSeedBytes)
]

{ #category : #api }
Nacl class >> signPublicKeyBytes [
	^ 32
]

{ #category : #api }
Nacl class >> signSecretKeyBytes [
	^ 64
]

{ #category : #api }
Nacl class >> signSeedBytes [
	^ self signSecretKeyBytes // 2
]

{ #category : #api }
Nacl class >> sodiumVersionMajor [

	^ self 
		ffiCall: #(int sodium_version_major()) 
		module: Nacl
]

{ #category : #api }
Nacl class >> sodiumVersionMinor [

	^ self 
		ffiCall: #(int sodium_version_minor()) 
		module: Nacl
]

{ #category : #api }
Nacl class >> sodiumVersionString [

	^ self 
		ffiCall: #(String sodium_version_string()) 
		module: Nacl
]

{ #category : #api }
Nacl class >> verify: signedMessage publicKey: publicKey [
	| m mlenBuf mlen |

	m := ByteArray new: signedMessage size.
	mlenBuf := ByteArray new: 8.
	self 
		checkError: 'crypto_sign_open failed' 
		apiResult: (self apiCryptoSignOpenBuffer: m bufferLength: mlenBuf signedMessage: signedMessage length: signedMessage size publicKey: publicKey).
	mlen := ((mlenBuf longAt: 5 bigEndian: self isBigEndian) bitShift: 32) + (mlenBuf longAt: 1 bigEndian: self isBigEndian).
	^ m copyFrom: 1 to: mlen
]

{ #category : #api }
Nacl class >> verifyCiphertext: ciphertext senderPublicKey: pk recipientSecretKey: sk andNonce: nonce [
	"https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
	Authenticated encryption - Combined mode
	The authentication tag and the encrypted message are stored together (this is usually what you want).
	Verifies and decrypts a ciphertext produced by #encryptMessage:withRecipientPublicKey:senderSecretKey:andNonce:. 
	The nonce has to match the nonce used to encrypt and authenticate the message.
	
	WebBrowser openOn: 'https://doc.libsodium.org/public-key_cryptography/authenticated_encryption'	"
	| c m |
	c := (ByteArray new: self boxBoxZeroBytes), ciphertext.
	m := ByteArray new: c size.
	self checkError: 'crypto_box_open failed' apiResult: (self apiCryptoBoxOpenMessage: m cipher: c cipherLength: c size nonce: nonce pk: pk sk: sk).
	^ m copyFrom: self boxZeroBytes + 1 to: m size
]

{ #category : #'accessing platform' }
Nacl >> macModuleName [
 
	^ 'libsodium.dylib'
]

{ #category : #'accessing platform' }
Nacl >> unix32ModuleName [

    ^ self unixModuleName

]

{ #category : #'accessing platform' }
Nacl >> unix64ModuleName [

    ^ self unixModuleName

]

{ #category : #'accessing platform' }
Nacl >> unixModuleName [

    ^ 'libsodium.so'
]

{ #category : #'accessing platform' }
Nacl >> win32ModuleName [
 
	^ 'libsodium.dll'
]
