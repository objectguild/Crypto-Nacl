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

	^ self 
		ffiCall: #(int crypto_box_curve25519xsalsa20poly1305(uchar *c, uchar *m, ulonglong mlen, uchar *n, uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoBoxKeypairPk: pk sk: sk [

	^ self 
		ffiCall: #(long crypto_box_curve25519xsalsa20poly1305_ref_keypair (byte * pk, byte * sk)) 
		module: Nacl.

"	<apicall: long 'crypto_box_curve25519xsalsa20poly1305_ref_keypair' (byte* byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoBoxOpenMessage: m cipher: c cipherLength: clen nonce: n pk: pk sk: sk [

	^ self 
		ffiCall: #(int crypto_box_curve25519xsalsa20poly1305_open(uchar *m, uchar *c, ulonglong clen, uchar *n, uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoHashSha512Output: outByteArray input: inByteArray inputLength: inByteArrayLength [

	^ self 
		ffiCall: #(int crypto_hash_sha512(uchar *outByteArray, uchar *inByteArray, ulonglong inByteArrayLength)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoScalarmultCurve25519BaseTarget: pk source: sk [

	^ self 
		ffiCall: #(int crypto_scalarmult_curve25519_base(uchar *pk, uchar *sk)) 
		module: Nacl
]

{ #category : #api }
Nacl class >> apiCryptoSecretboxCipher: c message: m messageLength: mlen nonce: n key: key [

	^ self 
		ffiCall: #(long crypto_secretbox_xsalsa20poly1305_ref(byte * c, byte * m, ulonglong mlen, byte * n, byte * key)) 
		module: Nacl.

"	<apicall: long 'crypto_secretbox_xsalsa20poly1305_ref' (byte* byte* ulonglong byte* byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoSecretboxOpenMessage: m cipher: c cipherLength: mlen nonce: n key: key [

	^ self 
		ffiCall: #(long crypto_secretbox_xsalsa20poly1305_ref_open(byte * m, byte * c, ulonglong mlen, byte * n, byte * key)) 
		module: Nacl.

"	<apicall: long 'crypto_secretbox_xsalsa20poly1305_ref_open' (byte* byte* ulonglong byte* byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoSignBuffer: b bufferLength: blenPtr message: m length: mlen privateKey: sk [ 

	^ self 
		ffiCall: #(long crypto_sign_ed25519_ref(byte * b, byte * blenPtr, byte * m, ulonglong mlen, byte * sk)) 
		module: Nacl.

"	<apicall: long 'crypto_sign_ed25519_ref' (byte* byte* byte* ulonglong byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoSignKeypairPk: pk sk: sk [

	^ self 
		ffiCall: #(long crypto_sign_ed25519_ref_keypair(byte * pk, byte * sk)) 
		module: Nacl.
		
"	<apicall: long 'crypto_sign_ed25519_ref_keypair' (byte* byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoSignKeypairPk: pk sk: sk seed: seed [

	^ self 
		ffiCall: #(long crypto_sign_ed25519_ref_seed_keypair(byte * pk, byte * sk, byte * seed)) 
		module: Nacl.

"	<apicall: long 'crypto_sign_ed25519_ref_seed_keypair' (byte* byte* byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiCryptoSignOpenBuffer: b bufferLength: blenPtr signedMessage: sm length: smlen publicKey: pk [

	^ self 
		ffiCall: #(long crypto_sign_ed25519_ref_open (byte * b, byte * blenPtr, byte * sm, ulonglong smlen, byte * pk)) 
		module: Nacl.

"	<apicall: long 'crypto_sign_ed25519_ref_open' (byte* byte* byte* ulonglong byte*) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> apiRandomBytes: aByteArray length: aByteArrayLength [

	^ self 
		ffiCall: #(void randombytes (byte * aByteArray, ulonglong aByteArrayLength)) 
		module: Nacl.

"	<apicall: void 'randombytes' (byte* ulonglong) module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> box: message nonce: nonce pk: pk sk: sk [
	| c m |
	m := (ByteArray new: self boxZeroBytes), message.
	c := ByteArray new: m size.
	self checkError: 'crypto_box failed' apiResult: (self apiCryptoBoxCipher: c message: m messageLength: m size nonce: nonce pk: pk sk: sk).
	^ c copyFrom: self boxBoxZeroBytes + 1 to: c size
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
	| pk sk |
	sk := ByteArray new: self boxSecretKeyBytes.
	pk := ByteArray new: self boxPublicKeyBytes.
	self checkError: 'crypto_box_keypair failed' apiResult: (self apiCryptoBoxKeypairPk: pk sk: sk).
	^ NaclBoxSecretKey skBytes: sk pkBytes: pk
]

{ #category : #api }
Nacl class >> boxKeypairFromSeed: seed [
	| sk pk |
	sk := (Nacl hash: seed) copyFrom: 1 to: Nacl boxSecretKeyBytes.
	pk := ByteArray new: Nacl boxPublicKeyBytes.
	self apiCryptoScalarmultCurve25519BaseTarget: pk source: sk.
	^ NaclBoxSecretKey skBytes: sk pkBytes: pk
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
	| c m |
	c := (ByteArray new: self boxBoxZeroBytes), ciphertext.
	m := ByteArray new: c size.
	self checkError: 'crypto_box_open failed' apiResult: (self apiCryptoBoxOpenMessage: m cipher: c cipherLength: c size nonce: nonce pk: pk sk: sk).
	^ m copyFrom: self boxZeroBytes + 1 to: m size
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
Nacl class >> hash: aByteArray [
	| result |
	result := ByteArray new: self hashBytes.
	self checkError: 'crypto_hash failed' apiResult: (self apiCryptoHashSha512Output: result input: aByteArray inputLength: aByteArray size).
	^ result
]

{ #category : #api }
Nacl class >> hashBytes [
	^ 64
]

{ #category : #api }
Nacl class >> hashString: aString [
	^ self hash: aString asUtf8ByteArray
]

{ #category : #testing }
Nacl class >> isBigEndian [

	^ (Smalltalk at: #EndianDetector) isBigEndian
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
		ffiCall: #(long sodium_version_major ()) 
		module: Nacl.
		
"	<apicall: long 'sodium_version_major' () module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> sodiumVersionMinor [

	^ self 
		ffiCall: #(long sodium_version_minor ()) 
		module: Nacl.
		
"	<apicall: long 'sodium_version_minor' () module: 'libsodium'>
	^self externalCallFailed"
]

{ #category : #api }
Nacl class >> sodiumVersionString [
	" 
	Nacl sodiumVersionString 
	"
	^ self 
		ffiCall: #(String sodium_version_string ()) 
		module: Nacl.
		
"	<apicall: char* 'sodium_version_string' () module: 'libsodium'>
	^self externalCallFailed"
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

{ #category : #'accessing platform' }
Nacl >> macModuleName [
 
	^ 'libsodium.dylib'
]

{ #category : #'accessing platform' }
Nacl >> unix64ModuleName [

    ^ 'libsodium64.so'

]

{ #category : #'accessing platform' }
Nacl >> unixModuleName [

    ^ 'libsodium.so'
]

{ #category : #'accessing platform' }
Nacl >> win32ModuleName [
 
	^ 'libsodium.dll'
]
