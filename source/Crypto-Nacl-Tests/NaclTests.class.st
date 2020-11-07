Class {
	#name : #NaclTests,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #test }
NaclTests >> testDeriveKeypairFromSeed [
	| kp |
	kp := Nacl deriveKeypairFromSeed: (ByteArray new: 0).
	self assert: kp publicKey bytes hex equals: '20d2d5a2cdd64d78eeb5437b33d1cb848204f5f3a4665eb5e55e6623387a8667'.
	self assert: kp secretBytes hex equals: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'.

]

{ #category : #test }
NaclTests >> testExampleHighlevel [
	"Test showing a simple example start to end, using the highlevel API"

	| aliceSeed bobSeed envelope aKeys bKeys plainText |
	aliceSeed := '.A man, a plan, a canal, Panama.'.
	bobSeed := 'Cuis is the best thing on wheels'.
	
	aKeys := NaclBoxSecretKey fromSeed: aliceSeed asByteArray.
	bKeys := NaclBoxSecretKey fromSeed: bobSeed asByteArray.

	plainText := 'Quando in le Curso del Eventos human, il deveni necessari
pro un Populo dissolver le Bandas Politic que les ha con-Nacl boxN
nectite con un altere, e assumer inter le Poteres del Terra, le
Position separate e equal al qual le Leges del Natura e del
Deo de Natura les da titulo, un decente Respecto al Opinio-
nes del Humanitate require que illes declara le causas que les
impelle al Separation.'.
	
	"Alice encrypts using her private key and Bob's public key"
	envelope := aKeys box: plainText asByteArray publicKey: bKeys publicKey.

	"Bob decrypts using Alice's public key ahd his private key"
	self assert:
		(bKeys boxOpen: envelope publicKey: aKeys publicKey) asString = plainText.
]

{ #category : #test }
NaclTests >> testExampleLowlevel [
	"Test showing a simple example start to end, using the lowlevel API"

	| aliceSeed bobSeed nonce aKeys bKeys plainText box |
	aliceSeed := '.A man, a plan, a canal, Panama.'.
	bobSeed := 'Cuis is the best thing on wheels'.
	
	aKeys := Nacl deriveKeypairFromSeed: aliceSeed asByteArray.
	bKeys := Nacl deriveKeypairFromSeed: bobSeed asByteArray.

	plainText := 'Quando in le Curso del Eventos human, il deveni necessari
pro un Populo dissolver le Bandas Politic que les ha con-Nacl boxN
nectite con un altere, e assumer inter le Poteres del Terra, le
Position separate e equal al qual le Leges del Natura e del
Deo de Natura les da titulo, un decente Respecto al Opinio-
nes del Humanitate require que illes declara le causas que les
impelle al Separation.'.
	
	nonce := Nacl boxNonce.
	
	"Alice encrypts using her private key and Bob's public key"
	box := Nacl encryptMessage: plainText asByteArray  withRecipientPublicKey: bKeys publicKey bytes senderSecretKey: aKeys secretBytes andNonce: nonce.

	"Bob decrypts using Alice's public key ahd his private key"
	self assert: (
		(Nacl boxOpen: box nonce: nonce pk: aKeys publicKey bytes sk: bKeys secretBytes) asString
		= plainText
	).
]

{ #category : #test }
NaclTests >> testHashSHA512 [
	self assert: (Nacl hashSHA512: (ByteArray new: 0)) hex equals: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'.
]

{ #category : #test }
NaclTests >> testHashStringSHA512 [
	self assert: (Nacl hashStringSHA512: 'The quick brown fox jumps over the lazy dog') hex equals: '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6'.
	self assert: (Nacl hashStringSHA512: 'The quick brown fox jumps over the lazy dog.') hex equals: '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed'.
]

{ #category : #tests }
NaclTests >> testPwHashString [
	| ops mem a b |
	ops := Nacl pwHashOpslimitInteractive.
	mem := Nacl pwHashMemlimitInteractive.
	a := Nacl pwHashUtf8StringClean: 'test' opslimit: ops memlimit: mem.
	b := Nacl pwHashUtf8StringClean: 'test' opslimit: ops memlimit: mem.
	self assert: a ~= b
]

{ #category : #tests }
NaclTests >> testPwHashVerify [
	| ops mem hashString |
	ops := Nacl pwHashOpslimitInteractive.
	mem := Nacl pwHashMemlimitInteractive.
	hashString := Nacl pwHashUtf8StringClean: 'test' opslimit: ops memlimit: mem.
	self assert: (Nacl pwHashStringIsVerified: hashString password: 'test') equals: true.
]

{ #category : #tests }
NaclTests >> testPwNeedsRehash [
	| ops mem hashString |
	ops := Nacl pwHashOpslimitInteractive.
	mem := Nacl pwHashMemlimitInteractive.
	hashString := Nacl pwHashUtf8StringClean: 'test' opslimit: ops memlimit: mem.
	self assert: ( Nacl pwHashStringNeedsRehash: hashString  opslimit: ops memlimit: mem ) equals: false.
	self assert: ( Nacl pwHashStringNeedsRehash: hashString  opslimit: Nacl pwHashOpslimitSensitive memlimit: mem ) equals: true.
]

{ #category : #test }
NaclTests >> testRandomBytes [
	self assert: (Nacl randomBytes: 1) size equals: 1.
	self assert: (Nacl randomBytes: 20) size equals: 20.
	self assert: (Nacl randomBytes: 32) size equals: 32.
	self assert: (Nacl randomBytes: 64) size equals: 64.

]

{ #category : #test }
NaclTests >> testSignKeypairFromSeed [
	| k sm |
	k := Nacl signKeypairFromSeed: 'This is my passphrase' asUtf8ByteArray.
	sm := ByteArray readHexFrom: 'dd13136c30516f8d6a679129e1b21cecd0d6c21e050f13a48468641565a3458e5390d83a301f9b5ba238097a7b4439663c7f5fb34684e09801d25bd08439a70248656c6c6f2c20776f726c64'.
	self assert: (k sign: 'Hello, world' asUtf8ByteArray) equals: sm.
	self assert: (k verifyKey verify: sm) asUtf8String equals: 'Hello, world'.
]
