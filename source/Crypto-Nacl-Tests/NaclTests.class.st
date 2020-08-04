Class {
	#name : #NaclTests,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #'as yet unclassified' }
NaclTests >> boxKey [
	^ NaclBoxSecretKey
		skBytes: (ByteArray readHexFrom: 'd54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3')
		pkBytes: (ByteArray readHexFrom: 'de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154')

]

{ #category : #'as yet unclassified' }
NaclTests >> iotaByteArray: n [
	| result |
	result := ByteArray new: n.
	1 to: n do: [:i | result at: i put: i - 1].
	^ result
]

{ #category : #'as yet unclassified' }
NaclTests >> signKey [
	^ NaclSigningKey
		skBytes: (ByteArray readHexFrom: '105cece5569cda0b3e1a06dcf3d95c7559b1c942d5f8fe0270377500172d306dcfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec')
		pkBytes: (ByteArray readHexFrom: 'cfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec')
]

{ #category : #'as yet unclassified' }
NaclTests >> testBox [
	| n e |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	e := self boxKey box: 'hello' asUtf8ByteArray nonce: n publicKey: self boxKey publicKey.
	self assert: e ciphertext hex equals: '3bc95b7983622e8afb763723703e17c6739be9c316'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testBoxKeypairSeed [
	| kp |
	kp := Nacl boxKeypairFromSeed: (ByteArray new: 0).
	self assert: kp publicKey bytes hex equals: '20d2d5a2cdd64d78eeb5437b33d1cb848204f5f3a4665eb5e55e6623387a8667'.
	self assert: kp secretBytes hex equals: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'.

]

{ #category : #'as yet unclassified' }
NaclTests >> testBoxOpen [
	| n m |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	m := self boxKey
			boxOpen: (ByteArray readHexFrom: '3bc95b7983622e8afb763723703e17c6739be9c316')
			nonce: n publicKey: self boxKey publicKey.
	self assert: m asUtf8String equals: 'hello'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testBoxOpenFail [
	| n |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	self should: [
		self boxKey
			boxOpen: (ByteArray readHexFrom: '3bc95b7983622e8afb763723703e17c6739be9c317') "note final digit!"
			nonce: n publicKey: self boxKey publicKey]
		raise: NaclError.
]

{ #category : #'as yet unclassified' }
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

{ #category : #'as yet unclassified' }
NaclTests >> testExampleLowlevel [
	"Test showing a simple example start to end, using the lowlevel API"

	| aliceSeed bobSeed nonce aKeys bKeys plainText box |
	aliceSeed := '.A man, a plan, a canal, Panama.'.
	bobSeed := 'Cuis is the best thing on wheels'.
	
	aKeys := Nacl boxKeypairFromSeed: aliceSeed asByteArray.
	bKeys := Nacl boxKeypairFromSeed: bobSeed asByteArray.

	plainText := 'Quando in le Curso del Eventos human, il deveni necessari
pro un Populo dissolver le Bandas Politic que les ha con-Nacl boxN
nectite con un altere, e assumer inter le Poteres del Terra, le
Position separate e equal al qual le Leges del Natura e del
Deo de Natura les da titulo, un decente Respecto al Opinio-
nes del Humanitate require que illes declara le causas que les
impelle al Separation.'.
	
	nonce := Nacl boxNonce.
	
	"Alice encrypts using her private key and Bob's public key"
	box := Nacl box: plainText asByteArray  nonce: nonce pk: bKeys  publicKey bytes sk: aKeys secretBytes.

	"Bob decrypts using Alice's public key ahd his private key"
	self assert: (
		(Nacl boxOpen: box nonce: nonce pk: aKeys publicKey bytes sk: bKeys secretBytes) asString
		= plainText
	).
]

{ #category : #'as yet unclassified' }
NaclTests >> testHash [
	self assert: (Nacl hash: (ByteArray new: 0)) hex equals: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'.
	self assert: (Nacl hashString: 'The quick brown fox jumps over the lazy dog') hex equals: '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6'.
	self assert: (Nacl hashString: 'The quick brown fox jumps over the lazy dog.') hex equals: '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testSecretbox [
	| k e |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	e := k box: 'Meet in the old churchyard at midnight.' asUtf8ByteArray nonce: (self iotaByteArray: Nacl secretboxNonceBytes).
	self assert: e ciphertext hex equals: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4db'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testSecretboxOpen [
	| k m |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	m := k
			boxOpen: (ByteArray readHexFrom: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4db')
			nonce: (self iotaByteArray: Nacl secretboxNonceBytes).
	self assert: m asUtf8String equals: 'Meet in the old churchyard at midnight.'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testSecretboxOpenFail [
	| k |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	self should: [
		k
			boxOpen: (ByteArray readHexFrom: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4dc') "note final digit!"
			nonce: (self iotaByteArray: Nacl secretboxNonceBytes)]
		raise: NaclError.
]

{ #category : #'as yet unclassified' }
NaclTests >> testSign [
	self assert: (self signKey sign: 'Hello, world' asUtf8ByteArray) hex equals: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64'
]

{ #category : #'as yet unclassified' }
NaclTests >> testSignKeypairFromSeed [
	| k sm |
	k := Nacl signKeypairFromSeed: 'This is my passphrase' asUtf8ByteArray.
	sm := ByteArray readHexFrom: 'dd13136c30516f8d6a679129e1b21cecd0d6c21e050f13a48468641565a3458e5390d83a301f9b5ba238097a7b4439663c7f5fb34684e09801d25bd08439a70248656c6c6f2c20776f726c64'.
	self assert: (k sign: 'Hello, world' asUtf8ByteArray) equals: sm.
	self assert: (k verifyKey verify: sm) asUtf8String equals: 'Hello, world'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testVerify [
	| m |
	m := self signKey verifyKey verify: (ByteArray readHexFrom: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64').
	self assert: m asUtf8String equals: 'Hello, world'.
]

{ #category : #'as yet unclassified' }
NaclTests >> testVerifyFail [
	self should: [
		self signKey verifyKey verify: (ByteArray readHexFrom: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c65'). "note final digit!"]
		raise: NaclError.
]
