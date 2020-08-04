"
A NaclSecretboxKeyTest is a test class for testing the behavior of NaclSecretboxKey
"
Class {
	#name : #NaclSecretboxKeyTest,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #'testing-support' }
NaclSecretboxKeyTest >> iotaByteArray: n [
	| result |
	result := ByteArray new: n.
	1 to: n do: [:i | result at: i put: i - 1].
	^ result
]

{ #category : #test }
NaclSecretboxKeyTest >> testBoxNonce [
	| k e |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	e := k box: 'Meet in the old churchyard at midnight.' asUtf8ByteArray nonce: (self iotaByteArray: Nacl secretboxNonceBytes).
	self assert: e ciphertext hex equals: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4db'.
]

{ #category : #test }
NaclSecretboxKeyTest >> testBoxOpenNonce [
	| k m |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	m := k
			boxOpen: (ByteArray readHexFrom: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4db')
			nonce: (self iotaByteArray: Nacl secretboxNonceBytes).
	self assert: m asUtf8String equals: 'Meet in the old churchyard at midnight.'.
]

{ #category : #test }
NaclSecretboxKeyTest >> testBoxOpenNonceFail [
	| k |
	k := NaclSecretboxKey keyBytes: (self iotaByteArray: Nacl secretboxKeyBytes).
	self should: [
		k
			boxOpen: (ByteArray readHexFrom: '01440c4518408578f1348926e058e82b139a5d3be7a3cc30cf54ea1e07e32eb731cd33adef4d468e65c647f521e7cc88e7b59cb22dc4dc') "note final digit!"
			nonce: (self iotaByteArray: Nacl secretboxNonceBytes)]
		raise: NaclError.
]
