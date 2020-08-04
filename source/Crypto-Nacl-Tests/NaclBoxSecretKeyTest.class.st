"
A NaclBoxSecretKeyTest is a test class for testing the behavior of NaclBoxSecretKey
"
Class {
	#name : #NaclBoxSecretKeyTest,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #'testing-support' }
NaclBoxSecretKeyTest >> boxKey [
	^ NaclBoxSecretKey
		skBytes: (ByteArray readHexFrom: 'd54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3')
		pkBytes: (ByteArray readHexFrom: 'de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154')

]

{ #category : #test }
NaclBoxSecretKeyTest >> testBoxNoncePublicKey [
	| n e |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	e := self boxKey box: 'hello' asUtf8ByteArray nonce: n publicKey: self boxKey publicKey.
	self assert: e ciphertext hex equals: '3bc95b7983622e8afb763723703e17c6739be9c316'.
]

{ #category : #test }
NaclBoxSecretKeyTest >> testBoxOpenNoncePublicKey [
	| n m |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	m := self boxKey
			boxOpen: (ByteArray readHexFrom: '3bc95b7983622e8afb763723703e17c6739be9c316')
			nonce: n publicKey: self boxKey publicKey.
	self assert: m asUtf8String equals: 'hello'.
]

{ #category : #test }
NaclBoxSecretKeyTest >> testBoxOpenNoncePublicKeyFail [
	| n |
	n := ByteArray readHexFrom: '065114ca5a687e0544a88e6fc757b30afc70a0355854fd54'.
	self should: [
		self boxKey
			boxOpen: (ByteArray readHexFrom: '3bc95b7983622e8afb763723703e17c6739be9c317') "note final digit!"
			nonce: n publicKey: self boxKey publicKey]
		raise: NaclError.
]
