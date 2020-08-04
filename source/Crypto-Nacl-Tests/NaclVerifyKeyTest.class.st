"
A NaclVerifyKeyTest is a test class for testing the behavior of NaclVerifyKey
"
Class {
	#name : #NaclVerifyKeyTest,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #test }
NaclVerifyKeyTest >> testVerify [
	| m |
	m := self verifyKey verify: (ByteArray readHexFrom: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64').
	self assert: m asUtf8String equals: 'Hello, world'.
]

{ #category : #test }
NaclVerifyKeyTest >> testVerifyFail [
	self should: [
		self verifyKey verify: (ByteArray readHexFrom: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c65'). "note final digit!"]
		raise: NaclError.
]

{ #category : #'testing-support' }
NaclVerifyKeyTest >> verifyKey [
	^ NaclVerifyKey bytes: (ByteArray readHexFrom: 'cfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec')
]
