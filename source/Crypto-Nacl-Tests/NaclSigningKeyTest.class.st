"
A NaclSigningKeyTest is a test class for testing the behavior of NaclSigningKey
"
Class {
	#name : #NaclSigningKeyTest,
	#superclass : #TestCase,
	#category : #'Crypto-Nacl-Tests'
}

{ #category : #'testing-support' }
NaclSigningKeyTest >> signKey [
	^ NaclSigningKey
		skBytes: (ByteArray readHexFrom: '105cece5569cda0b3e1a06dcf3d95c7559b1c942d5f8fe0270377500172d306dcfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec')
		pkBytes: (ByteArray readHexFrom: 'cfdfa9d055a2f69b8828d7aca7bae0256d735c8f9a8db28f920ddc269a86aaec')
]

{ #category : #test }
NaclSigningKeyTest >> testSign [
	self assert: (self signKey sign: 'Hello, world' asUtf8ByteArray) hex equals: '3c1d5b10d8feef927e7633501a53e8ddc5dc4439055acea3b96cf23b5c941540d50721dbae65cde0fadaefd26d924e25b3d59116240119df18f96366e0a7760c48656c6c6f2c20776f726c64'
]
