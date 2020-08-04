Extension { #name : #String }

{ #category : #'*Crypto-Nacl' }
String >> asUtf8ByteArray [
	^ (self convertToWithConverter: UTF8TextConverter new) asByteArray
]
