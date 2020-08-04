Class {
	#name : #NaclBoxEnvelope,
	#superclass : #Object,
	#instVars : [
		'nonce',
		'ciphertext'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclBoxEnvelope class >> fromByteArray: bytes [
	^ self new fromByteArray: bytes
]

{ #category : #'as yet unclassified' }
NaclBoxEnvelope >> asByteArray [
	^ nonce, ciphertext
]

{ #category : #accessing }
NaclBoxEnvelope >> ciphertext [
	
	^ ciphertext
]

{ #category : #accessing }
NaclBoxEnvelope >> ciphertext: anObject [
	
	ciphertext := anObject
]

{ #category : #'as yet unclassified' }
NaclBoxEnvelope >> fromByteArray: bytes [
	nonce := bytes copyFrom: 1 to: Nacl boxNonceBytes.
	ciphertext := bytes copyFrom: Nacl boxNonceBytes + 1 to: bytes size.
]

{ #category : #accessing }
NaclBoxEnvelope >> nonce [
	
	^ nonce
]

{ #category : #accessing }
NaclBoxEnvelope >> nonce: anObject [
	
	nonce := anObject
]
