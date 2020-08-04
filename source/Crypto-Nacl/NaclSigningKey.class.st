Class {
	#name : #NaclSigningKey,
	#superclass : #Object,
	#instVars : [
		'verifyKey',
		'secretBytes'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclSigningKey class >> fromRawSeed: seed [
	^ Nacl signKeypairFromRawSeed: seed
]

{ #category : #'as yet unclassified' }
NaclSigningKey class >> fromSeed: seed [
	^ Nacl signKeypairFromSeed: seed
]

{ #category : #'as yet unclassified' }
NaclSigningKey class >> random [
	^ Nacl signKeypair
]

{ #category : #'as yet unclassified' }
NaclSigningKey class >> skBytes: sk pkBytes: pk [
	| result |
	result := self new.
	result secretBytes: sk.
	result verifyKey: (NaclVerifyKey bytes: pk).
	^ result
]

{ #category : #'as yet unclassified' }
NaclSigningKey >> erase [
	secretBytes fillWithZero.
	secretBytes := nil.
]

{ #category : #accessing }
NaclSigningKey >> secretBytes [
	^ secretBytes
]

{ #category : #accessing }
NaclSigningKey >> secretBytes: aByteArray [
	secretBytes := aByteArray
]

{ #category : #'as yet unclassified' }
NaclSigningKey >> sign: aByteArray [
	^ Nacl sign: aByteArray privateKey: self secretBytes
]

{ #category : #accessing }
NaclSigningKey >> verifyKey [
	
	^ verifyKey
]

{ #category : #accessing }
NaclSigningKey >> verifyKey: anObject [
	
	verifyKey := anObject
]
