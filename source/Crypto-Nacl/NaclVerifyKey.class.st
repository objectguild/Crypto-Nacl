Class {
	#name : #NaclVerifyKey,
	#superclass : #Object,
	#instVars : [
		'bytes'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclVerifyKey class >> bytes: pk [
	| result |
	result := self new.
	result bytes: pk.
	^ result
]

{ #category : #accessing }
NaclVerifyKey >> bytes [
	
	^ bytes
]

{ #category : #accessing }
NaclVerifyKey >> bytes: anObject [
	
	bytes := anObject
]

{ #category : #'as yet unclassified' }
NaclVerifyKey >> verify: signedMessage [
	^ Nacl verify: signedMessage publicKey: self bytes
]
