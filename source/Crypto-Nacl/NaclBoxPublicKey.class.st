Class {
	#name : #NaclBoxPublicKey,
	#superclass : #Object,
	#instVars : [
		'bytes'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclBoxPublicKey class >> pkBytes: pk [
	| result |
	result := self new.
	result bytes: pk.
	^ result
]

{ #category : #accessing }
NaclBoxPublicKey >> bytes [
	
	^ bytes
]

{ #category : #accessing }
NaclBoxPublicKey >> bytes: anObject [
	
	bytes := anObject
]
