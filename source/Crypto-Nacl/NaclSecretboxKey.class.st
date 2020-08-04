Class {
	#name : #NaclSecretboxKey,
	#superclass : #Object,
	#instVars : [
		'keyBytes'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclSecretboxKey class >> keyBytes: aByteArray [
	^ self new keyBytes: aByteArray
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey class >> random [
	^ Nacl secretboxKey
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey >> box: message [
	^ self box: message nonce: Nacl secretboxNonce
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey >> box: message nonce: nonce [
	| e |
	e := NaclBoxEnvelope new.
	e nonce: nonce.
	e ciphertext: (Nacl secretbox: message nonce: nonce key: self keyBytes).
	^ e
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey >> boxOpen: envelope [
	^ self boxOpen: envelope ciphertext nonce: envelope nonce
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey >> boxOpen: ciphertext nonce: nonce [
	^ Nacl secretboxOpen: ciphertext nonce: nonce key: self keyBytes
]

{ #category : #'as yet unclassified' }
NaclSecretboxKey >> erase [
	keyBytes fillWithZero.
	keyBytes := nil.
]

{ #category : #accessing }
NaclSecretboxKey >> keyBytes [
	
	^ keyBytes
]

{ #category : #accessing }
NaclSecretboxKey >> keyBytes: anObject [
	
	keyBytes := anObject
]
