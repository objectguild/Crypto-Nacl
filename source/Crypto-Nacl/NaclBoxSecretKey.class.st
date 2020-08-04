Class {
	#name : #NaclBoxSecretKey,
	#superclass : #Object,
	#instVars : [
		'publicKey',
		'secretBytes'
	],
	#category : #'Crypto-Nacl'
}

{ #category : #'as yet unclassified' }
NaclBoxSecretKey class >> fromSeed: seed [
	^ Nacl deriveKeypairFromSeed: seed
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey class >> random [
	^ Nacl boxKeypair
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey class >> skBytes: sk pkBytes: pk [
	| result |
	result := self new.
	result secretBytes: sk.
	result publicKey: (NaclBoxPublicKey pkBytes: pk).
	^ result
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey >> box: message nonce: nonce publicKey: aPublicKey [
	| e |
	e := NaclBoxEnvelope new.
	e nonce: nonce.
	e ciphertext: (Nacl box: message nonce: nonce pk: aPublicKey bytes sk: self secretBytes).
	^ e
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey >> box: message publicKey: aPublicKey [
	^ self box: message nonce: Nacl boxNonce publicKey: aPublicKey
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey >> boxOpen: ciphertext nonce: nonce publicKey: aPublicKey [
	^ Nacl boxOpen: ciphertext nonce: nonce pk: aPublicKey bytes sk: self secretBytes
]

{ #category : #'as yet unclassified' }
NaclBoxSecretKey >> boxOpen: envelope publicKey: aPublicKey [
	^ self boxOpen: envelope ciphertext nonce: envelope nonce publicKey: aPublicKey
]

{ #category : #accessing }
NaclBoxSecretKey >> erase [
	secretBytes fillWithZero.
	secretBytes := nil.
]

{ #category : #accessing }
NaclBoxSecretKey >> publicKey [
	
	^ publicKey
]

{ #category : #accessing }
NaclBoxSecretKey >> publicKey: anObject [
	
	publicKey := anObject
]

{ #category : #accessing }
NaclBoxSecretKey >> secretBytes [
	^ secretBytes
]

{ #category : #accessing }
NaclBoxSecretKey >> secretBytes: aByteArray [
	secretBytes := aByteArray
]
