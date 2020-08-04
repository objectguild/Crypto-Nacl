Extension { #name : #ByteArray }

{ #category : #'*Crypto-Nacl' }
ByteArray >> asUtf8String [
	^ self asString convertFromWithConverter: UTF8TextConverter new
]

{ #category : #'*Crypto-Nacl' }
ByteArray >> fillWithZero [
	1 to: self size do: [:i | self at: i put: 0].
]
