Class {
	#name : #BaselineOfNacl,
	#superclass : #BaselineOf,
	#category : #BaselineOfNacl
}

{ #category : #baselines }
BaselineOfNacl >> baseline: spec [
	<baseline>
	spec
		for: #common
		do: [ 
			spec
				package: #'Crypto-Nacl';
				package: #'Crypto-Nacl-Tests' with: [ spec requires: #('Crypto-Nacl') ].
			spec
				group: 'default' with: #('core');
				group: 'core' with: #('Crypto-Nacl');
				group: 'tests' with: #('Crypto-Nacl-Tests') ].
]
