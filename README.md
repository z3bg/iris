Identifi
========

http://identifi.org


What
----
- Distributed identity and reputation database
- Web of trust
- API for integration with various trust or identity dependent applications
- Anyone can add identifiers and make statements about their relations to others
  - "user@example.com and http://facebook.com/user belong to the same owner"
  - "alice@example.com and bob@example.com are friends"
- Anyone can add reviews with their identity
  - "alice@example.com says: I successfully traded with bob@example.com"
- Credibility of statements can be evaluated by their author's reputation (history, social connections, identity verifications, reviews etc.)

Why
---
- Prevent spam (by accepting messages only from trusted / socially connected senders)
- Prevent astroturfing / sockpuppeting
- Makes it possible to trust people you have never met
  - Utilize your good reputation in various services and situations
  - Reduces risk of trade or loan, thus reducing price
- Ubiquitous reputation as non-violent, cost-effective and decentralized justice
  - Everyone can choose whose judgement or review to trust
  - Incentive against antisocial behavior
  - Incentive to restore trust by compensation and apology for misdeeds
- Facilitate gift economy / time banking
- Distributed public messaging, with trust lists instead of centralized moderator power
- Censorship-resistance
- Open database, vs. proprietary information silos of reputation and online identity

How
---
- Prototype built on Bitcoin code to utilize existing crypto, network, CLI, etc. functions
- Data package: [subject identifiers, object identifiers, message][signatures]
  - Identified by content hash
  - Signed by the entity which verified that the message originates from the named subject. Thus, all end users need not to have a crypto key of their own.
- Flood packages throughout the network
  - Nodes can choose to accept only packages with 1) a trusted signature, 2) trusted subject
- Crawl initial data from existing social networks and review systems

Building
--------

Makefile.unix builds nicely with dependencies from Debian packages (same as Bitcoin + sqlite).

Other makefiles TBD.

License
-------

Identifi is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.

Data format
-----------

Using JSON serialization for the prototype.

Suggested data format for Identifi packets:

	[
		<timestamp>,
		<pair array of message sender's identifiers>,
		<array of message recipients (as pair arrays) or topics>,
		<message content>
	]

Example:

    [
    	1373924495,
	    [ 	
	    	name:'Alice Smith', mbox:'mailto:alice@example.com' 
	    ],
		[
	    	[ 	
	    		['nick', 'Bob the Builder'],
	    		['homepage','http://twitter.com/bob'],
	    		['homepage','http://www.facebook.com/bob'],
	    		['depiction','magnet:<photo hash>?xs=http://example.com/1.jpg' ]
	    	],
	    	[	
	    		['responseTo','magnet:<hash of bob's message>']
	    	]
		],
    	'Bought a laptop from Bob. Thanks for the trade! #positive #trade'
	]

Messages and identifiers are to be stored locally in a hash table (or maybe later in a DHT). These hashes can be refered to with magnet URIs.

Messages are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a crawler that read the sender's message from Twitter.

Message encoding is UTF-8.

TODO
----

* Improve in-built trust evaluation algorithm
* Replace hashtag system with numeric ratings
* Recalculate old trust ratings when new packets arrive
* Network method for requesting packets created after a given timestamp
* Remove unnecessary Bitcoin code
* Add more signature methods
* Write performance tests and improve efficiency
* Crawlers
* Visualizations
* Trusted sites as entry points to the WoT. Let users authenticate with email, FB, pubkey, etc.

Future considerations
---------------------

Use [Redland](http://librdf.org) triple storage and/or [HDT](http://www.rdfhdt.org) serialization? This would enable handling of all kinds of RDF documents (standard FOAF for example) and queries by SPARQL.

Use [Whanau DHT](http://pdos.csail.mit.edu/papers/whanau-nsdi10-abstract.html) instead of a flooding network?

Use external SQL DB instead of sqlite for better multi-application access to data?

Use [GPGME](http://www.gnupg.org/related_software/gpgme) to integrate with PGP web of trust? Could provide a nice entry point to the Identifi WoT for many people.

Allow messages in Identifi packets to be JSON dicts? ATM limited to strings.
