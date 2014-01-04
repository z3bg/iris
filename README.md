Identifi
========

http://identifi.org
http://slid.es/mmalmi/identifi

What
----
- Distributed identity and reputation database
- Web of trust
- API for integration with various trust or identity dependent applications
- Anyone can add identifiers and make statements about their relations to others
  - "user@example.com and http://facebook.com/user belong to the same owner"
  - "alice@example.com and bob@example.com are friends"
  - "alice@example.com is expired" - keep online identity up to date
  - etc.
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
  - No monopoly on credit ratings

How
---
- Prototype built on Bitcoin code to utilize existing crypto, network, CLI, etc. functions (but not blockchain)
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

Developing
----------
[Sqlite Manager](https://addons.mozilla.org/en-US/firefox/addon/sqlite-manager/) is a nice Firefox plugin for debugging DATADIR/db.sqlite.

License
-------

Identifi is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.

Data format
-----------

Using JSON serialization for the prototype. BSON might be more efficient to process and would enable binary fields for attachments such as images.

Suggested data format for Identifi packets:

    {
    	'signedData':
    	{
	    	'timestamp': 1373924495,
		    'author':
		    [ 	
		    	['name', 'Alice Smith'],
		    	['mbox', 'mailto:alice@example.com']
		    ],
			'recipient':
			[
	    		['nick', 'Bob the Builder'],
	    		['url','http://twitter.com/bob'],
	    		['url','http://www.facebook.com/bob'],
	    		['depiction','magnet:<photo hash>?xs=http://example.com/1.jpg']
			],
			'responseTo': ['magnet:<hash of bob's message>'],
			'type': 'review',
			'comment': 'Bought a laptop from Bob. Thanks for the trade!',
			'rating': 1,
			'maxRating': 10,
			'minRating': -10
		},
		'signatures':
		[
			{
				'signerPubKey': 'asdf1234',
				'signature': '4321fdsa'
			}
		]
	}

SignedData may optionally contain additional fields.

Packets and identifiers are to be stored locally in a hash table (or maybe later in a DHT). These hashes can be refered to with magnet URIs.

Packets are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a crawler that read the sender's message from Twitter.

Message encoding is UTF-8.

TODO
----

* Implement Dijkstra pathfinding algorithm
* Recalculate old trust ratings when new packets arrive
* Allocate disk space based on the author's trust
* Improve network functions, add sanity checks
* Remove unnecessary Bitcoin code
* Write performance tests and improve efficiency
* Crawlers
* Visualizations
* Trusted sites as entry points to the WoT. Let users authenticate with email, FB, pubkey, etc.

Future considerations
---------------------

Use [Trsst](http://www.trsst.com) for data propagation and storage?

Use [Whanau DHT](http://pdos.csail.mit.edu/papers/whanau-nsdi10-abstract.html) instead of a flooding network?

[Freenet](http://freenetproject.org) as data storage? Saving data is trivial, but efficient indexing needs some effort.

Use external SQL DB instead of sqlite for better multi-application access to data?

Use [GPGME](http://www.gnupg.org/related_software/gpgme) to integrate with PGP web of trust? Could provide a nice entry point to the Identifi WoT for many people.

Serialize in BSON to improve efficiency and enable embedded binary (images etc)?