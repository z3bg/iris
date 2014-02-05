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
- Data package: [author identifiers, recipient identifiers, message][signatures]
  - Identified by content hash
  - Signed by the entity which verified that the message originates from the named author. Thus, all end users need not to have a crypto key of their own.
- Flood packages throughout the network
  - Nodes maintain their own trust graphs which are updated as new packets arrive
  - Packet storage priority is based on its author's and signer's position in the node's web of trust
  - Later on, connections to other nodes can be prioritized by trust
- Crawl initial data from existing social networks and review systems

Possible applications
---------------------
- Facial recognition and identifi-cation with Google glass or similar
  - Thumbs up to the friendly bus driver, policeman or the stranger who helped you
- Mywot.com-style browser plugin for website reviews
- Bitcoin UIs, connect addresses to identities or vice versa
- Email plugin
  - Generate trusted senders list from email history
  - Require new senders to be on identifi - send automatic response if not
- Decentralized marketplaces, P2P trade and finance
  - Check escrow or trader reputation
  - Airbnb, eBay, Uber, LocalBitcoins etc.
  - Time banking, gift economy
- Uncensored and sockpuppet-resistant reviews and recommendations for products, restaurants etc.
- Public messaging, automatically show or hide authors
- Social network based routing protocols

Building
--------
Makefile.unix builds nicely with dependencies from Debian packages (same as Bitcoin + sqlite).

Merge with build tools from the Bitcoin master branch TBD.

Developing
----------
Core functionality of the implementation is in identifidb.cpp, data.cpp and rpcdb.cpp.

Get the daemon running with `./identifid -daemon`. Call the JSON-RPC with .`./identifid rpccommand`. Rpc_tests.cpp shows how to use the RPC.

The program connects to a seed node from DNS by default and requests for packets created after a certain timestamp. Identifi developers' ECDSA pubkey is included and trusted by default as an entry point to the WoT. You need to connect your own pubkey or other identifiers to the WoT if you want your packets prioritized over spam by other nodes. An example website for this TBD.

The default database size limit 2 GB. Add `saveuntrustedpackets=1` to DATADIR/identifi.conf to allow packets from outside your WoT for testing.

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
		    	['email', 'alice@example.com']
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
				'signerPubKey': 'RXfBZLerFkiD9k3LgreFbiGEyNFjxRc61YxAdPtHPy7HpDDxBQB62UBJLDniZwxXcf849WSra1u6TDCvUtdJxFJU',
				'signature': 'AN1rKoqJauDSAeJFjoCayzCk7iYjVLBtCMeACm5xG6mup6cVkw7zrWrZk35W2K7892KKstbdqEpRYWVPejKLDw12HPnF3fQCH'
			}
		]
	}

SignedData may optionally contain additional fields.

Packets and identifiers are to be stored locally in a hash table (or maybe later in a DHT). These hashes can be refered to with magnet URIs.

Packets are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a crawler that read the sender's message from Twitter.

Message encoding is UTF-8.

TODO
----

* Refine pathfinding algorithm, take into account the amount of positive and negative ratings
* Add support for up / downvoting of packets and marking connections expired
* Recalculate packet priorities when new packets are saved
* Allocate disk space based on the author's trust
* Improve network functions, add sanity checks and invalid packet spam protection
* Remove unnecessary Bitcoin code
* Improve efficiency, measured by packet save time tests
* Crawlers
* Visualizations
* Trusted sites as entry points to the WoT. Let users authenticate with email, FB, pubkey, etc.
* Merge build tools from Bitcoin master branch

Future considerations
---------------------

Use [Trsst](http://www.trsst.com) for data propagation and storage?

Use [Whanau DHT](http://pdos.csail.mit.edu/papers/whanau-nsdi10-abstract.html) instead of a flooding network?

[Freenet](http://freenetproject.org) as data storage? Saving data is trivial, but efficient indexing needs some effort.

Use external SQL DB instead of sqlite for better multi-application access to data?

Use [GPGME](http://www.gnupg.org/related_software/gpgme) to integrate with PGP web of trust? Could provide a nice entry point into the Identifi WoT for many people.

Serialize in BSON to improve efficiency and enable embedded binary (images etc)? It's also a canonical format unlike JSON by default.