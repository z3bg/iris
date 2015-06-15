Identifi
========

http://identifi.org

IRC: [#identifi](https://webchat.freenode.net/?channels=identifi&uio=d4) on Freenode

Identifi & [identifi-js](https://github.com/identifi/identifi-js) in action: http://identi.fi

**NOTE**: This is a proof-of-concept implementation, not ready for production. The Node.js version will be more refined:
- https://github.com/identifi/identifi-daemon Provides a REST API and communicates with other nodes
- https://github.com/identifi/identifi-cli/tree/develop Command line interface for using local or remote Identifi nodes
- https://github.com/identifi/identifi-lib/tree/develop Library for talking to an Identifi node. Used by the previous.
- https://github.com/identifi/identifi-js AngularJS interface. Currently proxies the old API via Express.

What
----
- "Address book where you can find anyone in the world"
- Anyone can edit, add and verify contact details
- Users can give each other eBay-style reviews and trust ratings
- Filter all information by its author's position in your web of trust
  - For example, only show the content created by your friends and the people they trust
- Decentralized - data is stored and indexed on the devices of its users
- API for integration with various trust or identity dependent applications

Why
---
- Keep your contact details, payment addresses etc. up-to-date and verified
- Makes it possible to trust people you have never met
  - Utilize your good reputation in various services and situations
  - Reduces risk of trade or loan, thus reducing price
- Prevent spam (by accepting messages only from trusted / socially connected senders)
- Prevent astroturfing / sockpuppeting
- Facilitate gift economy / time banking
- Distributed public messaging, with trust lists instead of centralized moderator power
- Censorship-resistance
- Open database, vs. proprietary information silos of reputation and online identity
  - No monopoly on credit ratings
- Ubiquitous reputation as non-violent, cost-effective and decentralized justice
  - Everyone can choose whose judgement or review to trust
  - Incentive against antisocial behavior
  - Incentive to restore trust by compensation and apology for misdeeds

How
---
- Prototype built on Bitcoin code to utilize existing crypto, network, CLI, etc. functions (but not blockchain)
- Data package: [author identifiers, recipient identifiers, message][signatures]
  - Identified by content hash
  - Signed by the entity which verified that the message originates from the named author. Thus, all end users need not to have a crypto key of their own.
- Flood packages throughout the network
  - Nodes maintain their own trust graphs which are updated as new messages arrive
  - Message storage priority is based on its author's and signer's position in the node's web of trust
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
- Decentralized alternative to DNS - let your WoT decide which IP a name maps to

Building
--------

    sudo apt-get install build-essential libssl-dev libboost-all-dev libminiupnpc-dev

You'll also need sqlite3 version 3.8.3 or later: http://www.sqlite.org/download.html (users with existing sqlite package may need to configure sqlite3 with `--disable-dynamic-extensions --enable-static`).

    git clone git://github.com/identifi/identifi.git
    cd ./identifi/src
    make -f makefile.unix

Other makefiles have not been tested.

Developing
----------
Core functionality of the implementation is in identifidb.cpp, data.cpp and rpcdb.cpp.

Get the daemon running with `./identifi -daemon`. Call the JSON-RPC with `./identifi rpccommand`. Rpc_tests.cpp shows how to use the RPC.

The program connects to seed nodes from DNS by default and requests for messages created after a certain timestamp. Identifi developers' ECDSA pubkey is included and trusted by default as an entry point to the WoT. You need to connect your own pubkey or other identifiers to the WoT if you want your messages prioritized over spam by other nodes.

The default database size limit 2 GB. Add `saveuntrustedmsgs=1` to DATADIR/identifi.conf to allow messages from outside your WoT for testing.

[Sqlite Manager](https://addons.mozilla.org/en-US/firefox/addon/sqlite-manager/) is a nice Firefox plugin for debugging DATADIR/db.sqlite.

License
-------

Identifi is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.

Data format
-----------

NOTE: [Json web signatures](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41) will be used in the [Node.js version](https://github.com/identifi/identifi-daemon).

Current Identifi message format:

```
{
    "signature": {
      "pubKey": "PA4oX2htY38kXuNVnvNxXHiSiafcfJJyxJntwfgx7tgisjVbuEZcb1v3V2dojuHkrRyfVNu9Xi24nFcSPEdEvLeN",
      "signature": "AN1rKpVZvbBCZBcpTMyT9eaEsby8gRoYeNwkf8osYHQKLddPiFaYgiyME1ZKKzkgJRutxzQA5R6FLGCy5rJYWZZ67egTRnXot"
    },
    "signedData": {
      "author": [
        [
          "keyID",
          "1DqrzTcimQp3Ye88oHgxdU7DBTsM2TRYFj"
        ]
      ],
      "comment": "Identifi developers' key, trusted by default",
      "maxRating": 1,
      "minRating": -1,
      "rating": 1,
      "recipient": [
        [
          "keyID",
          "147cQZJ7Bd4ErnVYZahLfCaecJVkJVvqBP"
        ],
        [
          "nickname",
          "Identifi dev key 1"
        ]
      ],
      "timestamp": 1409307849,
      "type": "rating"
    }
}
```

SignedData may optionally contain additional fields.

Messages are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a crawler that read the sender's message from Twitter.

Message encoding is UTF-8.

**NOTE**: Moving to [JSON Web Signatures](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature) in the Node.js version.


Future considerations
---------------------

Browser plugin & mobile app

Query messages from peers by trust viewpoint? "Send me the trust tree from [ID] with messages after [timestamp] as leaves." Would help counter spam and irrelevant content.

Use [Trsst](http://www.trsst.com) for data propagation and storage?

Use [Whanau DHT](http://pdos.csail.mit.edu/papers/whanau-nsdi10-abstract.html) for distributed storage and retrieval?

[Freenet](http://freenetproject.org) as data storage? Saving data is trivial, but efficient indexing needs some effort.

[ArangoDB](https://www.arangodb.org/) graph database? Could enable on-demand trust path finding and eliminate the need for caching them.

Use [GPGME](http://www.gnupg.org/related_software/gpgme) to integrate with PGP web of trust? Could provide a nice entry point into the Identifi WoT for many people.
