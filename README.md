Identifi
========

http://identifi.org

IRC: [#identifi](https://webchat.freenode.net/?channels=identifi&uio=d4) on Freenode

Identifi & [identifi-js](https://github.com/identifi/identifi-js) in action: http://identi.fi

**NOTE**: This is a proof-of-concept implementation, not ready for production. The [Node.js version](https://github.com/identifi/identifi-daemon) will be more refined:
- HTTP based networking and JSON serialization (incompatible with the old implementation)
- https://github.com/identifi/identifi-daemon Provides a REST API and communicates with other nodes
- https://github.com/identifi/identifi-cli Command line interface for using local or remote Identifi nodes
- https://github.com/identifi/identifi-lib Library for talking to an Identifi node. Used by the previous.
- https://github.com/identifi/identifi-js AngularJS interface. Currently proxies the old API via Express.

What
----
- Global address book
- Anyone can edit and verify contact details
- Users can give each other eBay-style reviews and trust ratings
- Filter all information by its author's position in your web of trust
  - For example, only show the content created by your friends and the people they trust
- Decentralized - data is stored and indexed on the devices of its users. Compares to a phone's address book or a local DNS cache.
- API for integration with various trust or identity dependent applications

Why
---
- Keep your contact details, payment addresses etc. up-to-date and verified
- Makes it possible to trust people you have never met
  - Utilize your good reputation in various services and situations
  - Reduces risk of trade or loan, thus reducing price
- Prevent spam (by accepting messages only from trusted / socially connected senders)
- Prevent astroturfing / sockpuppeting
- Provide identity verifications to people who lack official ID
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

License
-------

Identifi is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.
