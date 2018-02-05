Identifi
========

Available at:
* https://identi.fi
* https://identifi.github.io/
* https://ipfs.io/ipns/identi.fi/
* https://ipfs.io/ipns/QmaiM39ABfBEkb1ajyZ9ebfJXYgfyDNNbUaVZSwezwwoDQ/
* [Chrome extension](https://chrome.google.com/webstore/detail/identifi/oelmiikkaikgnmmjaonjlopkmpcahpgh) ([mirror](https://github.com/identifi/identifi-angular/raw/master/dist.crx))

Code:
- https://github.com/identifi/identifi-daemon Maintains identity & message indexes on [IPFS](https://github.com/ipfs/ipfs)
- https://github.com/identifi/identifi-cli Command line interface for using local or remote Identifi nodes
- https://github.com/identifi/identifi-lib Library for talking to an Identifi node. Used by the previous.
- https://github.com/identifi/identifi-angular AngularJS interface. Served by identifi-daemon at http://localhost:4944 if available.
- https://github.com/identifi/identifi-node Node package that bundles all the previous.

Todo list: https://trello.com/b/8qUutkmP/identifi

What
----
- Concept: https://medium.com/@mmalmi/learning-to-trust-strangers-167b652a654f
- Global address book
- Anyone can edit and verify contact details
- Users can give each other eBay-style reviews and trust ratings
- Filter all information by its author's position in your web of trust
  - For example, only show the content created by your friends and the people they trust
- Decentralized - data is stored and indexed on the devices of its users (on [IPFS](https://github.com/ipfs/ipfs)). Compares to a phone's address book or a local DNS cache.
- API for integration with various trust or identity dependent applications

Why
---
- Keep your contact details, payment addresses etc. up-to-date and verified
- Makes it possible to trust people you have never met
  - Utilize your good reputation in various services and situations
  - Reduces risk of trade or loan, thus reducing cost
- Prevent spam (by accepting messages only from trusted / socially connected senders)
- Prevent fake accounts used for commercial or propaganda purposes
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
- Identifi message: [author identifiers, recipient identifiers, message][signatures]
  - Identified by content hash
  - Signed by the entity which verified that the message originates from the named author. Thus, all end users need not to have a crypto key of their own.
  - Encoded and signed as [JSON Web Tokens](https://jwt.io/)
- Messages are stored and indexed locally in an SQL database
  - Nodes maintain their own trust indexes which are updated as new messages arrive
  - Message storage priority is based on its author's and signer's position in the node's web of trust
  - Messages and indexes are also globally stored on IPFS
    - Can be used in serverless mode
    - [btree](https://github.com/mmalmi/merkle-btree) indexes
- Crawl initial data from existing social networks and review systems

Possible applications
---------------------
- Facial recognition and identifi-cation with a AR glasses
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
