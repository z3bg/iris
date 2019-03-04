Iris
========

Available at:
* https://iris.cx
* https://iris.to
* https://irislib.github.io
* [Chrome extension](https://chrome.google.com/webstore/detail/identifi/oelmiikkaikgnmmjaonjlopkmpcahpgh)
* [Firefox extension](https://addons.mozilla.org/en-US/firefox/addon/identifi/)

Code:
- https://github.com/irislib/iris-lib Library for reading and writing Iris messages and indexes
- https://github.com/irislib/iris-angular Angular UI for web, browser extensions and Electron app

What
----
- Concept: https://medium.com/@mmalmi/learning-to-trust-strangers-167b652a654f
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
- Iris message: {signedData: {author, recipient, comment, ...}, sig}
  - Identified by content hash
  - Signed by the entity which verified that the message originates from the named author. Thus, all end users need not to have a crypto key of their own.
- Crawl initial data from existing social networks and review systems

Possible applications
---------------------
- Facial recognition and identification with a AR glasses
  - Thumbs up to the friendly bus driver, policeman or the stranger who helped you
- Mywot.com-style browser plugin for website reviews
- Bitcoin UIs, connect addresses to identities or vice versa
- Email plugin
  - Generate trusted senders list from email history
  - Require new senders to be on Iris - send automatic response if not
- Decentralized marketplaces, P2P trade and finance
  - Check escrow or trader reputation
  - Airbnb, eBay, Uber, LocalBitcoins etc.
  - Time banking, gift economy
- Uncensored and sockpuppet-resistant reviews and recommendations for products, restaurants etc.
- Public messaging, automatically show or hide authors
- Social network based routing protocols
- Decentralized alternative to DNS - let your WoT decide which IP a name maps to


Contributing
------------

Please do **integrate** [iris-lib](https://github.com/irislib/iris-lib) with your existing application or with a test application and **create Github issues** for the bugs and other problems you may encounter. Your help is much appreciated!

License
-------

Iris is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.
