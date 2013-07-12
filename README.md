Identifi
========

http://identifi.org

by [Martti Malmi](http://github.com/mmalmi)

About
-----

WIP. 

Developing a prototype on Bitcoin code. The prototype uses a Bitcoin-like flooding network where all data is sent to every node. Later on, a social network based DHT such as [Whanau](http://pdos.csail.mit.edu/papers/whanau-nsdi10-abstract.html) could be used for distributed data storage and retrieval.

Building
--------

Makefile.unix builds nicely with dependencies from Debian packages (same as Bitcoin + sqlite).

Other makefiles TBD.

License
-------

Identifi is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.

Data format
-----------

Suggested data format for Identifi messages:

    [GMT timestamp] [list of message sender's identifiers] [list of message target/topic identifiers] message content

Messages may contain #hashtags and @identifiers.

    1373924495 ['Alice Smith', 'alice@example.com'] ['Bob the Builder', 'http://twitter.com/bob'] Bought a laptop from Bob. Thanks for the trade! #positive #trade

Messages and identifiers are to be stored locally in a hash table (or maybe later in a DHT). These hashes can be used as message topics or with @ in the message content.

    1373924495 user@twitter.com:bob [hash of Alice's message] #positive

Messages are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a Twitter crawler.

Message encoding is UTF-8.