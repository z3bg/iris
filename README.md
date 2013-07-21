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

	[
		<timestamp>,
		<dictionary of message sender's identifiers>,
		<list of message recipients or topics>,
		<message content>
	]

Example:

    [
    	1373924495,
	    { 	name:'Alice Smith', mbox:'mailto:alice@example.com'},
		[
	    	{ 	nick:'Bob the Builder',
	    		homepage:'http://twitter.com/bob',
	    		homepage:'http://www.facebook.com/bob',
	    		depiction:'magnet:<photo hash>?xs=http://example.com/1.jpg'},
	    	{	responseTo:'magnet:<hash of bob's message>'}
		],
    	'Bought a laptop from Bob. Thanks for the trade! #positive #trade'
	]

Messages and identifiers are to be stored locally in a hash table (or maybe later in a DHT). These hashes can be refered to with magnet URIs.

Messages are digitally signed by the entity that verifies that the message originated from the claimed sender. For example, this could be a website where the sender logged in with a Facebook account, or a crawler that read the sender's message from Twitter.

Message encoding is UTF-8.