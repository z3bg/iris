# Iris

Available at:
* [iris.to](https://iris.to)
* [iris.cx](https://iris.cx)
* [irislib.github.io](https://irislib.github.io)
* Browser extension: use Iris even if you are offline. In the future, can be used to sign in to websites.
  * [Chrome](https://chrome.google.com/webstore/detail/iris/oelmiikkaikgnmmjaonjlopkmpcahpgh)
  * [Firefox](https://addons.mozilla.org/en-US/firefox/addon/irisapp/)

Code:
- https://github.com/irislib/iris-lib Library for reading and writing Iris messages and indexes
- https://github.com/irislib/iris-angular Angular UI for web, browser extensions and Electron app

_Note: Iris is still **experimental** software._

---

**Want social media where _you_ decide what gets into your feed, not some obscure algorithm? Something that can't be censored by authoritarian governments? No big tech companies that decide what you can post, what gets visibility and who gets to have an account? Yet no harassing troll accounts, spam or ads? Something that works locally even if ISPs are unavailable in an emergency situation?**

Here comes Iris. Iris is a social networking application that stores and indexes everything on the devices of its users and connects directly with peers who run the application - no corporate gatekeepers needed.

## Public messaging
Interface-wise, Iris is not too different from some existing social media. You can post texts, photos, videos, audio or other types of files into your feed.

![Feed](https://github.com/irislib/iris/raw/master/img/feed.png)

At the time of writing this, Iris supports only public messaging.

## Web of trust
You can create new Iris accounts (technically: cryptographic keypairs) at will, without asking for anyone's permission, but only the users whose web of trust upvoted your account will see its posts.

When you upvote someone, they become your 1st degree contact. The accounts they upvoted become 2nd degree contacts. Then there are 3rd degree contacts and so on. This is the web of trust, which can be used to filter all content on Iris. Hiding users by downvoting is also possible.

**This way we can avoid spam and other unwanted content without giving power to central moderators.**

You can also add to your contacts list and rate people and organisations who are not yet on Iris.
A decentralised web of trust, unlike certain big brother systems, could be a strong positive social force as envisioned in the blog post [Learning to Trust Strangers](https://medium.com/@mmalmi/learning-to-trust-strangers-167b652a654f). (Iris is evolved from thereby mentioned Identifi.)

## Identity verifications
Keep your contact details up-to-date and ask for verifications from peers or specialised verifiers trusted by your WoT. Use your Iris account for online authentication or identification on services that support it.

If you lose access to your account (keypair), just create a new one and link it to your existing identity by asking for verifications from your web of trust.

## Importing content from existing sources
An Iris message is digitally signed by the entity that verified its origin. In other words: message author and signer can be different entities, and only the signer needs to be on Iris.

For example, a crawler can import and sign other people's messages from Twitter. Only the users who trust the crawler will see the messages.

![Feed](https://github.com/irislib/iris/raw/master/img/msg.png)
*A message imported from the bitcoin trading site bitcoin-otc.com by "Bitcoin-otc.com crawler".*

Importing content from existing sources helps overcome the network effect. It solves the chicken and egg problem, making Iris a useful medium even with no initial user base.

## Tech stack
Iris messages and contacts are stored and indexed on [GUN](https://gun.eco). [IPFS](https://ipfs.io) is used to store file attachments and message backups. Both are decentralised networks that run in the browser.

The [browser application](https://github.com/irislib/iris-angular) runs on AngularJS. [Iris-lib](https://github.com/irislib/iris-lib) is written in javascript for the browser and Node.js.

## Improving decentralisation
Currently the weak point of Iris's decentralisation is the list of initial peers, which could easily be blocked by governments or ISPs. By default, the application connects to IPFS default peers and a couple GUN peers. You can always add peers manually on the [settings page](https://irislib.github.io/#settings), but that is cumbersome for the average user.

We already have a multicast module prototype for GUN which can find peers on the same local area network. Bluetooth modules are not yet implemented, but will enable a network of peers that need to meet each other only occasionally.

On the wide area network level, trusted contacts could exchange network addresses privately to avoid having them blocked or tracked. WebRTC's NAT traversal capabilities can enable direct connections between typical network endpoint users, but you still need a firewall-opened/port-forwarded rendez-vous node for them, and in some cases a relay node.

## How to help
If you like the idea, please [create an Iris account](https://iris.to) and **share your profile link on your existing social networks**!

Currently the application is glitchy and slower than the technology allows, but it should give an idea of the intended functionality. Contributions to the [browser application](https://github.com/irislib/iris-angular) and the underlying [iris-lib](https://github.com/irislib/iris-lib) are very much appreciated.

If you want to integrate Iris with your product or service, please check out [iris-lib](https://github.com/irislib/iris-lib) and create Github issues if needed.

## License

Iris is released under the terms of the MIT license. See `COPYING` for more information or see http://opensource.org/licenses/MIT.

---

![The Greek goddess Iris](https://upload.wikimedia.org/wikipedia/commons/7/7b/Venus_supported_by_Iris%2C_complaining_to_Mars_1820.jpg)
*Iris (middle): Greek goddess of the rainbow and messenger of the gods.*
