+++
title = 'Stealing your Telegram account in 10 seconds flat'
date = 2024-04-29T16:00:00Z
draft = false
tags = ['infosec','telegram']
slug = "stealing-your-telegram-account-in-10-seconds-flat"
+++

If you handed me your phone, what's the worst I could do in 10 seconds?

<div class="tgThread">
	<!-- This is all handcrafted HTML & CSS :3 -->
	<div class="tgMsg tgMsgSmBL"><a href="https://web.telegram.org/">Web.telegram.org</a><span class="tgMsgTs">edited 23:51</span></div>
	<div class="tgMsg tgMsgSmTL tgMsgNoneBL"><span>Click that link and your browser will be logged into telegram without passwords</span><span class="tgMsgTs">23:52</span></div><div class="tgMsgSpeech"><div></div></div>
</div>

The other day I received an interesting message with a link to [Telegram's web client](https://web.telegram.org). Upon clicking on the link, I was greeted by the client, already logged in. Curious, I sent a message with the same link, clicked on it, and found myself logged in once again. There wasn't anything special about the link I had been sent, this is just Telegram's default behavior.

I wanted to find out how this works. The first step was to figure out how the Telegram client was passing the session to the browser. As I clicked on the link, I noticed something flash on the URL bar for just a split second:

<div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span style="color:#E3E3E3">web.telegram.org</span>/#tgWebAuthToken=dGhpcyB0b2tlbiBpcyByYW5kb20gYW5kIDEwMjQgYml0cyBsb25nLCBidXQgaW4gdGhlIGJsb2cgcG9zdCBpIHJlcGxhY2VkIGl0IHdpdGggdGhpcyBmdW4gZWFzdGVyIGVnZyBmb3IgdGhvc2Ugd2l0aCBhIGtlZW4gZXllIQ&tgWebAuthUserId=420493337&tgWebAuthDcId=4</span></div></div>

It seems like Telegram just opens up a URL with your account's token appended to it. The token gets put in a hash fragment, and quickly disappears once the web client loads up and realizes there's a token there. Although very convenient, this feature is pretty concerning because it can be used to quickly gain access to your account even if you use 2FA and a locked-down device (eg *non-rooted/jailbroken* phone).

So where does this URL and its session come from? I searched [tdesktop](https://github.com/telegramdesktop/tdesktop)'s[^1] code for various keywords such as "web.telegram.org" and "tgWebAuthToken", but weirdly enough I didn't get any results. After looking at the code for a bit, I could't find anything related to this feature, so I decided to build the app and attach a debugger to it.

After a couple hours of setting up and compiling my very own build of tdesktop

topics:

- didn't find it in grep, compiled the client
- go over the session token generation process
- show domains list in visual studio (z.t.me share trick)
- token expiration time (1 minute)
- 10 second domain/demo
- works on mobile
- web.telegram.org/_ trick
- failed attempt: web clients (foiled by the ampersand)
- failed attempt: android protocol hijack
- bonus: [web.telegram.org.](https://web.telegram.org.) to access old client

Discuss this post on: twitter, mastodon, hackernews, cohost

<!-- ![Sample Image](image.jpg) -->
[^1]: tdesktop is the official cross-platform desktop client (Telegram Lite on macOS)

<style>
	.urlBar {
		background: #3C3C3C;
		height: 34px;
		width: calc(100% - 12px);
		padding: 6px;
		border-radius: 4px;
		font-family: system-ui, sans-serif;
		font-size: 14px;
	}
	.urlBarInner *::selection {
		color: #000;
		background-color: #A8C7FA;
	}
	.urlBarInner {
		background: #282828;
		color: #C7C7C7;
		height: 34px;
		border-radius: 34px;
		width: 100%;
		line-height: 22px;
	}
	.urlBarText {
		text-overflow: ellipsis;
		overflow:hidden;
		white-space:nowrap;
		display:inline-block;
		margin-left:37px;
		width: calc(100% - 36px - 16px);
		margin-top: 6px;
	}
	.urlBarIcon {
		width: 16px;
		height: 16px;
		margin: 5px;
		color: #E3E3E3;
		fill: #E3E3E3;
		background: #3C3C3C;
		padding: 4px;
		position: absolute;
		display:block;
		border-radius: 24px;
	}
	.tgMsg *::selection {
		background-color: #2E70A5;
	}
	.tgThread {
		font-family: "Open Sans", system-ui, sans-serif;
		font-size: 12.75px;
		background: #0E1621;
		padding: 8px;
		border-radius: 4px;
		width: fit-content;
	}
	.tgMsg {
		background: #182533;
		color: #F5F5F5;
		border-radius: 16px;
		max-width: 410px;
		padding: 8px 8px 8px 11px;
		margin: 2px;
		width: fit-content;
	}
	.tgMsgSmTL {
		border-top-left-radius: 6px;
	}
	.tgMsgSmBL {
		border-bottom-left-radius: 6px;
	}
	.tgMsgNoneBL {
		border-bottom-left-radius: 0;
	}
	.tgMsg a {
		color: #70BAF5;
		text-decoration: none;
	}
	.tgMsgTs {
		margin-top: 5px;
		float: right;
		margin-left: 12px;
		color: #6D7F8F;
		user-select: none;
	}
	.tgMsgSpeech {
		background: #182533;
		width: 8px;
		height: 8px;
		position: absolute;
		transform: translate(-6px, -10px);
	}
	.tgMsgSpeech > div {
		background: #0E1621;
		width: 8px;
		height: 8px;
		border-bottom-right-radius: 8px;
	}
</style>