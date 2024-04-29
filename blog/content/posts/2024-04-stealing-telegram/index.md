+++
title = 'Stealing your Telegram account in 10 seconds flat'
date = 2024-04-29T16:00:00Z
draft = false
tags = ['infosec','telegram']
slug = "stealing-your-telegram-account-in-10-seconds-flat"
+++

If you handed me your phone, unlocked, what's the worst that I could do in 10 seconds?

The other day I received this message on Telegram:

<div class="tgThread">
	<!-- This is all handcrafted HTML & CSS :3 -->
	<div class="tgMsg tgMsgSmBL"><a href="https://web.telegram.org/">Web.telegram.org</a><span class="tgMsgTs">edited 23:51</span></div>
	<div class="tgMsg tgMsgSmTL tgMsgNoneBL">Click that link and your browser will be logged into telegram without passwords<span class="tgMsgTs">23:52</span></div><div class="tgMsgSpeech"><div></div></div>
</div>

It was just a link to Telegram's web client, but to my surprise, it did in fact do exactly what was told.

<!-- ![Sample Image](image.jpg) -->

<style>
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