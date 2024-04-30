+++
title = 'Stealing your Telegram account in 10 seconds flat'
date = 2024-04-29T16:00:00Z
draft = false
tags = ['infosec','telegram']
slug = "stealing-your-telegram-account-in-10-seconds-flat"
+++

Say you handed me your phone, what's the worst I could do in 10 seconds?

<div class="tgThread">
	<!-- This is all handcrafted HTML & CSS :3 -->
	<div class="tgMsg tgMsgSmBL"><a href="https://web.telegram.org/">Web.telegram.org</a><span class="tgMsgTs" aria-hidden="true">edited 23:51</span></div>
	<div class="tgMsg tgMsgSmTL tgMsgNoneBL"><span>Click that link and your browser will be logged into telegram without passwords</span><span class="tgMsgTs" aria-hidden="true">23:52</span></div><div class="tgMsgSpeech"><div></div></div>
</div>

The other day I received an interesting message with a link to [Telegram's web client](https://web.telegram.org). Upon clicking on the link, I was greeted to the client, already logged in. Curious, I sent myself a message with the same link, clicked on it, and found myself logged in once again. There wasn't anything special about the link I had been sent, this is just Telegram's default behavior.

I wanted to find out how this works. The first step was to figure out how the Telegram client was passing the session to the browser. As I clicked on the link, I noticed something flash on the URL bar for just a split second:

<div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span style="color:#E3E3E3">web.telegram.org</span>/#tgWebAuthToken=dGhpcyB0b2tlbiBpcyByYW5kb20gYW5kIDEwMjQgYml0cyBsb25nLCBidXQgaW4gdGhlIGJsb2cgcG9zdCBpIHJlcGxhY2VkIGl0IHdpdGggdGhpcyBmdW4gZWFzdGVyIGVnZyBmb3IgdGhvc2Ugd2l0aCBhIGtlZW4gZXllIQ&tgWebAuthUserId=420493337&tgWebAuthDcId=4</span></div></div>

It seems like Telegram just opens up a URL with your account's token appended to it. The token gets put in a hash fragment, and quickly disappears once the web client loads up and realizes there's a token there. Although very convenient, this feature is pretty concerning because it can be used to quickly gain access to your account even if you use 2FA and a locked-down device (eg a *non-rooted/jailbroken* phone).

So where does this URL and its session come from? I searched tdesktop[^1]'s code for various keywords such as "web.telegram.org" and "tgWebAuthToken", but oddly enough I didn't get any hits. After staring at the code and not finding anything related to this feature for a while, I decided to build the app for real and attach a debugger to it.

A couple hours of compiling later, I had my very own build of tdesktop up and running. I set up a few breakpoints, clicked on the link, and stepped through the code until I found the relevant bits. And eventually, I was here:

<div class="vsContainer">
	<div class="vsTabs"><span class="vsTab active">ui_integration.cpp<svg style="position:absolute;width:16px;height:16px;padding-left:27px" xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none"><polygon points="4 8 7 8 7 5 8 5 8 6 12 6 12 11 8 11 8 9 11 9 11 7 8 7 8 12 7 12 7 9 4 9"/></svg></span><span class="vsTab">base_integration.cpp</span><span class="vsTab">url_auth_box.cpp</span></div>
	<div class="vsBox" style="border-top: none; height: fit-content">
		<div aria-hidden="true">
		<span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#C16FCC"><rect fill="#454545" stroke="#B9B9B9" x="1.5" y="2.5" width="13" height="11"/><line x1="5.5" x2="5.5" y1="4" y2="9"/><line x1="8" x2="3" y1="6.5" y2="6.5"/><line x1="10.5" x2="10.5" y1="7" y2="12"/><line x1="13" x2="8" y1="9.5" y2="9.5"/></svg>Telegram<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span><span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#DEDEDE" stroke-linecap="square"><path d="m4.6 2.5c-0.7 0-1 0.4-1 1v3l-0.8 1v1l0.8 1v3c0 0.7 0.3 1 1 1"/><path d="m11.5 13.5c0.7 0 1-0.4 1-1v-3l0.8-1v-1l-0.8-1v-3c0-0.7-0.3-1-1-1"/></svg>Core::`anonymous-namespace'<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span><span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="#474152" stroke="#9670C6" stroke-linejoin="round"><polyline class="st0" points="13.5 5 13.5 12.1 8 14.6 8 7.7 13.5 5 8 2 2.4 5 8 7.7 8 14.6 2.4 11.7 2.4 5"/></svg>BotAutoLogin(const QString & url, const QString & domain,<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span>
	</div>
	<div style="height: 374px"><span style="width: 17px;display:inline-block;background:#333;height:100%"><div style="height:1px"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint active"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div></span><span class="vsCodeArea" style="width: calc(100% - 17px);display:inline-block;background:#1E1E1E;height:100%"><!-- This part (the syntax highlight) was really annoying to do manually, I wouldn't recommend doing it yourself. --><span class="vLn">   79     </span>
<span class="vLn">   80     </span><span class="vC5">[[<span class="vCA">nodiscard</span>]] </span><span class="vC2">bool </span><span class="vC0">BotAutoLogin</span><span class="vC5">(</span>
<span class="vLn">   81     </span>        <span class="vC2">const </span><span class="vC1">QString </span><span class="vC5">&amp;<span class="vC3">url</span>,</span>
<span class="vLn">   82     </span>        <span class="vC2">const </span><span class="vC1">QString </span><span class="vC5">&amp;<span class="vC3">domain</span>,</span>
<span class="vLn">   83     </span>        <span class="vC1">QVariant </span><span class="vC3">context</span><span class="vC5">) </span><span class="vC5">{</span>
<span class="vLn">   84     </span>    <span class="vC2">auto </span><span class="vC5">&amp;<span class="vC4">account </span>= </span><span class="vC7">Core</span><span class="vC5">::<span class="vC0">App</span>().</span><span class="vC0">activeAccount</span><span class="vC5">();</span>
<span class="vLn">   85     </span>    <span class="vC2">const auto </span><span class="vC5">&amp;<span class="vC4">config </span>= </span><span class="vC4">account</span><span class="vC5">.<span class="vC0">appConfig</span>();</span>
<span class="vLn">   86     </span>    <span class="vC2">const auto </span><span class="vC4">domains <span class="vC5">= </span>config</span><span class="vC5">.<span class="vC0">get</span>&lt;</span><span class="vC7">std</span><span class="vC5">::<span class="vC1">vector</span>&lt;</span><span class="vC1">QString</span><span class="vC5">&gt;&gt;(</span>
<span class="vLn">   87     </span>        <span class="vCB">&quot;<span class="vC8">url_auth_domains</span>&quot;</span><span class="vC5">,</span>
<span class="vLn">   88     </span>        <span class="vC5">{});</span>
<span class="vLn">   89     </span>    <span class="vC9">if </span><span class="vC5">(!<span class="vC4">account</span>.</span><span class="vC0">sessionExists</span><span class="vC5">()</span>
<span class="vLn">   90     </span>        <span class="vC5">|| <span class="vC3">domain</span>.</span><span class="vC0">isEmpty</span><span class="vC5">()</span>
<span class="vLn">   91     </span>        <span class="vC5">|| </span><span class="vC5">!<span class="vC7">ranges</span>::</span><span class="vC7">contains</span><span class="vC5">(<span class="vC4">domains</span>, </span><span class="vC3">domain</span><span class="vC5">)) {</span>
<span class="vLn">   92     </span>        <span class="vC9">return </span><span class="vC2">false</span><span class="vC5">;</span>
<span class="vLn">   93     </span>    <span class="vC5">}</span>
<span class="vLn">   94     </span>    <span class="vC2">const auto </span><span class="vC4">good </span><span class="vC5">= <span class="vC3">url</span>.</span><span class="vC0">startsWith</span><span class="vC5">(<span class="vC7">kBadPrefix</span>, </span><span class="vC7">Qt</span><span class="vC5">::<span class="vC6">CaseInsensitive</span>)</span> 
<span class="vLn">   95     </span>        <span class="vC5">? </span><span class="vC5">(<span class="vC7">kGoodPrefix </span>+ </span><span class="vC3">url</span><span class="vC5">.<span class="vC0">mid</span>(</span><span class="vC7">kBadPrefix</span><span class="vC5">.<span class="vC0">size</span>()))</span>
<span class="vLn">   96     </span>        <span class="vC5">: <span class="vC3">url</span>;</span>
<span class="vLn">   97     </span>    <span class="vC1">UrlAuthBox</span><span class="vC5">::<span class="vC0">Activate</span>(&amp;</span><span class="vC4">account</span><span class="vC5">.<span class="vC0">session</span>(), </span><span class="vC4">good</span><span class="vC5">, <span class="vC3">context</span>);</span>
<span class="vLn">   98     </span>    <span class="vC9">return </span><span class="vC2">true</span><span class="vC5">;</span>
<span class="vLn">   99     </span><span class="vC5">}</span>
<span class="vLn">  100     </span> <!----></span>
</span></div>
	</div>
<div style="height:6px"></div>
<div class="vsBox" style="height: fit-content">
<div style="padding:2px 0 0 4px;color:#B2B2B2;user-select:none">Locals</div>
<div class="vsLocals">
	<table>
    	<colgroup>
    	   <col span="1" style="width: 35%">
    	   <col span="1" style="width: 35%">
    	   <col span="1" style="width: 20%">
    	</colgroup>
		<thead>
			<tr>
				<th>Name</th>
				<th>Value</th>
				<th>Type</th>
			</tr>
		</thead>
		<tbody>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>Main::AppConfig::get&lt;std::vector&lt;QString,std::allocator&lt;QString&gt; &gt; &gt; returned</td>
	<td>{ size=5 }</td>
	<td>std::vector&lt;QString,std::allocator&lt;QString&gt;&gt; &amp;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>account</td>
	<td>{_domain={ptr_=0x000001b3822c5990 {_dataName={...} _local={...} _accounts={...} ...} } _local=unique_ptr {_owner={ptr_=0x000001b3887a6dd0 {_domain={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={ptr_=0x000001b3822c5990 {_dataName=data _local=unique_ptr {_owner={...} _dataName=data _localKey=shared_ptr  [2 strong refs] [] ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} ...} } ...} } ...} ...}</td>
	<td>Main::Account &amp;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#55AAFF"><rect fill="#323232" stroke="#E0E0E0" x="2.5" y="3.5" width="10" height="10"/><line x1="10" x2="5" y1="7.5" y2="7.5"/><line x1="10" x2="5" y1="9.5" y2="9.5"/></svg>config</td>
	<td>{_account={ptr_=0x000001b3887a6dd0 {_domain={...} _local={...} _mtp={...} ...} } _api={_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr {_instance={ptr_=0x000001b3886a1b40 {_private=unique_ptr } } _mode=Normal (0) _config=unique_ptr {_dcOptions={...} _fields={...} _updates={...} } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} } } ...} ...}</td>
	<td>const Main::AppConfig &amp;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>context</td>
	<td>{...}</td>
	<td>QVariant</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#55AAFF"><rect fill="#323232" stroke="#E0E0E0" x="2.5" y="3.5" width="10" height="10"/><line x1="10" x2="5" y1="7.5" y2="7.5"/><line x1="10" x2="5" y1="9.5" y2="9.5"/></svg>domain</td>
	<td>z.t.me</td>
	<td>const QString &amp;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="#E0E0E0" stroke="none"><path d="M11,9.5V5.2c0-0.4-0.5-0.7-0.9-0.4L5.9,9.1C5.5,9.5,5.8,10,6.2,10h4.3C10.8,10,11,9.8,11,9.5z"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>domains</td>
	<td>{ size=5 }</td>
	<td>std::vector&lt;QString,std::allocator&lt;QString&gt;&gt;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#3F3C44" stroke="#9670C6" stroke-linejoin="round"><polyline class="st0" points="13.5 5 13.5 12.1 8 14.6 8 7.7 13.5 5 8 2 2.4 5 8 7.7 8 14.6 2.4 11.7 2.4 5"/></svg>[capacity]</td>
	<td>5</td>
	<td>unsigned __int64</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[allocator]</td>
	<td>allocator</td>
	<td>std::_Compressed_pair&lt;std::allocator&lt;QString&gt;,std::_Vector_val&lt;std::_Simple_types&lt;QString&gt;&gt;,1&gt;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[0]</td>
	<td>web.telegram.org</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[1]</td>
	<td>web.t.me</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[2]</td>
	<td>k.t.me</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[3]</td>
	<td>z.t.me</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[4]</td>
	<td>a.t.me</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0 0 0 17px" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>[Raw View]</td>
	<td>{_Mypair=allocator }</td>
	<td>std::vector&lt;QString,std::allocator&lt;QString&gt;&gt;</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="#293644" stroke="#54A6F9"><polygon class="st0" points="10.4 1.5 14.5 5.6 14.5 9.6 5.6 15 1.5 11.4 1.5 6.4"/><polyline fill="none" points="1.8 6.7 5.4 10.4 5.4 14.6 5.4 10.4 14.5 5.6"/></svg>good</td>
	<td>???</td>
	<td>QString</td>
</tr>
<tr>
	<td><svg xmlns="http://www.w3.org/2000/svg" style="padding:0" fill="none" stroke="#E0E0E0" stroke-linejoin="round"><polygon points="9.5 8 6.5 5 6.5 11"/></svg><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#55AAFF"><rect fill="#323232" stroke="#E0E0E0" x="2.5" y="3.5" width="10" height="10"/><line x1="10" x2="5" y1="7.5" y2="7.5"/><line x1="10" x2="5" y1="9.5" y2="9.5"/></svg>url</td>
	<td>https://z.t.me</td>
	<td>const QString &amp;</td>
</tr>
		</tbody>
	</table>
</div>
</div>
</div>

So that's why I couldn't find the keywords! The list of domains this trick works with is sent to you by the Telegram server and stored in the config under the `url_auth_domains`[^2] key.

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

<!-- 
messages.requestUrlAuth#198fb446 flags:# peer:flags.1?InputPeer msg_id:flags.1?int button_id:flags.1?int url:flags.2?string = UrlAuthResult;

messages.acceptUrlAuth#b12c7125 flags:# write_allowed:flags.0?true peer:flags.1?InputPeer msg_id:flags.1?int button_id:flags.1?int url:flags.2?string = UrlAuthResult;

urlAuthResultRequest#92d33a0e flags:# request_write_access:flags.0?true bot:User domain:string = UrlAuthResult;
urlAuthResultAccepted#8f8c0e4e url:string = UrlAuthResult;
urlAuthResultDefault#a9d6db1f = UrlAuthResult;
-->
<!-- ![Sample Image](image.jpg) -->
[^1]: [tdesktop](https://github.com/telegramdesktop/tdesktop) is the official cross-platform desktop client (Telegram Lite on macOS)
[^2]: `url_auth_domains` is used for 

<style>
	.vsLocals svg {
		width: 16px;
		height: 16px;
		vertical-align: bottom;
		padding-left: 2px;
		padding-right: 4px;
	}
	.vsLocals th {
		font-weight: normal;
		text-align: left;
  		border: 1px solid #3D3D3D;
  		border-top: none;
  		border-left: none;
  		padding-left: 4px;
  		user-select: none;
	}
	.vsLocals td {
  		border: 1px solid #000;
  		border-top: none;
  		border-left: none;
  		padding: 0 0 0 3px;
		text-overflow: ellipsis;
		overflow: hidden;
		white-space: nowrap;
		max-width: 0;
		user-select: all;
	}
	.vsLocals > table {
		border-collapse: collapse;
		box-model: border-box;
		line-height: 16px;
		width: 100%;
		cursor: default;
	}
	.vsLocals > table *::selection {
		background: #7160E8;
	}
	.vsBreakpoint {
		width: 12px;
		height: 12px;
		background: #B7B7B7;
		border: 0.5px solid #DDD;
		border-radius: 14px;
		margin: 3px 0 2px 2px;
		opacity: 0;
	}
	.vsBreakpoint:hover {
		opacity: 1;
	}
	.vsBreakpoint.active {
		background: #C55159;
		border-color: #EF5B64;
		opacity: 1;
	}
	.vC1 { color: #4EC9B0 }
	.vC2 { color: #569CD6 }
	.vC3 { color: #9A9A9A }
	.vC4 { color: #9CDCFE }
	.vC5 { color: #B4B4B4 }
	.vC6 { color: #B8D7A3 }
	.vC7 { color: #C8C8C8 }
	.vC8 { color: #D69D85 }
	.vC9 { color: #D8A0DF }
	.vC0 { color: #DCDCAA }
	.vCA { color: #DCDCDC }
	.vCB { color: #E8C9BB }
	.vLn {
		user-select: none;
		cursor: default;
	}
	.vsCodeArea > span:hover {
		background: #2e2237;
	}
	.vsCodeArea::-webkit-scrollbar {
	  width: 10px;
	}
	.vsCodeArea::-webkit-scrollbar-track {
	  background: #2E2E2E;
	}
	.vsCodeArea::-webkit-scrollbar-thumb {
	  background: #4D4D4D; 
	}
	.vsCodeArea::-webkit-scrollbar-thumb:hover {
	  background: #999; 
	}
	.vsCodeArea::selection, .vsCodeArea *::selection  {
		background: #264F78;
	}
	.vsCodeArea {
		vertical-align: bottom;
		font-family: "Cascadia Code", "Cascadia Mono", "Lucida Sans Typewriter", "Courier New", monospace;
		white-space: pre-wrap;
		font-size: 13px;
		line-height: 17px;
    	display: inline-block;
    	color: #8A8A8A;
		text-wrap: nowrap;
    	overflow: auto;
    	overflow-y: hidden;
    	cursor: text;
	}
	.vsContainer {
		background: #1F1F1F;
		color: #FAFAFA;
		width: calc(100% - 8px);
		height: fit-content;
		border-radius: 4px;
		padding: 4px;
		font-family: system-ui, sans-serif;
		font-size: 12px;
		line-height: 16px;
	}
	.vsBox {
		border: 1px solid #3D3D3D;
		overflow: hidden;
		white-space:nowrap;
	}
	.vsDropdown {
		background: #383838;
		height: 18px;
		padding-top: 1px;
		border: 1px solid #424242;
		border-right: 4px solid #424242;
		width: 352px;
		display: inline-block;
		user-select: none;
	}
	.vsDropdown > svg {
		width: 16px;
		height: 16px;
		vertical-align: bottom;
		padding-left: 2px;
		padding-right: 3px;
	}
	.vsDropdown:hover {
		background: #3D3D3D;
	}
	.vsTabs {
		width: 100%;
		height: 21px;
		border-bottom: 2px #7160E8 solid;
		user-select: none;
		margin-left: 1px;
		overflow: hidden;
		white-space:nowrap;
	}
	.vsTab:hover {
		background: #3D3D3D;
		color: #FAFAFA;
	}
	.vsTab {
		display: inline-block;
		height: 16px;
		background: #2E2E2E;
		color: #B2B2B2;
		padding: 0 43px 3px 4.5px;
		margin: 1px 1px 0;
	}
	.vsTab.active {
		border-top: 2px #7160E8 solid;
		box-sizing: border-box;
		height: 20px;
		vertical-align: bottom;
		color: #FAFAFA;
		background: #3D3D3D;
		font-weight: 600;
		margin: 1px 0px 0;
		padding: 0 45px 3px 4.5px;
	}
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
	.urlBarIcon svg {
		width: 16px;
		height: 16px;
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