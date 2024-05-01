+++
title = 'Stealing your Telegram account in 10 seconds flat'
date = 2024-05-01T16:00:00Z
draft = false
tags = ['infosec','telegram']
slug = "stealing-your-telegram-account-in-10-seconds-flat"
summary = "Say you handed me your phone, what’s the worst I could do in 10 seconds?"
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

<div class="vsContainer" draggable="false">
	<div class="vsTabs"><span class="vsTab active">ui_integration.cpp<svg style="position:absolute;width:16px;height:16px;padding-left:27px" xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none"><polygon points="4 8 7 8 7 5 8 5 8 6 12 6 12 11 8 11 8 9 11 9 11 7 8 7 8 12 7 12 7 9 4 9"/></svg></span><span class="vsTab">base_integration.cpp</span><span class="vsTab">url_auth_box.cpp</span><span class="vsTab">scheme.h</span><span class="vsTab">local_url_handlers.cpp</span><span class="vsTab">basic_click_handlers.cpp</span></div>
	<div class="vsBox" style="border-top: none; height: fit-content">
		<div aria-hidden="true">
		<span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#C16FCC"><rect fill="#454545" stroke="#B9B9B9" x="1.5" y="2.5" width="13" height="11"/><line x1="5.5" x2="5.5" y1="4" y2="9"/><line x1="8" x2="3" y1="6.5" y2="6.5"/><line x1="10.5" x2="10.5" y1="7" y2="12"/><line x1="13" x2="8" y1="9.5" y2="9.5"/></svg>Telegram<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span><span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="#DEDEDE" stroke-linecap="square"><path d="m4.6 2.5c-0.7 0-1 0.4-1 1v3l-0.8 1v1l0.8 1v3c0 0.7 0.3 1 1 1"/><path d="m11.5 13.5c0.7 0 1-0.4 1-1v-3l0.8-1v-1l-0.8-1v-3c0-0.7-0.3-1-1-1"/></svg>Core::`anonymous-namespace'<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span><span class="vsDropdown"><svg xmlns="http://www.w3.org/2000/svg" fill="#474152" stroke="#9670C6" stroke-linejoin="round"><polyline class="st0" points="13.5 5 13.5 12.1 8 14.6 8 7.7 13.5 5 8 2 2.4 5 8 7.7 8 14.6 2.4 11.7 2.4 5"/></svg>BotAutoLogin(const QString & url, const QString & domain,<svg xmlns="http://www.w3.org/2000/svg" fill="#D6D6D6" stroke="none" style="float: right; padding-right: 2px"><polygon points="13 11 16 8 10 8"/></svg></span>
	</div>
	<div style="height: 374px"><span style="width: 17px;display:inline-block;background:#333;height:100%"><div style="height:1px"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint active" title="This is a breakpoint, code execution stops here, lets me see the cool info like the locals below, and also lets me step through the code line by line!"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div><div class="vsBreakpoint"></div></span><span class="vsCodeArea" style="width: calc(100% - 17px);display:inline-block;background:#1E1E1E;height:100%"><!-- This part (the syntax highlight) was really annoying to do manually, I wouldn't recommend doing it yourself. --><span class="vLn">   79     </span>
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
	<td>web.telegram.org</td>
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
	<td>https://web.telegram.org</td>
	<td>const QString &amp;</td>
</tr>
		</tbody>
	</table>
</div>
</div>
</div>

So that's why I couldn't find the keywords! The list of domains this trick works with is sent to you by the Telegram server and stored in the config under the `url_auth_domains`[^2] key. You can see the list of domains currently provided in the locals above.

Once you click on a link with a matching domain your client sends the link to Telegram's servers and if everything looks alright your client will get a cute little temporary URL with the tokens and everything appended. For those playing along at home, we send a `messages_requestUrlAuth` with only the `url` set[^3] and hope to get back a `urlAuthResultAccepted` with the new `url` inside.

Having figured out how the thing works, and armed with the list of domains, I began looking for ways to break it. It seems like the entire initial URL gets preserved, including the path, query parameters, and hash fragment, with the exception of the scheme being forced to https.

For example:

- `http://web.​telegram.org/` becomes `https://web.​telegram.org/​#tgWebAuthToken=...`
- `https://z.t.me/​pony` becomes `https://z.t.me/pony​?tgWebAuth=1​#tgWebAuthToken=...`
- `https://k.t.me/​#po=ny` becomes `https://k.t.me/​?tgWebAuth=1​#po=ny​&tgWebAuthToken=...`

<details><summary>(a lot) more examples</summary>
<table class="detailedUrlMapTable">
  <thead>
    <tr>
      <th>Original URL</th>
      <th>URL with token</th>
    </tr>
  </thead>
  <tbody>
<tr><td>https://z.t.me/</td><td>https://z.t.me/?tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/pony</td><td>https://z.t.me/pony?tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/#pony</td><td>https://z.t.me/?tgWebAuth=1#pony?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/#bon=bon</td><td>https://z.t.me/?tgWebAuth=1#bon=bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/#?bon</td><td>https://z.t.me/?tgWebAuth=1#?bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/?#bon</td><td>https://z.t.me/?tgWebAuth=1#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/?bon=bon</td><td>https://z.t.me/?bon=bon&amp;tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/?bon=bon#bon</td><td>https://z.t.me/?bon=bon&amp;tgWebAuth=1#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/#=</td><td>https://z.t.me/?tgWebAuth=1#=&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/?tgWebAuth=🐴</td><td>https://z.t.me/?tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://z.t.me/?tgWebAuth=1#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://z.t.me/?tgWebAuth=🐴#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://z.t.me/?tgWebAuth=1#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/pony</td><td>https://k.t.me/pony?tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/#pony</td><td>https://k.t.me/?tgWebAuth=1#pony?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/#bon=bon</td><td>https://k.t.me/?tgWebAuth=1#bon=bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/#?bon</td><td>https://k.t.me/?tgWebAuth=1#?bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/?#bon</td><td>https://k.t.me/?tgWebAuth=1#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/?bon=bon</td><td>https://k.t.me/?bon=bon&amp;tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/?bon=bon#bon</td><td>https://k.t.me/?bon=bon&amp;tgWebAuth=1#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/#=</td><td>https://k.t.me/?tgWebAuth=1#=&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/?tgWebAuth=🐴</td><td>https://k.t.me/?tgWebAuth=1#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://k.t.me/?tgWebAuth=1#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://k.t.me/?tgWebAuth=🐴#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://k.t.me/?tgWebAuth=1#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/pony</td><td>https://web.telegram.org/pony#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/#pony</td><td>https://web.telegram.org/#pony?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/#bon=bon</td><td>https://web.telegram.org/#bon=bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/#?bon</td><td>https://web.telegram.org/#?bon&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/?#bon</td><td>https://web.telegram.org/?#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/?bon=bon</td><td>https://web.telegram.org/?bon=bon#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/?bon=bon#bon</td><td>https://web.telegram.org/?bon=bon#bon?tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/#=</td><td>https://web.telegram.org/#=&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/?tgWebAuth=🐴</td><td>https://web.telegram.org/?tgWebAuth=🐴#tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://web.telegram.org/#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
<tr><td>https://web.telegram.org/?tgWebAuth=🐴#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset</td><td>https://web.telegram.org/?tgWebAuth=🐴#tgWebAuthToken=trixie&amp;tgWebAuthUserId=starlight&amp;tgWebAuthDcId=sunset&amp;tgWebAuthToken=...&amp;tgWebAuthUserId=420493337&amp;tgWebAuthDcId=4</td></tr>
  </tbody>
</table>
</details>

All of the domains apart from the web.telegram.org one are sort-of built for the [t.me deep links](https://core.telegram.org/api/links). Going on any of them without a path will just bring you to the telegram.org homepage. Going on one with a compatible path, such as [z.t.me/share?url=lyra.horse](https://z.t.me/share?url=lyra.horse), will open the respective client with a hash fragment, eg:  
[https://web.telegram.org/a/#?​tgaddr=​tg%3A%2F%2Fmsg_url%3F​url%3Dlyra.horse](https://web.telegram.org/a/#?tgaddr=tg%3A%2F%2Fmsg_url%3Furl%3Dlyra.horse)

This is usually performed with a HTTP 301 redirect, but if the `tgWebAuth` parameter is set and the t.me deep link is valid, you'll get to run this javascript instead:

<div class="chromeWindow"><!-- At this point I got a bit lazy, so instead of recreating it from scratch I just kinda copied chromium's view-source CSS :p -->
<div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText">view-source:https://<span style="color:#E3E3E3">z.t.me</span>/share?url=lyra.horse&tgWebAuth=1</span></div></div>
<table class="vs-main"><tbody><tr><td class="vs-ln" value="1"></td><td class="vs-lc"><span class="vs-tg">&lt;html&gt;</span></td></tr><tr><td class="vs-ln" value="2"></td><td class="vs-lc"><span class="vs-tg">&lt;head&gt;</span></td></tr><tr><td class="vs-ln" value="3"></td><td class="vs-lc"><span class="vs-tg">&lt;meta <span class="vs-at">name</span>="<span class="vs-av">robots</span>" <span class="vs-at">content</span>="<span class="vs-av">noindex, nofollow</span>"&gt;</span></td></tr><tr><td class="vs-ln" value="4"></td><td class="vs-lc"><span class="vs-tg">&lt;noscript&gt;</span>&lt;meta http-equiv="refresh" content="0;url='https://web.telegram.org/a/#?tgaddr=tg%3A%2F%2Fmsg_url%3Furl%3Dlyra.horse'"&gt;<span class="vs-tg">&lt;/noscript&gt;</span></td></tr><tr><td class="vs-ln" value="5"></td><td class="vs-lc"><span class="vs-tg">&lt;script&gt;</span></td></tr><tr><td class="vs-ln" value="6"></td><td class="vs-lc">try {</td></tr><tr><td class="vs-ln" value="7"></td><td class="vs-lc">var url = "https:\/\/web.telegram.org\/a\/#?tgaddr=tg%3A%2F%2Fmsg_url%3Furl%3Dlyra.horse";</td></tr><tr><td class="vs-ln" value="8"></td><td class="vs-lc">var hash = location.hash.toString();</td></tr><tr><td class="vs-ln" value="9"></td><td class="vs-lc">if (hash.substr(0, 1) == '#') {</td></tr><tr><td class="vs-ln" value="10"></td><td class="vs-lc">  hash = hash.substr(1);</td></tr><tr><td class="vs-ln" value="11"></td><td class="vs-lc">}</td></tr><tr><td class="vs-ln" value="12"></td><td class="vs-lc">location.replace(hash ? urlAppendHashParams(url, hash) : url);</td></tr><tr><td class="vs-ln" value="13"></td><td class="vs-lc">} catch (e) { location.href=url; }</td></tr><tr><td class="vs-ln" value="14"></td><td class="vs-lc"><br></td></tr><tr><td class="vs-ln" value="15"></td><td class="vs-lc">function urlAppendHashParams(url, addHash) {</td></tr><tr><td class="vs-ln" value="16"></td><td class="vs-lc">  var ind = url.indexOf('#');</td></tr><tr><td class="vs-ln" value="17"></td><td class="vs-lc">  if (ind &lt; 0) {</td></tr><tr><td class="vs-ln" value="18"></td><td class="vs-lc">    return url + '#' + addHash;</td></tr><tr><td class="vs-ln" value="19"></td><td class="vs-lc">  }</td></tr><tr><td class="vs-ln" value="20"></td><td class="vs-lc">  var curHash = url.substr(ind + 1);</td></tr><tr><td class="vs-ln" value="21"></td><td class="vs-lc">  if (curHash.indexOf('=') &gt;= 0 || curHash.indexOf('?') &gt;= 0) {</td></tr><tr><td class="vs-ln" value="22"></td><td class="vs-lc">    return url + '&amp;' + addHash;</td></tr><tr><td class="vs-ln" value="23"></td><td class="vs-lc">  }</td></tr><tr><td class="vs-ln" value="24"></td><td class="vs-lc">  if (curHash.length &gt; 0) {</td></tr><tr><td class="vs-ln" value="25"></td><td class="vs-lc">    return url + '?' + addHash;</td></tr><tr><td class="vs-ln" value="26"></td><td class="vs-lc">  }</td></tr><tr><td class="vs-ln" value="27"></td><td class="vs-lc">  return url + addHash;</td></tr><tr><td class="vs-ln" value="28"></td><td class="vs-lc">}</td></tr><tr><td class="vs-ln" value="29"></td><td class="vs-lc"><span class="vs-tg">&lt;/script&gt;</span></td></tr><tr><td class="vs-ln" value="30"></td><td class="vs-lc"><span class="vs-tg">&lt;/head&gt;</span></td></tr><tr><td class="vs-ln" value="31"></td><td class="vs-lc"><span class="vs-tg">&lt;/html&gt;</span></td></tr><tr><td class="vs-ln" value="32"></td><td class="vs-lc"><span class="vs-cm">&lt;!-- page generated in 4.3ms --&gt;</span></td></tr><tr><td class="vs-ln" value="33"></td><td class="vs-lc"><span></span></td></tr></tbody></table>
</div>

I was a bit puzzled at first, but eventually realized it was just a simple hack to deal with URL hash fragments. The [hash fragment](https://en.wikipedia.org/wiki/URI_fragment) part of the URL never gets sent to the server, so the server cannot know *where* to redirect you *if* it wants to add its own hash fragment. In this specific case, we have `#tgWebAuthToken=...` in the URL already and want to add `#?tgaddr=...` to it as as we redirect to the web client (so in the end we get `#?tgaddr=...&tgWeb​AuthToken=...`).

For the rest of the night I played around with Telegram's various web clients. A little-known fact is that the [legacy Telegram web client](https://github.com/zhukov/webogram) can still be accessed to this day by going to [web.telegram.org?legacy=1](https://web.telegram.org/?legacy=1). What's more, the session is shared between the web clients, so an exploit in the old web client might still be useful even if the target uses a different web client.

I couldn't find anything too interesting in [WebK](https://github.com/morethanwords/tweb), but both [WebZ](https://github.com/Ajaxy/telegram-tt) and the legacy client provided some promising leads in messing with the `tgaddr` in the URL. It ended up being a dead end for my research though, as I couldn't figure out a way to get rid of or bypass the ampersand in the `&tgWebAuthToken=...` part of the URL.

I also looked into the mobile apps. Both the [iOS](https://github.com/TelegramMessenger/Telegram-iOS) and [Android](https://github.com/DrKLO/Telegram) clients support the link authentication thing, which makes the whole situation a bit more worrying considering it's generally a lot harder to just copy a session token off a mobile device. On Android I messed around with intents, but ended up at another dead end as intents for web links have been [locked down since Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#android-app-links-verification-changes) and require verification to work. I also messed around with protocol intents, but the way the app has been built prevents the token from being appended in those cases.

*So, no exploit?*

In my research I was unable to come up with a successful remote exploit - but that doesn't mean it was all in vain. Combining all the research so far and adding a little cherry on top we can create a scenario where we can steal someone's Telegram session in just a few seconds of physical access to their device, no matter if it's their computer, phone, or tablet.

We start off by sending "z.t.me" in their Telegram app and tapping on the link. This will open their browser to a link that will redirect to `telegram.org/​#tgWebAuthToken=...`. From here we edit the domain in the browser to `telegramz.org` - a domain I own - and hit/tap enter. The javascript on my domain will take it from here, logging one of *my* devices in with the token.

**Here's a demo of me pulling off the entire attack in less than 10 seconds on an Android phone and a laptop:**

<svg height="32px" style="display: inline-block;vertical-align: middle" viewBox="0 0 68 48"><path class="ytp-large-play-button-bg" d="M66.52,7.74c-0.78-2.93-2.49-5.41-5.42-6.19C55.79,.13,34,0,34,0S12.21,.13,6.9,1.55 C3.97,2.33,2.27,4.81,1.48,7.74C0.06,13.05,0,24,0,24s0.06,10.95,1.48,16.26c0.78,2.93,2.49,5.41,5.42,6.19 C12.21,47.87,34,48,34,48s21.79-0.13,27.1-1.55c2.93-0.78,4.64-3.26,5.42-6.19C67.94,34.95,68,24,68,24S67.94,13.05,66.52,7.74z" fill="#f00"></path><path d="M 45,24 27,14 27,34" fill="#fff"></path></svg><a href="https://www.youtube.com/watch?v=">https://www.youtube.com/watch?v=</a>

<div class="ytLink"><svg height="32px" style="display: inline-block;vertical-align: middle" viewBox="0 0 68 48"><path class="ytp-large-play-button-bg" d="M66.52,7.74c-0.78-2.93-2.49-5.41-5.42-6.19C55.79,.13,34,0,34,0S12.21,.13,6.9,1.55 C3.97,2.33,2.27,4.81,1.48,7.74C0.06,13.05,0,24,0,24s0.06,10.95,1.48,16.26c0.78,2.93,2.49,5.41,5.42,6.19 C12.21,47.87,34,48,34,48s21.79-0.13,27.1-1.55c2.93-0.78,4.64-3.26,5.42-6.19C67.94,34.95,68,24,68,24S67.94,13.05,66.52,7.74z" fill="#f00"></path><path d="M 45,24 27,14 27,34" fill="#fff"></path></svg><span><a href="https://www.youtube.com/watch?v=">Stealing your Telegram account in 10 seconds flat</a></span></div>

<div class="ytLink2">
<div style="padding:13px;display: inline-block">
<span style="width:40px;height:40px;display:inline-block;background: pink;border-radius:40px;vertical-align: middle;"></span><span style="text-shadow: 0 0 2px #0008;vertical-align: middle;padding-left:10px">Stealing your Telegram account in 10 seconds flat</span></div>
<svg width="15%" style="margin:auto;display:block;position:absolute;top:0;left:0;bottom:0;right:0" viewBox="0 0 68 48"><path class="ytp-large-play-button-bg" d="M66.52,7.74c-0.78-2.93-2.49-5.41-5.42-6.19C55.79,.13,34,0,34,0S12.21,.13,6.9,1.55 C3.97,2.33,2.27,4.81,1.48,7.74C0.06,13.05,0,24,0,24s0.06,10.95,1.48,16.26c0.78,2.93,2.49,5.41,5.42,6.19 C12.21,47.87,34,48,34,48s21.79-0.13,27.1-1.55c2.93-0.78,4.64-3.26,5.42-6.19C67.94,34.95,68,24,68,24S67.94,13.05,66.52,7.74z" fill="#f00"></path><path d="M 45,24 27,14 27,34" fill="#fff"></path></svg>
<div style="position:absolute;bottom: 8px;background:#171717cc;width:fit-content;height:47px;font-size:16px;font-weight:500;display:flex;align-items: center"><span style="margin: 12px">Watch on YouTube</span></div>
</div>

This attack is incredibly easy to pull off even for a low-skill attacker. Assuming some higher forces have already set up a custom domain for you, all you need to know is how to tap on a link and add a letter onto the URL bar. You don't need any specialized tools, you don't need to know anything about the target, you don't even need a phone.

So what should Telegram do about this?

<div class="tgQr">
<div style="margin: 0 auto;width:280px;aspect-ratio:1/1;max-width:100%;background:#FFF;border-radius:24px"><a href="https://lyra.horse/antonymph/"><svg fill="none" stroke="#000" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 280 280" xmlns="http://www.w3.org/2000/svg">
<!-- QR data -->
<polyline points="92 28 100 28 100 36 108 36"/><polyline points="124 28 124 36 132 36 124 36 124 44 116 44 116 68 100 68 108 68 108 76 108 60 132 60 132 52 132 60 140 60 140 84 156 84 156 76"/><polyline points="148 68 117.2 68 124 68 124 84 116 84 116 92"/><polyline points="132 92 132 100 124 100"/><polyline points="84 116 108 116 108 100 84 100 84 92 76 92 100 92 100 84 100 108 100 116 100 108 116 108"/><polyline points="180 44 180 52 148 52 148 44 164 44 164 28 188 28 172 28 172 36 164 36 164 52 156 52 156 60"/><polyline points="172 76 172 68 188 68 188 76 188 60"/><polyline points="188 116 188 108 180 108 180 100 180 108 164 108 164 92 164 100 156 100"/><line x1="188" x2="196" y1="92" y2="92"/><polyline points="236 116 236 100 244 100 244 108 236 108"/><polyline points="212 100 220 100 220 116"/><polyline points="52 92 36 92 36 100"/><polyline points="252 148.9 252 132 244 132 252 132 252 124"/><polyline points="196 140 188 140 188 148"/><polyline points="68 100 68 108 76 108 68 108 68 116"/><polyline points="92 156 92 164 100 164 100 156 76 156 84 156 84 140 76 140"/><line x1="28" x2="28" y1="108" y2="116"/><polyline points="36 124 36 132 44 132 36 132 36 140"/><polyline points="28 148 28 156 36 156 36 164"/><polyline points="68 148 60 148 60 164 68 164 52 164 52 156 60 156 60 188"/><polyline points="76 172 84 172 84 180 100 180 84 180 84 188 76 188"/><line x1="92" x2="92" y1="196" y2="204"/><polyline points="116 228 116 220 100 220 108 220 108 204 132 204 132 220 132 212 124 212 124 204 148 204 140 204 140 188 124 188 124 180 132 180 132 188"/><polyline points="92 228 92 244 100 244 100 236 92 236"/><polyline points="124 252 132 252 132 244"/><polyline points="172 252 164 252 164 236 156 236 156 228 156 236 140 236 140 228"/><polyline points="148 180 172 180 172 164 172 172 180 172"/><polyline points="172 228 172 220 164 220 164 204 164 212 156 212"/><line x1="188" x2="188" y1="236" y2="252"/><polyline points="212 156 212 140 228 140 228 132 220 132 220 140 236 140 236 164 244 164 244 180 252 180 244 180 244 156 236 156 236 164 220 164 220 172 196 172 196 164 188 164"/><polyline points="228 164 228 196 220 196 220 172 204 172 204 180 204 188 204 180 220 180 220 188 180 188 180 204 188 204 188 188 188 220 204 220 204 236 204 228 196 228 196 220 220 220 220 196 220 228 244 228 244 236 252 236 236 236 236 244 228 244 228 228 236 228 236 236 236 220 244 220 244 228 236 228 236 204 252 204 252 196 252 212 252 204 236 204 236 212 220 212"/><line x1="204" x2="204" y1="204" y2="204"/><line x1="244" x2="244" y1="252" y2="252"/><line x1="148" x2="148" y1="252" y2="252"/><line x1="148" x2="148" y1="220" y2="220"/><line x1="108" x2="108" y1="188" y2="188"/><line x1="108" x2="108" y1="172" y2="172"/><line x1="44" x2="44" y1="188" y2="188"/><line x1="28" x2="28" y1="172" y2="172"/><line x1="44" x2="44" y1="148" y2="148"/><line x1="76" x2="76" y1="124" y2="124"/><line x1="52" x2="52" y1="108" y2="108"/><line x1="92" x2="92" y1="76" y2="76"/><path d="m148 108"/><line x1="180" x2="180" y1="132" y2="132"/><line x1="196" x2="196" y1="124" y2="124"/><line x1="212" x2="212" y1="124" y2="124"/><line x1="204" x2="204" y1="108" y2="108"/><line x1="252" x2="252" y1="92" y2="92"/><line x1="148" x2="148" y1="28" y2="28"/>
<!-- QR position -->
<polyline points="52 44 52 60 60 60 60 44 44 44 44 60 52 60"/><path d="m44 28h16c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16h-16c-8.8 0-16-7.2-16-16v-16c0-8.8 7.2-16 16-16z"/><polyline points="52 220 52 236 60 236 60 220 44 220 44 236 52 236"/><path d="m44 204h16c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16h-16c-8.8 0-16-7.2-16-16v-16c0-8.8 7.2-16 16-16z"/><polyline points="228 44 228 60 236 60 236 44 220 44 220 60 228 60"/><path d="m220 28h16c8.8 0 16 7.2 16 16v16c0 8.8-7.2 16-16 16h-16c-8.8 0-16-7.2-16-16v-16c0-8.8 7.2-16 16-16z"/>
<!-- TG logo -->
<circle fill="#3390EC" stroke="none" cx="140" cy="140" r="32"/><path fill="#FFF" stroke="none" d="m131 143.6c5.7-3.8 11.4-7.5 14.8-9.2 0.7-0.5 1.5 0.5 0.9 1.1-2.6 3.3-6.5 6.6-10.8 10.8-0.8 0.8-0.6 2 0.3 2.6 3.5 2.6 7.7 5.2 12.2 7.8 1.8 1.1 4.2 0.1 4.5-2 1.7-9.1 3-17.7 3.9-25.8 0.3-1.9-1.6-3.5-3.5-2.7-10.4 4-21.8 8.8-34.3 14.1-1 0.5-1.6 1.5-0.1 2.3l4.5 1.6c2.6 0.9 5.3 0.8 7.6-0.6z"/>
</svg></a></div>
<p>Log in to Telegram by QR Code</p>
<ol><li><span>Open Telegram on your phone</span></li><li><span>Go to Settings &gt; Devices &gt; Link Desktop Device</span></li><li><span>Point your phone at this screen to confirm login</span></li></ol>
</div>

The same thing they did with the QR code logins!

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
[^2]: `url_auth_domains` is a list of domains used for logging into the web clients, but there is another list under the `autologin_domains` key, which is used for webapps such as [bugs.telegram.org](https://bugs.telegram.org) instead.
[^3]: There are also `peer`, `msg_id`, and `button_id` fields, but if we set our `flag` to `f_url` (4) we skip them.

<style>
	.ytLink {
		width: fit-content;
		height: 32px;
		padding: 4px;
		background: #020;
		border-radius: 4px;
		font-family: "Roboto", "Arial", sans-serif;
	}
	.ytLink a {
		color: #EEE;
        font-size: 18px;
        font-weight: 700;
	}
	.ytLink2 {
		position: relative;
		width: 100%;
		aspect-ratio: 16 / 9;
		background: #FF0;
		background: linear-gradient(90deg, rgba(174,238,184,1) 0%, rgba(223,233,148,1) 100%);
		border-radius: 4px;
		color:#eee;
		font-size: 18px;
		font-family: 'YouTube Noto', Roboto, Arial, Helvetica, sans-serif;
	}
	.tgQr div {
		transform: scale(1);
		cursor: pointer;
		filter: none;
		transition: transform 0.2s, filter 0.2s;
	}
	.tgQr div:hover {
		transform: scale(1.05);
		filter: drop-shadow(2px 4px 7px #000);
	}
	.tgQr svg *:hover {
		stroke: pink;
	}
	.tgQr {
		font-family: "Roboto", "Segoe UI", "Helvetica Neue", system-ui, sans-serif;
		background: #212121;
		border-radius: 4px;
		color: #FFF;
		padding: 32px calc(50% - 180px) 16px;
		font-size: 16px;
	}
	.tgQr p {
		margin: 1.5rem 0 1rem 0;
    	font-size: 1.25rem;
		line-height: 1.5;
		font-weight: 500;
		text-align: center;
	}
	.tgQr ol {
		padding: 0 1.75rem;
		margin: 0 0 1rem;
	}
	.tgQr li {
		margin: .75rem 0;
		display: flex;
		counter-increment: item;
	}
	.tgQr ol li::before {
    	content: counter(item);
    	display: flex;
    	justify-content: center;
    	align-items: center;
    	min-width: 1.375rem;
    	height: 1.375rem;
    	margin: 0 .75rem 0 0;
    	background: rgb(135,116,225);
    	border-radius: 50%;
    	font-size: smaller;
	}
	.vs-main {
    	width: 100%;
    	word-break: normal;
    	overflow-wrap: anywhere;
    	white-space: pre-wrap;
    	color: white;
    	font-family: monospace;
    	border-spacing: 0px;
    	background: #000;
    	border-top: 1px solid #444746;
	}
	.vs-ln::before {
    	content: attr(value);
	}
	.vs-ln {
		box-sizing: border-box;
    	width: 31px;
    	background-color: rgb(60, 60, 60);
    	user-select: none;
    	text-align: right;
    	color: rgb(128, 128, 128);
    	font-size: 12px;
    	padding: 0px 4px;
    	border-right: 1px solid rgb(187, 187, 187);
    	vertical-align: baseline;
	}
	.vs-lc {
		padding: 0px 5px;
		vertical-align: baseline;
	}
	.vs-tg {
		color: rgb(93, 176, 215);
	}
	.vs-at {
		color: rgb(155, 187, 220);
	}
	.vs-av {
		color: rgb(242, 151, 102);
	}
	.vs-cm {
		color: rgb(35, 110, 37);
	}
	.chromeWindow {
		background: #3C3C3C;
		height: fit-content;
		width: 100%;
		border-radius: 4px;
		overflow: hidden;
	}
	.detailedUrlMapTable {
		table-layout: fixed;
		width: 100%;
		word-break: break-all;
		font-size: 12px;
		font-family: monospace;
		border-collapse: collapse;
		color: #70BAF5;
		background: #182533;
		border-radius: 4px;
	}
	.detailedUrlMapTable td {
		border: 1px solid #0E1621;
		padding: 4px 4px;
	}
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