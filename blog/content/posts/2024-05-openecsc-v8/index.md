+++
title = 'Exploiting V8 at openECSC'
date = 2024-05-20T13:37:00Z
draft = false
tags = ['ctf','browser']
slug = "exploiting-v8-at-openecsc"
summary = "todo: fill this and also the date"
+++

Despite having 7 Chrome CVEs, I've never actually exploited a memory corruption in it's [V8 JavaScript engine](https://v8.dev/) before. [Baby array.xor](https://github.com/ECSC2024/openECSC-2024)<!-- TODO: link -->, a challenge at this year's openECSC CTF, was my first time going from a V8 bug to popping a `/bin/sh` shell.

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
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,10 4,6 8,2 8.85,2.85 5.7,6 8.85,9.15 Z"/><circle cx="10" cy="6" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.1</span>, <span class="jsConValOut">0.2</span>, <span class="jsConValOut">0.3</span>]</i></summary>
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
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,10 4,6 8,2 8.85,2.85 5.7,6 8.85,9.15 Z"/><circle cx="10" cy="6" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.10000000000001079</span>, <span class="jsConValOut">0.20000000000002158</span>, <span class="jsConValOut">0.30000000000004035</span>]</i></summary>
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
	width: 100%;
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
	/* border-bottom: 1px solid #5E5E5E; */
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
.jsConType {
	color: #7CACF8;
}
.jsConStr {
	color: #FE8D59;
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
</style>

Quite the peculiar feature. It may seem a little confusing if you aren't familiar with [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754) [doubles](https://en.wikipedia.org/wiki/Double-precision_floating-point_format), but it makes sense once we look at the hex representations of the values:

<div class="jsConsole" style="text-align:center; width: fit-content; margin: 0 auto">
	<div class="jsConLine">(<span class="jsConType">double</span>)&nbsp;<span class="jsConValIn">0.1</span> ^ (<span class="jsConType">uint64</span>)&nbsp;<span class="jsConValIn">1337</span> = (<span class="jsConType">double</span>)&nbsp;<span class="jsConValIn">0.10000000000001079</span></div>
	<div class="jsConBorder"></div>
	<div class="jsConLine" style="white-space: pre">  <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">99a</span></span></div>
	<div class="jsConLine">^ <span class="jsConValIn">0x0000000000000<span class="jsConFun">539</span></span></div>
	<div class="jsConLine">= <span class="jsConValIn">0x3fb9999999999<span class="jsConFun">ca3</span></span></div>
</div>

It pretty much just interprets the double as an integer, and then performs the XOR operation on it. In this example we XORed the doubles with 0x539 (1337 in hex), so the last three hex digits of each double changed. It's a pretty silly operation to perform on a double.

Just XORing doubles isn't going to get us anywhere though, since the values are stored in a doubles array (`PACKED_DOUBLE_ELEMENTS`[^2]) as just *raw 64-bit doubles*. All we can do is change some numbers around, but that's something we can already do without xor. It'd be a lot more interesting if we could run this xor thingie on a mixed array (`PACKED_ELEMENTS`) consisting of *memory pointers* to other JavaScript objects, because we could point the pointers to places in memory we're not supposed to.

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
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,10 4,6 8,2 8.85,2.85 5.7,6 8.85,9.15 Z"/><circle cx="10" cy="6" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">0.1</span>, <span class="jsConValOut">0.2</span>, <span class="jsConValOut">0.3</span>]</i> <span class="jsConNull">// hehe, looks good!</span></summary>
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

The **IsJSArray** method makes sure that we are in fact passing an array, and the **HasOnlySimpleReceiverElements** method checks for anything sus[^3] within the array or it's prototype.

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
	<div class="jsConLine"><svg class="jsConIcon" xmlns="http://www.w3.org/2000/svg"><path d="M 8,10 4,6 8,2 8.85,2.85 5.7,6 8.85,9.15 Z"/><circle cx="10" cy="6" r="1"/></svg><details><summary><i>(3) [<span class="jsConValOut">140508</span>, <span class="jsConValOut">2.2</span>, <span class="jsConValOut">140484</span>]</i> <span class="jsConNull">// waow!</span></summary>
<div style="padding-left: 24px">
	<span class="jsConIdx jsConB">0</span>: <span class="jsConValOut">0x000449b8</span> (<span class="jsConType">SMI</span>)<br/>
	<span class="jsConIdx jsConB">1</span>: <span class="jsConValOut">0x00044cbd</span> (<span class="jsConType">pointer to double</span>)<br/>
	<span class="jsConIdx jsConB">2</span>: <span class="jsConValOut">0x00044988</span> (<span class="jsConType">SMI</span>)<br/>
</div>
	</details></div>
</div>

We're cooking!

## Part 2: Cooking up some primitives

Now that we've found a way to put some objects in an array and mess with them, we must figure out a way to turn that into the `addrof` and `fakeobj` primitives. There are a few different ways to accomplish this from here. I'll go with the path I took originally, but see if you can figure out any other ways to get there - I'll share a couple (arguably better ones) at the end of the post.

But first, we should look at how v8 stores stuff in the memory so that we can figure out what our memory corruption looks like and what we can do with it. How could we do that?

With the **d8 natives syntax** and a **debugger**! If we launch d8 (the v8 shell) with the `--allow-natives-syntax` flag, we can use various debug functions such as `%DebugPrint(obj)` to examine what's going on with objects, and if we combine that with a debugger ([gdb](https://gnu.org/software/gdb/) in this case) we can even check out the entire memory to understand it better. Let's try it:

```js
> gdb --args ./d8 --allow-natives-syntax //<-- use d8 with the natives syntax in gdb
GNU gdb (GDB) 14.2
...                      
(gdb) run // <-- start d8
Starting program: /home/lyra/Desktop/array.xor/dist/d8 --allow-natives-syntax
V8 version 12.7.0 (candidate)
d8> arr = [1.1, 2.2, 3.3] // <-- create an array
[1.1, 2.2, 3.3]
d8> %DebugPrint(arr) // <-- debugprint the array
DebugPrint: 0xa3800042be9: [JSArray] // <-- we get the address here
 - map: 0x0a38001cb7c5 <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x0a38001cb11d <JSArray[0]>
 - elements: 0x0a3800042bc9 <FixedDoubleArray[3]> [PACKED_DOUBLE_ELEMENTS]
 - length: 3
 - properties: 0x0a3800000725 <FixedArray[0]>
 - All own properties (excluding elements): {
    0xa3800000d99: [String] in ReadOnlySpace: #length: 0x0a3800025f85 <AccessorInfo name= 0x0a3800000d99 <String[6]: #length>, data= 0x0a3800000069 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x0a3800042bc9 <FixedDoubleArray[3]> {
           0: 1.1
           1: 2.2
           2: 3.3
 }
0xa38001cb7c5: [Map] in OldSpace
 - map: 0x0a38001c01b5 <MetaMap (0x0a38001c0205 <NativeContext[295]>)>
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - enum length: invalid
 - back pointer: 0x0a38001cb785 <Map[16](HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x0a3800000a89 <Cell value= 1>
 - instance descriptors #1: 0x0a38001cb751 <DescriptorArray[1]>
 - transitions #1: 0x0a38001cb7ed <TransitionArray[4]>
   Transition array #1:
     0x0a3800000e5d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x0a38001cb805 <Map[16](HOLEY_DOUBLE_ELEMENTS)>
 - prototype: 0x0a38001cb11d <JSArray[0]>
 - constructor: 0x0a38001cae09 <JSFunction Array (sfi = 0xa380002b2f9)>
 - dependent code: 0x0a3800000735 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0

[1.1, 2.2, 3.3]
d8> ^Z  // <-- suspend d8 (ctrl+z) to get to gdb
Thread 1 "d8" received signal SIGTSTP, Stopped (user).
0x00007ffff7da000a in read () from /usr/lib/libc.so.6
(gdb) x/8xg 0xa3800042be9-1 // <-- examine the array's address
0xa3800042be8:	0x00000725001cb7c5	0x0000000600042bc9
0xa3800042bf8:	0x00bab9320000010d	0x7566280a00000adc
0xa3800042c08:	0x29286e6f6974636e	0x20657375220a7b20
0xa3800042c18:	0x3b22746369727473	0x6d2041202f2f0a0a
(gdb) 
```

In this example I made an array, used DebugPrint to see it's address, and then used gdb's `x/32xg`[^4] command to see the memory around that address. Going forward I'll be cleaning up the examples shown in the blog post, but this is essentially how you can follow along at home.

<!-- todo: i don't think that's quite true -->
You'll notice I subtracted 1 from the memory address before viewing it - that's because of tagged pointers! ~~In a `PACKED_ELEMENTS` array, doubles that~~ end with a 0 bit (even) are stored as-is, but everything ending with a 1 bit (odd) gets interpreted as a pointer, so a pointer to `0x1000` gets stored as `0x1001`. Because of this, we have to subtract 1 from all tagged pointers before checking out their address.

<!-- Anyways, what are those exploit primitives? `addrof` lets us see the memory address of any object, and `fakeobj` lets us create a "fake" JavaScript object - they're almost like memory read and write functions, but not quite. -->

But let's try to understand what the gdb output above means:



<div class="jsMem">
	<div class="jsMemTitle">V8<div class="jsMemSep"></div></div>
	<div class="jsMemDbg">DebugPrint: <span class="jsMemVar10">0xa3800042be9</span>: [JSArray]
- map: <span class="jsMemVar7">0x0a38001cb7c5</span> &lt;Map[16](PACKED_DOUBLE_ELEMENTS)&gt; [FastProperties]
- prototype: 0x0a38001cb11d &lt;JSArray[0]&gt;
- elements: 0x0a3800042bc9 &lt;<span class="jsMemVar2">FixedDoubleArray</span>[<span class="jsMemVar1">3</span>]&gt; [PACKED_DOUBLE_ELEMENTS]
- length: <span class="jsMemVar8">3</span>
- properties: <span class="jsMemVar6">0x0a3800000725</span> &lt;FixedArray[0]&gt;
- All own properties (excluding elements): {
   0xa3800000d99: [String] in ReadOnlySpace: #length: 0x0a3800025f85 &lt;AccessorInfo name= 0x0a3800000d99 &lt;String[6]: #length&gt;, data= 0x0a3800000069 &lt;undefined&gt&gt; (const accessor descriptor, attrs: [W__]), location: descriptor
}
- elements: <span class="jsMemVar9">0x0a3800042bc9</span> &lt;FixedDoubleArray[<span class="jsMemVar1">3</span>]&gt; {
          0: <span class="jsMemVar3">1.1</span>
          1: <span class="jsMemVar4">2.2</span>
          2: <span class="jsMemVar5">3.3</span>
}</div>
<div class="jsMemTitle">GDB<div class="jsMemSep"></div></div>
	<div class="jsMemHex">0xa3800042bb8: 0x00000004000005e5<span class="under430"><br>0xa3800042bc0:</span> 0x001d3377020801a4
<span class="jsMemVar9">0xa3800042bc8</span>: 0x<span class="jsMemVar1">00000006</span><span class="jsMemVar2">000008a9</span><span class="under430"><br>0xa3800042bd0:</span> 0x<span class="jsMemVar3">3ff199999999999a</span>
0xa3800042bd8: 0x<span class="jsMemVar4">400199999999999a</span><span class="under430"><br>0xa3800042be0:</span> 0x<span class="jsMemVar5">400a666666666666</span>
<span class="jsMemVar10">0xa3800042be8</span>: 0x<span class="jsMemVar6">00000725</span><span class="jsMemVar7">001cb7c5</span><span class="under430"><br>0xa3800042bf0:</span> 0x<span class="jsMemVar8">00000006</span><span class="jsMemVar9">00042bc9</span>
0xa3800042bf8: 0x00bab9320000010d<span class="under430"><br>0xa3800042c00:</span> 0x7566280a00000adc
</div>
<div class="jsMemTitle">ENG<div class="jsMemSep"></div></div>
<div class="jsMemLegend">
The array is at <span class="jsMemVar10">0xa3800042be8</span>, its <span class="jsMemVar6">properties list</span> is empty, it's a <code><span class="jsMemVar7">PACKED_DOUBLE_ELEMENTS</span></code> array with a <span class="jsMemVar8">length of 3</span><sup id="fnref:4"><a href="#fn:4" class="footnote-ref" role="doc-noteref" style="color:#95dcff">4</a></sup> at <span class="jsMemVar9">0xa3800042bc9</span>. At that address we find a <span class="jsMemVar2">FixedDoubleArray</span> with a <span class="jsMemVar1">length of 3 (again)</span> and the doubles <span class="jsMemVar3">1.1</span>, <span class="jsMemVar4">2.2</span>, and <span class="jsMemVar5">3.3</span>.
</div>
</div>

Try <span class="fineText">hovering over</span><span class="coarseText">tapping on</span> the text and stuff above. You'll see what the memory values mean and how they're represented in the %DebugPrint output.

You may be wondering why the memory only contains half the address - `0xa3800042bc8` is stored as `0x00042bc9` for example. This is [V8's pointer compression](https://v8.dev/blog/pointer-compression) and it makes pointers only store the lower 32 bits of an address.

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
	--jsMemVarF0:  #ff9999;
	--jsMemVarF1:  #99ffc1;
	--jsMemVarF2:  #99ffea;
	--jsMemVarF3:  #99eaff;
	--jsMemVarF4:  #99c1ff;
	--jsMemVarF5:  #9999ff;
	--jsMemVarF6:  #ffea99;
	--jsMemVarF7:  #eaff99;
	--jsMemVarF8:  #c1ff99;
	--jsMemVarF9:  #99ff99;
	--jsMemVarF10:  #ffc199;
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

-->
[^5]

[^1]: If we could modify a boxed double - a special double that can also be tagged as a pointer - we could already use xor to corrupt memory, but `PACKED_DOUBLE_ELEMENTS` in V8 uses unboxed doubles.

[^2]: `PACKED_DOUBLE_ELEMENTS` means that the array consists of doubles only, and it also doesn't have any empty "holes". A double array with holes would be `HOLEY_DOUBLE_ELEMENTS` instead.

[^3]: [HasOnlySimpleReceiverElements](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-array.cc;l=42;drc=fe67713b2ff62f8ba290607bf7482a8efd0ca6cc) makes sure that there are no accessors on any of the elements, and that the array's prototype hasn't been modified.

[^4]: `x/32xg` stands for: e(**x**)amine (**32**) he(**x**)adecimal (**g**)iant words (64-bit values). I recommend checking out [a reference](https://visualgdb.com/gdbreference/commands/x) to see other ways this command can be used.

[^5]: In memory the length of the array is doubled (6 instead of 3) because each double value takes up two 32-bit "slots". TODO: factcheck this

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