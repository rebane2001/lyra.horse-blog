+++
title = 'Exploiting V8 at openECSC'
date = 2024-05-20T13:37:00Z
draft = false
tags = ['ctf','browser']
slug = "exploiting-v8-at-openecsc"
summary = "todo: fill this and also the date"
+++

Despite having 7 Chrome CVEs, I've never actually exploited a memory corruption in it's [V8 JavaScript engine](https://v8.dev/) before. [Baby array.xor](https://github.com/ECSC2024/openECSC-2024)<!-- TODO: link -->, a challenge at this year's openECSC CTF, was my first time going from a V8 bug to popping a `/bin/sh` shell.

Most V8 exploits tend to have two parts to them - figuring out a unique way to trigger some sort of a memory corruption of a single byte, and then following a common pattern of building upon that corruption to read arbitrary addresses, create fake objects, and eventually reach arbitrary code execution. This challenge was no different.

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

This patch adds a

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