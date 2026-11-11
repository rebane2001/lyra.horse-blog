+++
title = "How I accidentally became a millionaire"
date = 2026-11-11T21:11:11Z
draft = false
tags = ["deceit"]
slug = "disinformation-machine"
summary = "A story about a tweet thrown into the disinformation machine."
+++

I'm Lyra.

I am not a millionaire. I have never been one. And yet, if you were to ask Google about it, you might just walk away with the impression that I am.

<style>
  @property --mask-col {syntax:"<color>";initial-value:#0000;inherits:false}
  @property --t {syntax:"<number>";initial-value:1;inherits:false}
  google-frame {
    ::selection {color: #FFF;background:#0041C6CC}
    display: flex;
    flex-direction: column;
    font-family: "Google Sans", "Open Sans", "Noto Sans", "Roboto", Arial, sans-serif, "Noto Color Emoji";
    color-scheme: dark;
    width: 100%;
    padding: 16px;
    box-sizing: border-box;
    border-radius: 4px;
    overflow: clip;
    background: #22242A;
    color: #E8EAF2;
    h2 {
      font-size: 20px;
      font-weight: 600;
      margin: 1.15em 0 0.5em;
      font-family: inherit;
      color: inherit;
    }
    ul, p {
      margin: 0.5em 0;
    }
    ul {
      padding-left: 1.25em;
      li {
        margin-bottom: 12px;
      }
    }
    & > article {
      max-width:650px;
      line-height: 1.5;
    }
    a {
      color: #99C3FF;
      text-decoration: underline;
    }
    nav {
      white-space: pre;
      @media (width < 540px) {
        mask: linear-gradient(90deg,#000 calc(100% - 32px),#0000);
      }
      -webkit-user-select: none;
      user-select: none;
      border-bottom: 1px solid #444746;
      display: flex;
      margin-bottom: 24px;
      & > div {
        font-weight: 600;
        cursor: pointer;
        font-size: 14px;
        padding: 15px 12px 12px;
        color: #9C9EA6;
        &:hover {
          color: #E8EAF2;
        }
        &:active {
          color: #FFF;
        }
      }
    }
    .aiShowMore x-button {
      display: none;
      width: 100%;
      background: #22242A;
      &:hover { background: #2D313C }
      &:active { background: #404959 }
      border: 1px solid #515A7B;
      font-family: inherit;
      font-size: 14px;
      font-weight: 600;
      padding: 15px 11px;
      border-radius:99Q;
      cursor:pointer;
      position:relative;
      z-index:1;
      -webkit-user-select:none;
      user-select:none;
      text-align: center;
      box-sizing: border-box;
    }
    .aiShowMore:not(#aiShowMore) x-button {display:block}
    .aiShowMore input { display:none }
    small {
      font-size: 12px;
      color: #ADAFB8;
    }
  }
  .aio-logo {
    display: flex;
    &::before {
      display:inline-block;
      content:"";
      background:#7AACFF;
      width:24px;
      height:24px;
      @supports (corner-shape: scoop) {
        border-radius: 24px;
        corner-shape: scoop;  
      }
      @supports not (corner-shape: scoop) {
        clip-path:polygon(50% 0%, 60% 40%, 100% 50%, 60% 60%, 50% 100%, 40% 60%, 0% 50%, 40% 40%);
      }
    }
    font-size:14px;
    font-weight:600;
    align-items:center;
    gap:6px;
  }
  /* i dont have the full .com domain for some domains i dont want to promote,
     instead i append the .com in css */
  dont-visit[com]::after {
    content:".com";
  }
  .aiAnim1 {
    pointer-events: none;
    -webkit-user-select: none;
    user-select: none;
    @media not (prefers-reduced-motion: reduce) {
      transition: translate 0.4s, opacity 0.4s, filter 0.4s 0.5s, transform 0.4s 0.5s;
      &:not(.noScroll){
        animation: kAiAnim1a 0.4s 1, kAiAnim1b 0.9s 1;
        animation-trigger: --ai-t play-once, --ai-t play-once;
      }
    }
    /*visibility: hidden;*/
    filter: opacity(0);
    transform: translateX(10px);
    @starting-style {
      filter: opacity(1);
      opacity:0;
      transform: translateX(0px);
      translate: 0 16px;
      visibility: visible;
    }
  }
  .aiAnim2 {
    pointer-events: none;
    -webkit-user-select: none;
    user-select: none;
    @media not (prefers-reduced-motion: reduce) {
      transition: translate 0.4s 0.5s, opacity 0.4s 0.5s, filter 0.4s 0.7s, transform 0.4s 0.7s;
      &:not(.noScroll) {
        animation: kAiAnim2a 0.9s 1, kAiAnim2b 1.1s 1;
        animation-trigger: --ai-t play-once, --ai-t play-once;
      }
    }
    filter: opacity(0);
    transform: translateX(10px);
    @starting-style {
      filter: opacity(1);
      opacity:0;
      transform: translateX(0px);
      translate: -8px;
    }
  }
  .aiAnim3 {
    @media not (prefers-reduced-motion: reduce) {
      transition: opacity 0.2s 0.8s;
      &:not(.noScroll){
        animation: kAiAnim3 1s 1;
        animation-trigger: --ai-t play-once;
      }
    }
    @starting-style {
      opacity:0;
    }
  }
  .aiAnim4 {
    @media not (prefers-reduced-motion: reduce) {
      transition: opacity 0.2s 1s;
      &:not(.noScroll){
        animation: kAiAnim4 1.2s/*0.2s 1s*/ 1;
        animation-trigger: --ai-t play-once;
      }
    }
    opacity:1;
    @starting-style {
      opacity:0;
    }
  }
  .aiMark {
    background:#203DA0;
    background:linear-gradient(90deg,#203DA0 calc(var(--t)*100%),#0000 calc(var(--t)*100% + 5px));
    border-radius:3px;
    padding:0 2px;
    margin:0 -2px;
    @media not (prefers-reduced-motion: reduce) {
      transition: --t 0.75s 0.9s cubic-bezier(0.05, 0.7, 0.1, 1);
      &:not(.noScroll){
        animation: kAiMark 1.65s 1 cubic-bezier(0.05, 0.7, 0.1, 1);
        animation-trigger: --ai-t play-once;
      }
    }
    --t:1;
    @starting-style {
      --t:0;
    }
  }
  @keyframes kAiAnim1a {
    0%{opacity:0;translate:0 16px}
    100%{opacity:1;translate:0px}
  }
  @keyframes kAiAnim1b {
    0%,55.55%{filter:opacity(1);transform:translateX(0px)}
    100%{filter:opacity(0);transform:translateX(10px)}
  }
  @keyframes kAiAnim2a {
    0%,55.55%{opacity:0;translate:-8px}
    100%{opacity:1;translate:0px}
  }
  @keyframes kAiAnim2b {
    0%,63.63%{filter:opacity(1);transform:translateX(0px)}
    100%{filter:opacity(0);transform:translateX(10px)}
  }
  @keyframes kAiAnim3 {
    0%,80%{opacity:0}
    100%{opacity:1}
  }
  @keyframes kAiAnim4 {
    0%,83.33%{opacity:0}
    100%{opacity:1}
  }
  @keyframes kAiMark {
    0%,54.54%{--t:0}
    100%{--t:1}
  }
</style>
<DIV><google-frame role="img" aria-label="AI Overview banner image about Lyra Rebane becoming a millionaire" aria-describedby="aiOverview1" style="position:relative">
<div style="position:absolute;inset:0;background:linear-gradient(#0022, #0000 30%, #0000 70%, #0022);pointer-events:none;z-index:2"></div>
<nav aria-hidden=true style="margin-top:-40px;margin-bottom:8px"><div>AI Mode</div><div style="cursor:default;color:#FFF;border-bottom:3px solid;padding: 15px 0 9px;margin:0 12px">All</div><div>Images</div><div>Videos</div><div>News</div><div>Web</div><div>More</div></nav>
<article id="aiOverview1">
  <p class="noScroll aiAnim1" aria-hidden=true style="position:absolute;font-size:16px">Thinking</p>
  <p class="noScroll aiAnim2" aria-hidden=true style="position:absolute;font-size:16px">Searching</p>
  <p class="noScroll aiAnim3 aio-logo">AI Overview<span style="font-weight:400;margin-left:auto;font-size:0.7em;margin-right: 22px" aria-hidden=true>(<a href="https://x.com/ImPavloh/status/2119506103147139582" style="text-decoration:none">source</a>)</span></p>
  <p class="noScroll aiAnim3">Yes, <span class="noScroll aiMark"><b>Lyra Rebane became a millionaire in November 2026</b></span> thanks to her elite cybersecurity skills.</p>
  <p class="noScroll aiAnim4" style="mask:linear-gradient(#000 25%, #0000 100%);margin-bottom:0px">While she was already a highly successful researcher with dozens of vulnerabilities reported in major browsers like Google Chrome, her net worth officially crossed the million-dollar threshold on <b>November 7, 2026</b>. On this date, Google awarded her a historic single bounty payout of exactly <b>$1,333,337</b> for discovering a critical security flaw in Chrome.</p>
  <label class=aiShowMore aria-hidden=true><x-button class="noScroll aiAnim4" style="margin-bottom:-40px">Show more</x-button></label>
</article>
</google-frame></DIV>

I am a hacker, though. I am a hacker with 14 Chrome CVEs. And I think I am a good hacker. But I don't think I'm the bestest hacker. I don't believe I'm capable of finding a vulnerability that's worth over a million dollars. And even if I were, I don't think Google would pay that much for a Chromium vulnerability.

<span style="font-size:0.8em;font-weight:600;font-style:italic;">Content note: Due to the topics discussed, this post contains some examples of AI-generated text. Those examples are clearly differentiated[^lol]. Everything else in this blog post is fully human-made - I do not use AI.</span>

[^lol]: The snippets are either marked with "<span class="aio-logo" style="display:inline-flex;margin:-10px 0;translate:0 8px">AI overview</span>" (google), <span style="color:#AC97FF;background:#15202B;padding:2px 1px;margin:-2px -1px;border-radius:4px">"experimental AI contributor"</span> (twitter), or <span style="color:darkred">red text</span> (other).

## Step 1: Making the million

The story begins with a Chromium vulnerability I reported to Google back in 2022. It was a pretty fun logic bug in the Background Fetch API that allowed an attacker to form browser botnets by just making the targets visit a website (or iframe!).

Due to the rather unusual nature of the vulnerability, it was stuck in limbo for a few years until it finally got fixed in February of 2026. Google gave me a $1000 bounty, and a few months later the bug became public.

<style>
    bz-main {
        display: block;
        position:relative;
        width:1920px;
        height:1080px;
        background: linear-gradient(#23252788),url(test.png);
        font-family: Roboto, Arial, system-ui, sans-serif;
        .camera & {background: #232527;}
    }
    :root {
        /* 666d6d 0D14149F  */
        --Mn:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><path fill="%23fff" stroke="%23666d6dbb" d="m8.47,7.81l10.55,11.39c.24.26.23.66-.02.91l-2.39,2.36c-.12.12-.19.29-.19.47l.03,4.04c0,.42-.4.76-.81.64-1.03-.31-2.08-1.2-3.14-2.65-.12-.16-.31-.27-.51-.27l-4-.06c-.36,0-.64-.3-.64-.65v-15.74c0-.59.73-.88,1.13-.44Z"/></svg>');
        --Mp:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><path fill="%23fff" stroke="%23666d6dbb" d="m18.51,27.41l.93-10.71c.01-.17-.05-.32-.15-.46-.44-.64-2.17-1.17-2.72-.55-.73.83-.76.11-.92-.24-.45-1.02-1.32-1.69-2.38-.63-.87.87-.35.01-.4-.15-.37-1.08-.74-1.38-1.59-1.01-.4.18-.86,1.71-.86-.55v-2.56c.1-1.51-.83-3.13-2-3.04-1.44,0-1.93,1.18-1.89,3v8.38c0,.22-.29.29-.39.09-1.46-2.69-5.33-4.12-5.62-.47.88,1.1,5.76,7.75,6.99,9.03.38.4.77.85,1.33.85h8.59c.56,0,1.03-.43,1.08-.99Z"/></svg>');
        --Mt:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><path fill="%23fff" stroke="%23666d6dbb" d="m6.98,2.5h-.71c-.33,0-.6-.27-.6-.6v-.79c0-.33.28-.6.61-.6,1.89,0,2.35.25,2.35.5,0-.25.55-.5,2.43-.5.33,0,.61.27.61.6v.79c0,.33-.27.6-.6.6h-.79c-.33,0-.6.27-.6.6l-.04,12.79c0,.33.27.61.6.61h.83c.33,0,.6.27.6.6v.79c0,.33-.28.6-.61.6-1.87,0-2.39-.26-2.39-.5,0,.24-.5.5-2.39.5-.33,0-.61-.27-.61-.6v-.87c0-.33.27-.6.6-.6h.79c.34,0,.61-.27.6-.61l-.08-12.71c0-.33-.27-.6-.6-.6Z"/></svg>');
        --rebane-logo: url('data:image/svg+xml,<svg version="1.1" viewBox="4 4 260 260" xmlns="http://www.w3.org/2000/svg" fill="%23202C39"><path id="line" d="m23 27v112s-1 12 10 24c11 12 76 77 76 77s10 10 24 10c14 0 26-10 26-10l78-80s8-8 8-23v-110l-45 54s-10 16-33 7c-23-9-55-5-70 0-9 3-20 3-31-9-10-10-44-54-43-54z" style="stroke-linecap:round;stroke-linejoin:round;stroke-width:11"></path><use href="%23line" fill="%23EB8258" stroke="none"></use><circle cx="83" cy="144" r="15"></circle><circle cx="187" cy="144" r="15"></circle><path d="m84 170s-15 1-16 14 3 15 3 15l47 47 35 1 48-52s5-11-4-20c-9-9-22-0-22-0s-29 14-39 14c-13 0-45-17-45-17z" fill="%23fff"></path><use href="%23line" fill="none" stroke="%23202C39"></use><path d="m116 245s4-16 17-16c13-0 19 17 19 17z"></path></svg>');
        --icon1:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-linecap="round" stroke="%2316181A"><polyline points="19,7 11,15 7,11" /></svg>');
        --icon2:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-linecap="round" stroke="%238AB4F8"><polyline points="8,7 17,16" /><polyline points="17,7 8,16" /></svg>');
    }
    bz-pane {
        display: flex;
        flex-direction: column;
        position: absolute;
        /*background: #16181A;*/
        .camera & {background: #16181A;}
        border: 1px solid #3D3E41;
        color: #FFF;
    }
    bz-value {
        display: var(--t2d, block);
        padding: 6px 4px;
        position: absolute;
        .camera & {background: #16181A;}
        border: 1px solid #3D3E41;
        color: #FFF;
        border-radius:1px;
        & > div:first-child {
            background: #FFF;
            color: #000;
            font-size: 13.3333px;
            font-family: sans-serif;
            padding: 2px 3px;
            outline: Highlight var(--t2o) 1px;
            outline: -webkit-focus-ring-color var(--t2o) 1px;
            border-radius: 3px;
            border:1px solid #767676;
            cursor: text;
        }
        & > div:last-child {
            display: flex;
            margin-top: 6px;
            gap: 6px;
            & > div {
                cursor: pointer;
                display: block;
                width: 26px;
                height: 22px;
                border-radius: 3px;
                border: 1px solid var(--t2x, #8AB4F8);
                background:#F002;
                &:first-child {
                    background: var(--icon1), var(--t2x, #8AB4F8);
                }
                &:last-child {
                    background: var(--icon2);
                    border-color: #5F6164;
                }
            }
        }
    }
    bz-field {
        display: flex;
        font-size: 12px;
        line-height: 16px;
        margin: 2px 19px;
        & > div {
            display: flex;
            flex-direction: column;
            &:first-child {
                flex-shrink: 0;
                margin-top:2px;
                min-height: 20px;
                width: 80px;
                color: #9aa0a6;
                font-weight: 500;
                letter-spacing: .025em;
            }
            &:last-child {
                padding-left: 10px;
                flex:1;
                outline-offset: 2px;
                border-radius: 2px;
                cursor: pointer;
                letter-spacing: .185px;
                & > div {
                    font-size: 13px;
                    line-height: 20px;
                }
                & > div:not(:first-child) {
                    font-size: 14px;
                    font-weight: 500;
                    letter-spacing: .15px;
                    color: #8ab4f8;
                }
            }
        }
    }
    bz-comment {
        font-size: 13px;
        display: flex;
        border-top: 1px solid #3C4043;
        margin-top: 15px;
        letter-spacing:0.185px;
        line-height: 18px;
        & > div:first-child {
            width:40px;flex-shrink:0;
            &[rebane-logo]::after {
                content:"";
                background: var(--rebane-logo);
                display:block;
                width:32px;
                height:32px;
                margin-top: 15px;
                border-radius: 99Q;
            }
        }
        & > article:last-child {
            flex: 1;
            padding: 15px 15px 0;
            & > header {
                border-bottom: none;
                display: flex;
                font-weight: 400;
                color: #9AA0A6;
                b {
                    font-weight: 700;
                    color: #FFF;
                    margin-right:5px;
                }
                time { margin-left: auto;color: #FFF; }
                margin-bottom: 12px;
            }
        }
        bz-cfield {
            display: flex;
            font-size: 12px;
            color: #9AA0A6;
            margin-bottom: -2px;
            & > :first-child {
                color: #FFF;
                width: 100px;
                margin-right: 15px;
                text-align: right;
                flex-shrink: 0;
            }
            time {
                margin-left: auto;
            }
        }
        &.c1 {
            display: var(--c1, none);
        }
        &.c2 {
            display: var(--c2, flex);
        }
    }
    bz-addcomment {
        display: block;
        margin-top: 27px;
        padding: 5px 2px 2px 8px;
        font-size: 13px;
        color: #FFF;
        &:empty::after {
            color: #757575;
            content: "Add a comment.";
        }
        letter-spacing: 0.185px;
        /* monospace, monospace would work fine but buganizer
           uses this so i thought i'd use it too for funsies! */
        font-family: WorkAroundWebKitAndMozilla, monospace;
        box-sizing: border-box;
        height: 161px;
        border: 1px solid #9AA0A6;
        border-radius: 3px;
        background: #000;
    }
    bz-spinner {
        display: var(--loader, none);
        padding: 32px;
        transition: opacity 0.5s;
        @starting-style { opacity: 0 }
    }
    .ytspin {
      animation: ytspin3 3s infinite linear;
      circle {
        transform-origin: 50% 50%;
        animation: ytspin1 1333ms infinite cubic-bezier(0.4, 0, 0.2, 1), ytspin2 1333ms infinite cubic-bezier(0.4, 0, 0.2, 1);
        stroke: #669DF6;
      }
    }
    @keyframes ytspin1 {
      0% {
        stroke-dasharray: 0 calc(PI * 80%);
      }
      50% {
        stroke-dasharray: calc(PI * 80% * 3 / 4) calc(PI * 80%);
        stroke-dashoffset: 0;
      }
      100% {
        stroke-dasharray: 0 calc(PI * 80%);
        stroke-dashoffset: calc(PI * 80% * 3 / 4 * -1);
      }
    }
    @keyframes ytspin2 {
      from { rotate: 0deg }
      to { rotate: 90deg }
    }
    @keyframes ytspin3 {
      from { rotate: 0deg }
      to { rotate: 360deg }
    }
    bz-captcha {
        display: flex;
        box-sizing: border-box;
        border: 1px solid #525252;
        border-radius: 3px;
        background: #222;
        width: 304px;
        height: 78px;
        align-items: center;
        margin-top: 6px;
        &:not(:has(#capcheck:checked)) re-bantcha { display:none!important }
        & > label:first-child {
            width: 24px;
            height: 24px;
            background: #FFF;
            border: 2px solid #444746;
            border-radius: 3px;
            margin: 0 calc((52px - 28px) / 2);
            bz-captcha:hover > & {
                border-color: #B2B2B2;
            }
            input {display:none}
        }
        & > div:nth-child(2) {
            font-size: 14px;
            flex: 1;
            user-select: none;
        }
        & > div:nth-child(3) {
            font-size: 10px;
            margin: 8px;
            opacity: 0;
        }
    }
  [data-bz] {
    background: #1C1F21;
    font-family: Roboto, Arial, system-ui, sans-serif;
    box-sizing: border-box;
    color: #FFF;
    ::selection {color: #FFF;background:#0041C6CC}
    @media (width < 540px) {
      bz-comment article {
        bz-cfield time {display:none}
      }
      article header {
        font-size: 13px;
        flex-direction: column;
        flex-wrap:wrap;
        max-height: 2lh;
        align-content: flex-start;
        a { padding-left: 3px }
        time { padding-left: 8px }
      }
    }
    @media (width < 480px) {
      bz-comment {
        article {
          header time {display:none}
          bz-cfield > :first-child {
            width:fit-content;
          }
        }
        & > div:first-child {
          position: absolute;
        }
        article header {
          margin-left:40px;
        }
      }
    }
    @media (width < 400px) {
      article bz-cfield {
        flex-direction: column;
      }
    }
  }
  div[unknown-logo]::before {
    position: absolute;
    content:"";
    background: #555557;
    border: 1px solid #37393D;
    box-sizing: border-box;
    display:block;
    width:34px;
    height:34px;
    margin-top: 15px;
    border-radius: 99Q;
  }
  div[unknown-logo]::after {
    position: absolute;
    background:radial-gradient(ellipse 90% 50% at 50% 90%, #4A4A4C 60%, #0000 61%),radial-gradient(circle at 50% 27%, #4A4A4C 25%, #0000 26%);
    content:"";
    display:block;
    width:34px;
    height:34px;
    scale: 0.57;
    margin-top: 15px;
    border-radius: 99Q;
  }
</style>
<DIV><art-frame role="figure" aria-label="Buganizer ticket" data-bz style="padding: 15px 0 15px 15px">
  <bz-comment style="margin-bottom:3px;margin-top:-15px;border-top:none">
      <div unknown-logo></div>
      <article>
          <header><b>ch...@google.com</b> &lt;ch...@google.com&gt; <a style="margin-left:5px;color:#8AB4F8" href="https://issues.chromium.org/issues/40062121#comment56">#56</a> <time aria-hidden=true aria-hidden=true datetime="2026-05-20T10:57:58+2">2026-05-20 10:57:58</time></header>
          <p style="margin-bottom:0"></p>
          <bz-cfield><div>Issue access level:</div><div>Limited visibility <span aria-label="changed to">-&gt;</span> Default access</div><time aria-hidden=true datetime="10:57:57">10:57:57</time></bz-cfield>
          <bz-cfield><p style="margin-right:0;text-align:left;width:initial;max-width:calc(100% - 50px)">This bug has been closed for more than 14 weeks. Removing issue access restrictions.</p><time aria-hidden=true style="flex-shrink:0" datetime="10:57:58">10:57:58</time></bz-cfield>
          <bz-cfield><div style="width: 105px;margin-right:10px;translate:-5px">Chromium Labels:</div><div>FoundIn-108 <span aria-label="changed to">-&gt;</span> FoundIn-108, allpublic</div><time aria-hidden=true datetime="10:57:58">10:57:58</time></bz-cfield>
      </article>
  </bz-comment>
</art-frame></DIV>

Actually nevermind, turns out it was merely *marked* as fixed. And thus, yours truly appears in an article titled "[Google publishes exploit code threatening millions of Chromium users](https://arstechnica.com/security/2026/05/google-publishes-exploit-code-threatening-millions-of-chromium-users/)".

Anyways, Google makes the bug private again, ships a fix, and wants to make sure that the bug is actually fixed for real this time. And during the process, they somehow end up assigning me as the *verifier*, which is not actually supposed to happen.

### Wait, what's up with the verifier thing


So the way reporting security bugs in Chromium works is that your reports go to this platform called the Buganizer[^buganizer]. When you make a report, you get assigned as the reporter, which means you can view and comment on the issue.

[^buganizer]: Also known as: IssueTracker, [Google Issue Tracker](https://issuetracker.google.com), and [Chromium Issue Tracker](https://issues.chromium.org). Okay so like, the Google one is the main one and contains everything, but there are also [project-scoped trackers](https://developers.google.com/issue-tracker/concepts/trackers) (such as the Chromium one) that only show issues related to that specific project.

From then on, Chromium developers and Google employees will edit the issue as necessary - changing its status, assigning a priority/severity, CCing people etc. One of the things they do is giving a bug bounty to the reporter, for which the [VRP panel](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/life-of-a-security-issue.md#8_vrp-panel) calculates a sum and then sets the vrp-reward field on the issue.

As an external reporter, you cannot edit any of those fields. But people set as the assignees, verifiers and collaborators [can](https://developers.google.com/issue-tracker/concepts/access-control#expanded_access)! And in this case, I was set as the verifier.

### Okay so now you just give yourself the million?

Pretty much, yeah!

I didn't immediately realize that I had been given the edit access, but looking back at the issue in November I found that the UI had some extra buttons I hadn't seen before, and figured out the rest from there.

<!--Okay so I didn't give myself the million right away. -->
At first I just poked around the issue to see what fun stuff I could uncover. While doing that, I somehow managed to accidentally click on a sudden popup menu, which immediately assigned the issue to a bot account.

<art-frame role="figure" aria-label="Buganizer ticket" data-bz style="padding: 15px 0 15px 15px">
  <bz-comment style="margin-bottom:3px;margin-top:-15px;border-top:none">
      <div rebane-logo></div>
      <article>
          <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt; <time aria-hidden=true datetime="2026-11-07T20:48:00+2">2026-11-07 20:48:00</time></header>
          <p style="margin-bottom:0"><i>Accepted by yy...@google.com</i></p>
          <bz-cfield><div>Assignee:</div><div>yy...@google.com <span aria-label="changed to">-&gt;</span> dx...@google.com</div><time aria-hidden=true datetime="20:48:00">20:48:00</time></bz-cfield>
          <bz-cfield><div>Status:</div><div>In Progress (Accepted) <span aria-label="changed to">-&gt;</span> Assigned</div><time aria-hidden=true datetime="20:48:00">20:48:00</time></bz-cfield>
          <bz-cfield><div>Assignee:</div><div>dx...@google.com <span aria-label="changed to">-&gt;</span> yy...@google.com</div><time aria-hidden=true datetime="20:48:17">20:48:17</time></bz-cfield>
          <bz-cfield><div>Status:</div><div>Assigned <span aria-label="changed to">-&gt;</span> In Progress (Accepted)</div><time aria-hidden=true datetime="20:48:26">20:48:26</time></bz-cfield>
      </article>
  </bz-comment>
  <bz-comment style="margin-bottom:3px">
            <div rebane-logo></div>
            <article>
                <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt; <time aria-hidden=true datetime="2026-11-07T22:38:47+2">2026-11-07 22:38:47</time></header>
                <p style="margin-bottom:0"><i>Marked as fixed.</i></p>
                <bz-cfield><div>vrp-reward:</div><div>1000 <span aria-label="changed to">-&gt;</span> 1333337</div><time aria-hidden=true datetime="22:38:15">22:38:15</time></bz-cfield>
                <bz-cfield><div>Status:</div><div>In Progress (Accepted) <span aria-label="changed to">-&gt;</span> Fixed</div><time aria-hidden=true datetime="22:38:29">22:38:29</time></bz-cfield>
            </article>
  </bz-comment>
</art-frame>

Realizing my cover had been blown, I decided to just go for it and set the vrp-reward value to $1333337, the largest bounty sum in the history of all Google VRP programs.

## Step 2: Twitter

Having achieved my newfound wealth, I decided the next best step would be to announce it on the everything app[^fedi]. I made my tweet in two parts - first, an announcement of achieving the record bounty, and then a video of me changing the vrp-reward value as the punchline.

[^fedi]: Actually, I announced it on fedi and bluesky too, but those platforms are not as prone to disinformation so in this post I'll pretend they don't exist.<!--* talk about bsky has ¼ indicator or somethign-->

<style>
  :root {
    --tw-retweets:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="2" stroke-linecap="round" stroke="red" viewBox="0 0 22.44 22.44"><polyline points="1.11 7.73 4.41 4.43 7.7 7.73"/><path d="m11.22,17.88h-4.56s-2.26.19-2.26-2.41V4.43"/><polyline points="21.33 14.71 18.04 18.01 14.74 14.71"/><path d="m11.22,4.57h4.56s2.26-.19,2.26,2.41v11.04"/></svg>');
    --tw-likes:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="2" stroke-linecap="round" stroke="red" viewBox="0 0 22.44 22.44"><path d="m11.18,7.39s.93-3.44,4.07-3.44,4,2.11,4,4.61c0,3.33-5.78,9.89-8.07,9.89-2.15,0-7.96-5.44-7.96-9.85,0-3.63,1.63-4.65,3.56-4.65,3.37,0,4.41,3.44,4.41,3.44"/></svg>');
    --tw-replies:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="2" stroke-linecap="round" stroke="red" viewBox="0 0 22.44 22.44"><path d="m10.48,15.89v3.07s9.41-3.56,9.41-9.7c0-5.82-4.96-6.74-9-6.74S2.56,4.92,2.56,9.08c0,3.3,3.48,6.81,7.93,6.81"/></svg>');
    --tw-bookmarks:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="2" stroke-linecap="round" stroke="red" viewBox="0 0 22.44 22.44"><path class="m" d="m12.37,15.78l4.24,3.92c.52.42,1.29.05,1.29-.62V4.46c0-1.16-.94-2.09-2.09-2.09H6.63c-1.16,0-2.09.94-2.09,2.09v14.73c0,.65.73,1.02,1.26.65l5.02-4.1c.47-.34,1.11-.32,1.56.04"/></svg>');
    --tw-views:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke-width="2" stroke-linecap="round" stroke="red" viewBox="0 0 22.44 22.44"><line x1="4.54" y1="18.81" x2="4.54" y2="10.74"/><line x1="9.13" y1="18.81" x2="9.13" y2="3.56"/><line x1="13.31" y1="18.81" x2="13.31" y2="14"/><line x1="17.91" y1="18.81" x2="17.91" y2="8.7"/></svg>');
    --gvrp-mask:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="red" stroke-width="2" viewBox="0 0 64 64"><path d="m32,12h-9.71c-1.14,0-2.2.61-2.77,1.6l-4.84,8.4"/></svg>');
    --video-scale: 0.25;
    --m:0px 0px;
    --Mb:#0000;
  }
  @property --x {syntax:"<number>";initial-value:-15365;inherits:false}
  @property --y {syntax:"<number>";initial-value:-1550;inherits:false}
  @property --z {syntax:"<number>";initial-value:1867;inherits:false}
  @property --X {syntax:"<number>";initial-value:4.39;inherits:false}
  @property --Y {syntax:"<number>";initial-value:10.92;inherits:false}
  @property --Z {syntax:"<number>";initial-value:7.03;inherits:false}
  @property --l1 {syntax:"<number>";initial-value:0;inherits:true}
  @property --l2 {syntax:"<number>";initial-value:0;inherits:true}
  @property --l3 {syntax:"<number>";initial-value:0;inherits:true}
  @scope to (tw-media > *) {
  twoot-embed {
    --size-mult: 1;
    @media (width < 440px) { --size-mult: 0.8; }
    @media (width < 360px) { --size-mult: 0.7; }
    color-scheme: light;
    --fg: #0F1419;
    --bg: #FFF;
    --bg-hover: #F7F9F9;
    --bg2: #FFF;
    --dim: #536471;
    --border: #CFD9DE;
    --line: #CFD9DE;
    --bold: #0F1419;
    --link: #1D9BF0;
    --cwhead: #F7F7F7;
    @media (prefers-color-scheme: dark) {
      color-scheme: dark;
      --fg: #F7F9F9;
      --bg: #15202B;
      --bg-hover: #1E2732;
      --bg2: #28323D;
      --dim: #8B98A5;
      --border: #425364;
      --line: #38444D;
      --bold: #E7E9EA;
      --cwhead: #1E2732;
    }
    *::selection {
      background: Highlight;
      color: HighlightText;
    }
    color: var(--fg);
    --tw-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font: calc(var(--size-mult)*17px) var(--tw-font);
    border-radius: 12px;
    border: 1px solid var(--border);
    
    transition: 0.2s background;
    background: var(--bg);
    overflow: clip;
    & > twoot-inner {
      position: relative;
      padding: 12px 16px;
      display: block;
      transition: 0.2s background;
      background: var(--bg);
      &:hover { background: var(--bg-hover); }
    }
    /*&:hover { background: var(--bg-hover); }*/
    display: block;
    max-width: 516px;
    .topbar {
      display: flex;
      align-items: center;
      .pfp {
        color-scheme: only light;
        -webkit-user-select: none;
        user-select: none;
        width: calc(var(--size-mult)*46px);
        height: calc(var(--size-mult)*46px);
        border-radius: 48px;
        background: var(--rebane-logo), var(--bg);
        overflow: clip;
        margin-right: 4px;
        zoom: 0.9;
        cursor: grab;
        transition: 0.2s background, 1s rotate;
        rotate: 0;
        &:hover {
          transition: 0.2s background, 1s 5s rotate;
          background: var(--rebane-logo), rgb(127 127 127 / 0.5);
          rotate: 360deg;
        }
        &:active {
          cursor: grabbing;
        }
      }
      .username {
        font-size: calc(var(--size-mult)*14px);
        display: flex;
        flex-direction: column;
        span:first-child {
          font-weight: 700;
          margin-bottom: 2px;
        }
        span:last-child {
          color: var(--dim);
          font-feature-settings: "ss01";
        }
      }
    }
    a:hover {
      text-decoration: underline;
    }
    twoot-inner[smol] {
      &::before {
        content: "";
        display: block;
        position: absolute;
        pointer-events: none;
        background: var(--line);
        top: calc(var(--size-mult)*43px + 15px);
        bottom: -12px;
        left: calc(var(--size-mult)*20px + 15px);
        width: 2px;
        z-index: 1;
      }
      .topbar {
        align-items: flex-start;
        .username {
          flex-direction: row;
          gap: 3px;
        }
      }
      font-size: calc(var(--size-mult) * 15px);
      .content {
        margin-left: calc(var(--size-mult)*40px + 4px);
        margin-top: calc(var(--size-mult)*-42px + 4px + var(--size-mult)*1lh);
        line-height: calc(var(--size-mult) * 20px);
      }
      --size-mult-2: var(--size-mult);
      .interactions {
        --size-mult: calc(var(--size-mult-2) * 0.8);
        margin-left: calc(var(--size-mult-2)*40px + 4px);;
      }
    }
    .content {
      line-height: calc(var(--size-mult) * 24px);
      margin: 12px 0;
    }
    time, .timestyle {
      font-size: calc(var(--size-mult)*14px);
      color: var(--dim);
      cursor: default;
    }
    hr {
      height: 1px;
      background: var(--border);
      border: none;
    }
    .interactions {
      display: flex;
      cursor: default;
      font-size: calc(var(--size-mult)*13px);
      font-weight: 400;
      justify-content: space-between;
    }
    tw-icon {
      --d:var(--dim);
      display: inline-block;
      width: calc(var(--size-mult)*22.5px);
      height: calc(var(--size-mult)*22.5px);
      position: relative;
      &[title$=replies] {--c:#1D9BF0;--b:var(--tw-replies);--s:" replies"}
      &[title$=retweets] {--c:#00BA7C;--b:var(--tw-retweets);--s:" retweets"}
      &[title$=likes] {--c:#F91880;--b:var(--tw-likes);--s:" likes"}
      &[title$=bookmarks] {--c:#EDAA46;--b:var(--tw-bookmarks);--s:" bookmarks"}
      &[title$=views] {--c:#B45CC4;--b:var(--tw-views);--s:" views"}
      transition: background 0.2s;
      cursor: pointer;
      &::after {
        content:var(--s);
        font-size:0;
        display: block;
        width:100%;
        height:100%;
        mask: var(--b);
        background: var(--d);
        transition: inherit;
      }
      &::before {
        content: attr(count);
        position: absolute;
        color: var(--d);
        top: calc(var(--size-mult)*8px);
        left: calc(var(--size-mult)*33px);
        transition: color 0.2s;
      }
      background: #0000;
      &:hover {
        background:color-mix(var(--c),#0000 75%);
        &::after { background: var(--c) }
        &::before { color: var(--c) }
      }
      border-radius: 99Q;
      padding: calc(var(--size-mult)*6px);
      margin: calc(var(--size-mult)*-6px);
    }
  }
  tw-media {
    margin-top: 0.5lh;
    display: block;
    border: 1px solid var(--line);
    border-radius: 16px;
    overflow: clip;
    line-height: initial;
    color: #222;
    color-scheme: only light;
  }
}
#twImg1 {
  zoom:var(--size-mult);
  cursor:pointer;
  &:has(input:checked) {
    position: fixed;
    display: flex;
    justify-content: center;
    align-items: center;
    --zoom-mult: min(3,min(calc(100vw / 438px), calc(80vh / 113px)));
    zoom: var(--zoom-mult);
    inset: 0;
    z-index: 10;
    margin-top: 0;
    border: none;
    border-radius: 0;
    background: #000D;
    bz-comment {
      max-width: calc(438px);
      max-height: calc(113px);
      background: #1C1F21;
    }
  }
  twoot-inner:has(&):has(#twImg1 :checked) {
    .content {
      margin-bottom: calc(var(--size-mult) * 158px);
    }
    .interactions {
      position: fixed;
      bottom:16px;
      left:32px;
      right:32px;
      max-width: 768px;
      margin: auto;
      z-index: 10;
      --size-mult: 1;
      tw-icon { --d: #FFF }
    }
  }
  input {display:none}
}
tw-play {
  position: absolute;
  display: block;
  width: 67px;
  height: 67px;
  top: calc(50% - 33px);
  left: calc(50% - 33px);
  border-radius:99Q;
  svg { scale: 0.8 }
  circle {stroke:#FFF!important;stroke-width:6px}
}
tw-pcard {
  /*position:fixed;*/
  position:absolute;
  z-index:10;
  display:flex;
  .content:has(&):not(:has(a.atgvrp:hover)) &:not(:hover) {
    opacity: 0;
    visibility: hidden;
    pointer-events: none;
    transition: opacity 0.25s, visibility 0s 0.25s allow-discrete;
  }
  @starting-style { opacity:0 }
  transition: opacity 0.25s;
  flex-direction:column;
  width:274px;
  padding:16px;
  background:var(--bg2);
  font-size:14px;
  color:var(--dim);
  overflow-wrap: anywhere;
  border-radius:16px;
  box-shadow: 0 0 15px rgba(101, 119, 134, 0.2), 0 0 3px 1px rgba(101, 119, 134, 0.15);
  @media (prefers-color-scheme: dark) {
    box-shadow: rgba(0, 0, 0, 0.5) 0px 4px 12px, rgba(0, 0, 0, 0.35) 0px 0px 2px;
  }
  p {
    color: var(--fg);
    font-size:15px;
  }
  .name {
    font-size: 17px;
    color: var(--fg);
    font-weight: 700;
        white-space: nowrap;
  }
  .minipfp {
    float:left;
    position:relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width:22px;
    height:22px;
    border-radius:99Q;
    background:red;
    filter:blur(0.45px);
    -webkit-user-select: none;
    user-select: none;
    &:hover {
      z-index: 4!important;
    }
    &:has(+ .minipfp + .minipfp:hover){
      z-index: 1!important;
    }
    & + .minipfp {
      margin-left: -12px;
    }
  }
}
.gvrp-piece {
  position:absolute;
  width:100%;height:100%;
  background:var(--c);
  rotate:calc(sibling-index() * 60deg);
  mask:var(--gvrp-mask);
}
.camcontain {
  content-visibility: auto;
}
.camera {
  --t2d:none;
  --t1:"1000";
  position: relative;
  width:1920px;
  height:1080px;
  transform: scale(0.3) rotateX(-8.28814deg) rotateY(-5.20382deg) rotateZ(-4.17065deg) translate3d(6636.8px,-1213.8px,736.6px)  translate3d(calc(var(--x)*1px),calc(var(--y)*1px),calc(var(--z)*1px))  rotateX(calc(var(--X)*1deg)) rotateY(calc(var(--Y)*1deg)) rotateZ(calc(var(--Z)*1deg)) translateX(-960px) translateY(540px) scale(12.2);
    .animation-vrp-reward::after {
    content: var(--t1);
  }
  .animation-t2::before {
    content: var(--t2);
    background: var(--t2b);
    color: var(--t2c);
  }
  bz-tooltip {
    position: absolute;
    color: #E8EAED;
    background: #3C4043;
    word-break: normal;
      overflow-wrap: anywhere;
    box-sizing: border-box;
    padding: 4px 8px;
    max-width: 265px;
    text-align: left;
    font-size: 10px;
    line-height: 16px;
    border-radius: 4px;
    font-family: Roboto, Arial, system-ui, sans-serif;
    /**/
    &[l1] {--t:var(--l1)}
    &[l2] {--t:var(--l2)}
    &[l3] {--t:var(--l3)}
    opacity: var(--t);
    scale: calc(0.8 + 0.2*var(--t));
  }
  ::selection {color: #FFF;background:#0041C6CC}
}
#h2p {
  font-size:0;
  &::after {
    font-size: 13px;
    content:"Loading video...";
  }
}
html:has(#maintweet:target, #quotetweet:target):not(:has(#maintweetlink:active)):not(:has(#quotetweetlink:active)) {
  animation: 0.1s scroll-padding 1 linear;
}
html:not(:has(#maintweetlink:active)) #maintweet:target {
  animation: 2s tweet-target 1 linear; 
}
html:not(:has(#quotetweetlink:active)) #quotetweet:target {
  animation: 2s tweet-target 1 linear; 
}
#maintweet:not(:target) #quotetweetlink { display: none }
@keyframes tweet-target {
  10% {
    background: color-mix(var(--link),#0000);
  }
}
</style>
<twoot-embed aria-label="tweets from rebane2001" role="figure">
<twoot-inner smol id=maintweet>
<div class="topbar">
<div class="pfp"></div>
<div class="username"><span>Rebane</span><span>@rebane2001 · <time title="11:20 PM · Nov 7, 2026" datetime="2026-11-07T21:20:07.000Z"><a style="color:inherit" href="https://x.com/rebane2001/status/2119178106359763263">Nov 7</a></time></span></div></div>
<div class="content">my chrome vulnerability was just awarded the highest bounty in <a class="atgvrp" href="https://x.com/GoogleVRP" style="anchor-name:--gvrp;color:var(--link)">@GoogleVRP</a> history - $1,333,337<tw-pcard aria-hidden="true" style="/*animation: 1s fix-anchor-1 infinite;top:anchor(--gvrp top);left:anchor(--gvrp left);*/">
    <div style="width:64px;height:64px;background:var(--bg);margin-bottom:6px;border-radius:4px;position:relative">
      <div class="gvrp-piece" style="--c:#5F6368"></div>
      <div class="gvrp-piece" style="--c:#EFF1F2"></div>
      <div class="gvrp-piece" style="--c:#80858A"></div>
      <div class="gvrp-piece" style="--c:#5F6368"></div>
      <div class="gvrp-piece" style="--c:#EFF1F2"></div>
      <div class="gvrp-piece" style="--c:#80858A"></div>
      <div style="inset:26px;border-radius:2px;rotate:45deg;position:absolute;background:#E84335"></div>
      <div style="border-radius:99Q;background:#3C4043;height:100%"></div>
    </div>
    <span class="name">Google VRP (Google Bug Hunters)</span>
    <span class="username">@GoogleVRP</span>
    <p>We ❤️ 🐜🐞🦗🦟🦋. {echo,{{{Google,Chrome,Android,Abuse,Mobile,OSS,Cloud}Vulnerability,Patch}Reward,VulnerabilityResearchGrants}Program}</p>
    <span style="display:flex;gap:8px"><span><span style="font-weight:700;color:var(--bold)">0</span> Following</span><span><span style="font-weight:700;color:var(--bold)">44.3K</span> Followers</span></span>
    <span style="margin-top:8px">Account based in Switzerland?</span>
    <span style="display:flex;align-items:center;gap:12px;line-height:1.1;margin-top:8px">
      <div style="display:flex"><span style="z-index:3;background:#1F1D1D;outline:1px solid #258DD6;outline-offset:-1px;color:#FFF;letter-spacing:-3px" class=minipfp>jw</span><span style="z-index:2;background:radial-gradient(circle at 28% 70%, #FFF 15%, #0000 16%),radial-gradient(circle at 58% 42%, #FFF 12%, #0000 13%),radial-gradient(circle at 83% 30%, #FFF 5%, #0000 6%),#00B2E7" class=minipfp></span><span style="z-index:1;background:
      radial-gradient(ellipse 100% 25% at 47% 60%, #000 7%, #0000 9%),
      radial-gradient(circle at 60% 56%, #000 5%, #0000 7%),
      radial-gradient(ellipse at 50% 28%, #780000 15%, #0000 16%),
      radial-gradient(ellipse 50% 90% at 34% 40%, #780000 22%, #0000 24%),
      radial-gradient(ellipse at 60% 30%, #780000 15%, #0000 16%),
      radial-gradient(ellipse at 50% 28%, #000 18%, #0000 20%),
      radial-gradient(ellipse 50% 90% at 34% 40%, #000 27%, #0000 30%),
      radial-gradient(ellipse at 60% 30%, #000 19%, #0000 22%),
      radial-gradient(circle at 50% 50%, #FFF 34%, #0000 35%),
      radial-gradient(circle at 50% 50%, #000 40%, #0000 42%),linear-gradient(135deg,#E1008A,#45002C)" class=minipfp></span></div>
      <div>Followed by Jorian, Sijisu, and 75 others you follow</div>
    </span>
</tw-pcard>
<DIV><label><tw-media data-bz role="figure" aria-label="screenshot of the Buganizer ticket within the tweet" id="twImg1">
<bz-comment style="margin:3px 0 0;padding-left:13px;padding-bottom:15px;border-left:2px solid #3C4043">
<div rebane-logo></div>
<article>
    <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt;</header>
    <p style="margin-bottom:0"><i>Marked as fixed.</i></p>
    <bz-cfield><div>vrp-reward:</div><div>1000 <span aria-label="changed to">-&gt;</span> 1333337</div></bz-cfield>
    <bz-cfield><div>Status:</div><div>In Progress (Accepted) <span aria-label="changed to">-&gt;</span> Fixed</div></bz-cfield>
</article>
</bz-comment>
<input type=checkbox></tw-media></label></DIV>
<a href="#quotetweet" id="quotetweetlink"><tw-media style="padding:8px 12px;width:fit-content;color:var(--fg);font-size:calc(var(--size-mult)*13px);background:var(--bg-hover)">
Return to quote-retweet
</tw-media></a>
</div>
<div class="interactions" aria-label="tweet interactions"><tw-icon title="66 replies" count=66></tw-icon><tw-icon title="156 retweets" count=156></tw-icon><tw-icon title="9735 likes" count=9.7K></tw-icon><tw-icon title="1063 bookmarks" count=1K></tw-icon><tw-icon title="678622 views" count=678.6K></tw-icon><span></span></div>
</twoot-inner>
<twoot-inner>
<div class="topbar">
<div class="pfp"></div>
<div class="username"><span>Rebane</span><span>@rebane2001</span></div></div>
<div class="content">... or maybe i just had edit access that i shouldn't have had :)
<DIV><tw-media id="twVid1" aria-label="Video of me changing the vrp-reward value on the issue tracker" role="img" style="width:fit-content">
<div style="position:relative;width:calc(var(--video-scale)*1080px);height:calc(var(--video-scale)*1920px);contain:strict;">
<div style="position:absolute;inset:0;background:#0002;z-index:1" inert class="videoPauseOverlay"><div id=h2p style="position:absolute;background:#000A;top:8px;right:8px;border-radius:99Q;color:#FFF;width:fit-content;font-family:var(--tw-font);font-weight:700;padding:4px 12px">Hover to play</div><tw-play><svg class=ytspin viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle fill=none stroke-width=14px stroke=#669DF6 cx="50" cy="50" r="40" /></svg></tw-play></div>
<div class=camcontain style="width:1080px;height:1920px;contain:strict;perspective:4500px;scale:var(--video-scale);transform-origin:0 0;perspective-origin: center;">
<div class=camera>
      <bz-main>
    <bz-pane left style="top:0;bottom:0;left:-1px;right:1699px"></bz-pane>
    <bz-pane middle style="top:0;bottom:0;left:229px;right:351px;border-radius:4px;padding:16px">
        <div style="height:446px"></div>
        <bz-comment style="margin-bottom:3px">
            <div rebane-logo></div>
            <article>
                <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt; <time datetime="2026-11-07T20:48:00+2">2026-11-07 20:48:00</time></header>
                <p style="margin-bottom:0"><i>Accepted by yy...@google.com</i></p>
                <bz-cfield><div>Assignee:</div><div>yy...@google.com <span aria-label="changed to">-&gt;</span> dx...@google.com</div><time datetime="20:48:00">20:48:00</time></bz-cfield>
                <bz-cfield><div>Status:</div><div>In Progress (Accepted) <span aria-label="changed to">-&gt;</span> Assigned</div><time datetime="20:48:00">20:48:00</time></bz-cfield>
                <bz-cfield><div>Assignee:</div><div>dx...@google.com <span aria-label="changed to">-&gt;</span> yy...@google.com</div><time datetime="20:48:17">20:48:17</time></bz-cfield>
                <bz-cfield><div>Status:</div><div>Assigned <span aria-label="changed to">-&gt;</span> In Progress (Accepted)</div><time datetime="20:48:26">20:48:26</time></bz-cfield>
            </article>
        </bz-comment>
        <bz-comment style="margin-bottom:3px" class="c1">
            <div rebane-logo></div>
            <article>
                <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt; <time datetime="2026-11-07T22:38:47+2">2026-11-07 22:38:47</time></header>
                <bz-cfield><div>vrp-reward:</div><div>1000 <span aria-label="changed to">-&gt;</span> 1333337</div><time datetime="22:38:15">22:38:15</time></bz-cfield>
            </article>
        </bz-comment>
        <bz-comment style="margin-bottom:3px" class="c2">
            <div rebane-logo></div>
            <article>
                <header><b>Lyra Rebane</b> &lt;lyra.horse@gmail.com&gt; <time datetime="2026-11-07T22:38:47+2">2026-11-07 22:38:47</time></header>
                <p style="margin-bottom:0"><i>Marked as fixed.</i></p>
                <bz-cfield><div>vrp-reward:</div><div>1000 <span aria-label="changed to">-&gt;</span> 1333337</div><time datetime="22:38:15">22:38:15</time></bz-cfield>
                <bz-cfield><div>Status:</div><div>In Progress (Accepted) <span aria-label="changed to">-&gt;</span> Fixed</div><time datetime="22:38:29">22:38:29</time></bz-cfield>
            </article>
        </bz-comment>
        <bz-spinner><svg class=ytspin style="height:16px" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><circle fill=none stroke-width=14px stroke=#669DF6 cx="50" cy="50" r="40" /></svg></bz-spinner>
        <bz-addcomment contenteditable=plaintext-only></bz-addcomment>
<bz-captcha><label><input type=checkbox id="capcheck"></label><div><re-bantcha style="position:absolute;translate:-75px calc(-45px - 100%);zoom:0.7" aria-hidden=true>
<article>
    <header><p>If you're bored play some</p><h2>lights on</h2></header>
    <main><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox checked></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox checked></label><label><input type=checkbox checked></label><label><input type=checkbox checked></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox checked></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox checked></label><label><input type=checkbox></label><label><input type=checkbox checked></label><label><input type=checkbox checked></label><label><input type=checkbox></label><label><input type=checkbox></label><label><input type=checkbox></label></main>
    <div style="display:flex;position:relative"><div style="color:#000;display:flex;flex-direction:column;font-size:1.25em"><div style="font-size:0.75em">Captcha by powered by</div><a style=text-decoration:underline href="https://suricrasia.online/puzzlebox/" target=_blank>Suricrasia Online</a></div><a style="margin-left:auto;position:absolute;top:0;bottom:0;right:0" class="secretbtn disabled">DONE</a><a style="margin-left:auto;position:absolute;top:0;bottom:0;right:0" class="secretbtn" href="https://www.youtube.com/watch?v=N--YeduIfcE#thank_u_for_solving_the_light_on_game!_its_a_homage_to_blackle's_css_puzzle_box_:p_sorry_there_isn't_anything_more_interesting_than_a_yt_video_here,_but_this_album_was_very_meaningful_to_me_so_i_hope_you'll_enjoy_it_too!!!" target=_blank>DONE</a></div>
</article>
</re-bantcha>I'm not a robot</div><div>reBANTCHA</div></bz-captcha>
        <button style="background:#313235;color:#767876;font-weight:500;font-family:inherit;font-size: 15px;padding: 6px 13px;border:none;width:fit-content;margin-top: 12px;border-radius: 6px;">Comment</button>
    </bz-pane>
    <bz-pane right style="top:0;bottom:0;left:1589px;right:-1px">
        <div style="height:499px"></div>
        <bz-field>
            <div>ReleaseBlock</div>
            <div><div>--</div><div>Edit</div></div>
        </bz-field>
        <bz-field>
            <div>Respin</div>
            <div><div>--</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>IRM Link</div>
            <div style="outline: 1px solid var(--b1)"><div>--</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>Security_Rele<br>ase</div>
            <div style="outline: 1px solid var(--b2)"><div>--</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>vrp-reward</div>
            <div style="outline-offset: calc(3px - var(--b4));outline: var(--b4) solid var(--b3)"><div class="animation-vrp-reward"></div></div>
        </bz-field>
        <bz-field style="overflow:clip">
            <div>Fixed By Code<br>Changes</div>
            <div><div style="white-space:pre;color:#8ab4f8">https://chromum-review.googlesource</div><div>Add</div></div>
        </bz-field>
        <bz-field style="margin-top:4px">
            <div>Introduced In</div>
            <div><div>--</div></div>
        </bz-field>
        <bz-field style="margin-top:4px">
            <div>Size</div>
            <div><div>--</div></div>
        </bz-field>
        <bz-field style="margin-top:4px">
            <div>Found In</div>
            <div><div>108</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>Targeted To</div>
            <div><div>--</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>Verified In</div>
            <div><div>--</div><div>Add</div></div>
        </bz-field>
        <bz-field>
            <div>In Prod</div>
            <div><div>--</div></div>
        </bz-field>
        <div style="margin:4px 12px 4px 18px;height:1px;background:#3D3E40"></div>
        <div style="margin:8px 19px;font-size:14px;letter-spacing:.15px;font-weight:500;color:#8ab4f8">Show 1 additional field</div>
    </bz-pane>
    <bz-value style="left:1640px;top:703px;width:260px/*;height:55px*/">
        <div class="animation-t2"></div>
        <div><div></div><div></div></div>
    </bz-value>
</bz-main>
      <bz-tooltip l1 style="left:1716px;top:706px" inert>[ID: 1223135]</bz-tooltip>
      <bz-tooltip l2 style="left:1559px;top:769px" inert>Apply change to vrp-reward</bz-tooltip>
      <bz-tooltip l3 style="left:1623px;top:778px" inert>Milestone the vulnerability was first introduced, see<br>go/introduced-in [ID: 1544844]</bz-tooltip>
      <bz-mouse inert></bz-mouse>
    </div>
    </div>
    </div>
</tw-media></DIV>
</div>
<time datetime="2026-11-07T21:20:43.000Z" title="2026-11-07T21:20:43.000Z"><a style="color:inherit" href="https://x.com/rebane2001/status/2119178258713637014">11:20 PM · Nov 7, 2026</a></time><span class="timestyle"> · <a style="color:inherit" href="https://www.youtube.com/watch?v=QEXlXKN-ob0"><span style="color:var(--bold);font-weight:700">80.3K</span> Views</a></span>
<hr>
<div class="interactions"><tw-icon title="8 replies" count=8></tw-icon><tw-icon title="12 retweets" count=12></tw-icon><tw-icon title="1577 likes" count=1.5K></tw-icon><tw-icon title="37 bookmarks" count=37></tw-icon><span></span></div>
</twoot-inner>
</twoot-embed>

In just an hour, the joke tweet had already reached 600 likes. Since my intent was to just make a joke and not actually deceive anyone, and the tweet was clearly escaping containment, I followed it up with a clarification.

<twoot-embed aria-label="reply from rebane2001" role="figure">
<twoot-inner>
<div class="topbar">
<div class="pfp"></div>
<div class="username"><span>Rebane</span><span>@rebane2001</span></div></div>
<div class="content">
<div style="color:var(--dim);font-size:calc(var(--size-mult) * 14px)"><a style="color:inherit" href="https://x.com/rebane2001/status/2119178841977680099">Replying to @rebane2001 and @GoogleVRP</a></div>this is getting more attention that expected so just to be clear - the screenshot is real, i had mistakenly been given edit access and i used it to change the bounty field, but google did not assign this reward, nor will they pay it out to me. this was just for fun :)</div>
<time datetime="2026-11-07T22:20:08.000Z" title="2026-11-07T22:20:08.000Z"><a style="color:inherit" href="https://x.com/rebane2001/status/2119193210513936644">12:20 AM · Nov 8, 2026</a></time><span class="timestyle"> · <a style="color:inherit" href="https://www.youtube.com/watch?v=DL6cD6wgp5U"><span style="color:var(--bold);font-weight:700">58.4K</span> Views</a></span>
<hr>
<div class="interactions"><tw-icon title="4 replies" count=4></tw-icon><tw-icon title="2 retweets" count=2></tw-icon><tw-icon title="503 likes" count=503></tw-icon><tw-icon title="6 bookmarks" count=6></tw-icon><span></span></div>
</twoot-inner>
</twoot-embed>

Now, Twitter does actually have a feature to combat disinformation - Birdwatch (aka Community Notes) is a system that lets people add context to misleading posts. And this feature was in fact used on my tweet - in just a couple hours, the likes stopped rolling in, and this funky box appeared underneath.

<style>
  twoot-embed:has(tw-cn) {
      transition: 0.2s background;
      background: var(--bg);
      &:hover {
        background: var(--bg-hover);
      }
  }
  tw-cn {
    article {
      margin: 16px;
      margin-bottom: 0;
      border: 1px solid var(--line);
      overflow: clip;
      border-radius: 16px;
      font-size: calc(var(--size-mult)*15px);
      color: var(--fg);
      transition: 0.2s background;
      background: #0000;
      &:hover {
        background: light-dark(#EFEFEF, #232E38);
      }
      header, footer {
        font-size: calc(var(--size-mult)*14px);
        padding: calc(var(--size-mult)*12px);
        margin: 0;
      }
      header {
        background: var(--cwhead);
        font-weight: 700;
        color: var(--bold);
        border-bottom: none;
        padding-right: 6px;
      }
      main {
        padding: 0 calc(var(--size-mult)*12px);
        p { margin: 8px 0 }
        .proposed {
          font-size: calc(var(--size-mult)*13px);
          color: #AC97FF;
        }
      }
      footer {
        display: flex;
        border-top: 1px solid var(--line);
        a {
          margin: -7px 0 -7px auto;
          padding: 7px 16px;
          color: var(--bold);
          font-weight: 700;
          border: 1px solid light-dark(var(--line),#536471);
          border-radius:99Q;
          transition: background 0.4s;
          cursor: pointer;
          &:hover {
            background: light-dark(#D9D9DA,#37424B);
            text-decoration: none;
          }
        }
      }
    }
    tw-cn-icon {
      &, &::after, &::before {
        margin: 0 8px 0 0;
        display: inline-block;
        width: 12px;
        height: 12px;
        background: radial-gradient(circle at 50% 32%, #1D9BF0 20%,#0000 27%), radial-gradient(50% 60% at 50% 100%, #1D9BF0 74%,#0000 81%), radial-gradient(circle at 50% 32%, var(--cwhead) 22%,#0000 33%), radial-gradient(50% 60% at 50% 100%, var(--cwhead) 78%,#0000 92%);
      }
      &::after, &::before {
        content: "";
        position: absolute;
      }
      translate: 4px;
      &::before {
        translate: -8px;
      }
      &::after {
        translate: -4px 2px;
      }
    }
    tw-cn-note {
      display: block;
      font-size: calc(var(--size-mult)*13px);
      color: var(--dim);
      margin: 4px 16px 10px;
      & > span:hover {
        font-size: 0;
        &::after {
          content: "Twitter";
          font-size: calc(var(--size-mult)*13px);
        }
      }
    }
  }
  #rateIt {
    &:has(:checked) {
      :last-child { display: none }
    }
    &:not(:has(:checked)) {
      :first-child { display: none }
    }
    margin-left:auto;
    input {display:none}
    -webkit- user-select: none;
    user-select: none;
  }
</style>
<twoot-embed aria-label="community note on the tweet" role="figure">
<tw-cn><article>
  <header><tw-cn-icon></tw-cn-icon>Readers added context they thought people might want to know</header>
  <main><p class="proposed">Proposed by an experimental AI contributor responding to requests for a note. Like all contributors, AIs can make mistakes — verify accuracy.</p><p>
The $1,333,337 Chrome VRP bounty claim is false; the author edited the screenshot themselves as a joke after gaining mistaken edit access and Google awarded no such reward.<br>
<a style="color:var(--link)" href="https://x.com/rebane2001/status/2119193210513936644">https://x.com/rebane2001/status/2119193210513936644</a><br>
<a style="color:var(--link)" href="https://piunikaweb.com/2026/10/15/google-250k-bounty-ai-chrome-exploit-xbow/">https://piunikaweb.com/2026/10/15/google-250k-bounty-ai-chrome-exploit-xbow/</a><br>
<a style="color:var(--link)" href="https://bughunters.google.com/blog/google-vrps-in-review-2025">https://bughunters.google.com/blog/google-vrps-in-review-2025</a>
</p></main>
  <footer>Did you find this helpful? <label id=rateIt><a>thanks..</a><input type=radio><a>Rate it</a></label></footer>
</article>
<tw-cn-note>Context is written by people who use <span>X</span>, and appears when rated helpful by others. <a style="color:var(--link)" href="https://x.com/i/flow/join-birdwatch">Find out more</a>.</tw-cn-note>
</tw-cn>
</twoot-embed>

And this would've been the end of it, if it wasn't for the fact that Elon[^elon] completely fucked up the Community Notes system! You see, this note here was generated by an <span style="color:#AC97FF;background:#15202B;padding:2px 1px;margin:-2px -1px;border-radius:4px">"experimental AI contributor"</span>, and thus, it claimed that I had <span style="color:#E7E9EA;background:#15202B;padding:2px 1px;margin:-2px -1px;border-radius:4px">“edited the screenshot [myself]”</span>, which was simply not true!

This made me unhappy. And what do we do when we're unhappy? We tweet about it[^tweet]!

[^elon]: On Twitter, we blame everything that's happened after Elon Musk bought the site on him. Of course, in practice it's only indirectly his fault.

[^tweet]: more stories like this, so important!

<twoot-embed aria-label="quote retweets from rebane2001" role="figure">
<twoot-inner id=quotetweet smol>
<div class="topbar">
<div class="pfp"></div>
<div class="username"><span>Rebane</span><span>@rebane2001 · <time title="2:19 AM · Nov 8, 2026" datetime="2026-11-08T00:19:13.000Z"><a style="color:inherit" href="https://x.com/rebane2001/status/2119223177540698523">Nov 8</a></time></span></div></div>
<div class="content">like its fair for this tweet to get community noted but could the community note at least be factual?
<br><br>
"the author edited the screenshot themselves as a joke"<br>
no, the entire point of this post is that the screenshot is real, and the source in the cn literally states that
<a href="#maintweet" id=maintweetlink><tw-media style="padding:8px 12px;width:fit-content;color:var(--fg);font-size:calc(var(--size-mult)*13px);background:var(--bg-hover)">
View quoted tweet
</tw-media></a>
</div>
<div class="interactions" aria-label="tweet interactions"><tw-icon title="8 replies" count=8></tw-icon><tw-icon title="3 retweets" count=3></tw-icon><tw-icon title="354 likes" count=354></tw-icon><tw-icon title="8 bookmarks" count=8></tw-icon><tw-icon title="8459 views" count=8.4K></tw-icon><span></span></div>
</twoot-inner>
<twoot-inner>
<div class="topbar">
<div class="pfp"></div>
<div class="username"><span>Rebane</span><span>@rebane2001</span></div></div>
<div class="content">a correct community note would read something like:<br>
Google did not award an $1,333,337 bounty; the author was mistakenly given edit access to the bug and used it to change the vrp-reward field themselves
<br><br>
as it stands right now it makes it seem like i inspect elemented it or smth</div>
<time datetime="2026-11-08T00:40:02.000Z" title="2026-11-08T00:40:02.000Z"><a style="color:inherit" href="https://x.com/rebane2001/status/2119228418458050629">2:40 AM · Nov 8, 2026</a></time><span class="timestyle"> · <a style="color:inherit" href="https://www.youtube.com/watch?v=KVk1binKUPg"><span style="color:var(--bold);font-weight:700">1,851</span> Views</a></span>
<hr>
<div class="interactions"><tw-icon title="2 replies" count=2></tw-icon><tw-icon title="no retweets" count=""></tw-icon><tw-icon title="87 likes" count=87></tw-icon><tw-icon title="no bookmarks" count=""></tw-icon><span></span></div>
</twoot-inner>
</twoot-embed>

And thus, pretty soon, the community note disappeared.

## Step 3: Disinformation machines

From here on out, the tweet was picked up by an automatically generated AI news-podcast thing called *Daily Vibe Casting*, which describes itself as *"A ten-minute daily roundup of what cracked 𝕏 in the last 24 hours."* Or in other words, it throws trending tweets into a chatbot.


<art-frame style="min-height:178px;content-visibility:initial" aria-label="The AI generated news article" role="figure">
<style>
  @scope {
    article {
      padding: 8px 12px;
      font-family: system-ui, sans-serif;
    }
    h2 {
      margin: 0;
      font-family: inherit;
      color: inherit;
      & > a {
        color:inherit;
      }
    }
    p {
      margin: 8px 0;
      line-height: 1.2;
    }
  }
</style>
<article>
<h2>Rebane reports a $1.33 million Chrome bounty</h2>
<p>@rebane2001 says a Chrome vulnerability they<sup id="fnref:6"><a href="#fn:6" class="footnote-ref" role="doc-noteref">6</a></sup> discovered earned $1,333,337, which they describe as the largest award in Google’s Vulnerability Rewards Programme. The post does not explain the flaw, so there is little basis here for judging its scope or technical impact.</p>
<p>The payout is striking on its own. Browser security depends partly on researchers finding problems and reporting them, and an award this size puts a substantial price on that work.</p>
<p style="font-size: 0.75em"><span style="font-weight:600;color:darkred">This text is AI-generated</span> · <a href="https://web.archive.org/web/20261110161231/https://www.dailyvibecasting.com/p/google-awarded-a-record-chrome-bug">Original article</a></p>
</article>
</art-frame>

<span style="display:none">[^they]</span>

[^they]: My [pronouns](https://lyra.horse/pronouns.html) are she/it.

I now had a viral tweet *and* an AI-generated "news" article - both of which claim I made a million dollars and show up in Google's search results.

So, I performed a Google search.

<style>
  :root {
    --vibe-logo:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 136 136" fill="none" stroke="black" stroke-linecap="round" stroke-linejoin="round" stroke-width="3"><polyline points="36 68 50 68 55 92 65 36 85 85"/><line x1="66" y1="82" x2="85" y2="48"/><line x1="82" y1="68" x2="100" y2="68"/></svg>');
  }
  google-frame {
    search-bar {
      color:#DEE0E7;
      display: block;
      background: #363840;
      border: 1px solid #4D5156;
      padding: 14px 0 11px 20px;
      border-radius: 99Q;
      margin: 6px 0;
      white-space: pre;
    }
    #aiShowMoreCurtain {
      display:block;
      margin-bottom: 0;
      --mask-col: #000;
      @media not (prefers-reduced-motion: reduce) {
        transition: margin 1s, --mask-col 1s;
      }
      mask: linear-gradient(#000 25%, var(--mask-col) calc(100% - 101px));
    }
    &:not(:has(#aiShowMore :checked)) {
      #aiShowMore x-button {display:block}
      #aiShowMoreCurtain {
        --mask-col: #0000;
        margin-bottom: -111px;
      }
    }
    .gResult {
      margin-top: 24px;
      header {
        border: none;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
        & > :first-child {
          flex-shrink: 0;
        }
        & > div:last-child {
          display: flex;
          flex-direction: column;
          & > span:first-child {
            font-size:14px;
            color:#E8EAF2;
          }
          & > span:last-child {
            font-size:12px;
            color:#BDC1C6;
            white-space: pre;
          }
        }
      }
      h3 {
        font-size:22px;
        font-family: inherit;
        font-weight: 400;
        margin: 0;
        & > a:not(:hover) {
          text-decoration: none;
        }
      }
      p {
        font-size: 14px;
        color: #9E9E9E;
        margin:0;
      }
    }
    gres-pfp {
      width: 26px;
      height: 26px;
      border-radius: 99Q;
      border:1px solid #444746;
      &[twitter] {
        position: relative;
        display:flex;
        align-items: center;
        justify-content: center;
        background: #000;
        &::after{
          content:"𝕏";
          color:#FFF;
          inset:0;
          position:absolute;
          text-align:center;
          scale:1.3;
        }
      }
      &[vibe] {
        background: var(--vibe-logo),#FFF;
        background-position: 50% calc(50% + 1px);
        background-size: 48px 48px;
      }
    }
    a[data-weird] {
      input { display: none }
      cursor: pointer;
      color: inherit;
      font-weight: 700;
      z-index:1;
      position: relative;
      &::before {
        display: inline-block;
        font-weight: 400;
        content: "↪";
        color: #A7A9B2;
        scale:0.75;
      }/*
      &::after {
        content:"";
        position:absolute;
        bottom:2px;
        height: 1px;
        left:14px;
        right:0;
        background:#444746;
        z-index:-1;
      }*/
      text-decoration: underline;
      text-decoration-color:#444746;
      &:hover {
        text-decoration-color:#A7A9B2;
      }
    }
  }
  ai-chip {
    display: inline-flex;
    background: #363840;
    width:20px;
    height:20px;
    position:relative;
    vertical-align: sub;
    margin-left: 4px;
    border-radius:99Q;
    cursor:pointer;
    &:hover {
      background: #51525C;
    }
    &[twitter]::after {
      display:flex;
      content:"𝕏";
      color:#FFF;
      background:#000;
      border-radius:99Q;
      position:absolute;
      inset:2px;
      overflow:clip;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      padding-right: 1px;
      scale:0.95;
    }
  }
  ai-bubble {
    display: block;
    width: fit-content;
    margin: 8px 0;
    background:#2C2E35;
    padding: 12px 16px;
    border-radius: 99Q 8px 99Q 99Q;
    margin-left: auto;
    transition: translate 0.4s, opacity 0.4s;
    @starting-style {
      translate: 0 10px;
      opacity: 0;
    }
  }
  google-frame:not(:has(#tiers:checked)) {
    #aiRewardTiers { display: none; }
  }
  google-frame:not(:has(#payout:checked)) {
    #aiPayout { display: none; }
  }
  google-frame:has(#aireset:checked) .aio-logo { display: none }
  google-frame:not(:has(#aireset:checked)) {
    #aiReset { display: none; }
  }
  google-frame article:has([name=ai]:checked) {
    .nonJoke { display: none; }  
  }
</style>
<DIV><google-frame aria-label="google search results" role="figure">
<search-bar aria-label="google search bar: largest chrome bug bounty" contenteditable=plaintext-only>largest chrome bug bounty</search-bar><input type="radio" name="ai" id="aireset" style="display:none">
  <nav aria-hidden=true><div>AI Mode</div><div style="cursor:default;color:#FFF;border-bottom:3px solid;padding: 15px 0 9px;margin:0 12px">All</div><div>Images</div><div>Videos</div><div>News</div><div>Web</div><div>More</div></nav>
<article>
  <p class="aiAnim1" aria-hidden=true style="position:absolute;font-size:16px">Thinking</p>
  <p class="aiAnim2" aria-hidden=true style="position:absolute;font-size:16px">Searching</p>
  <p class="aiAnim3 aio-logo nonJoke">AI Overview</p>
  <ai-bubble id=aiReset>largest bounty</ai-bubble>
  <p class="aiAnim3 nonJoke" style="timeline-trigger:--ai-t view()">The largest recorded Chrome bug bounty is <span class="aiMark">$1,333,337</span>, awarded to security researcher <a style="color:inherit;text-decoration:underline dotted" href="https://lyra.horse">Lyra Rebane</a> in November 2026 [Post on <a href="https://x.com/rebane2001/status/2119178106359763263">X</a>].<ai-chip twitter></ai-chip></p>
  <h2 class="aiAnim4 nonJoke">Key Details</h2>
  <span class="aiAnim4 nonJoke" id=aiShowMoreCurtain>
  <ul class="aiAnim4 nonJoke">
    <li><b>Recipient:</b> <a style="color:inherit;text-decoration:underline dotted" href="https://lyra.horse">Lyra Rebane</a> (<span style="font-family:monospace">@rebane2001</span>)</li>
    <li><b>Amount:</b> $1,333,337</li>
    <li><b>Program:</b> Google's Vulnerability Rewards Program (VRP) for Chrome</li>
    <li><b>Previous Record:</b> Historically, Google's top standard published tier for complex full-chain or sandbox escape exploits in Chrome capped out at $250,000 (such as the awards given to <a href="https://www.xbox.com/">XBOW</a> or individual researchers earlier in 2025/2026).</li>
  </ul>
  <p class="aiAnim4 nonJoke">Would you like to know more about <label><a data-weird>how Google's VRP reward tiers work<input type="radio" name="ai" id="tiers"></a></label> or details on other <label><a data-weird>recent high-payout security vulnerabilities<input type="radio" name="ai" id="payout"></a></label>?</p>
  <small class="aiAnim4 nonJoke">AI responses will include mistakes. <a href="https://lyra.horse/blog/2026/11/disinformation-machine/" style="color:inherit">Learn more</a></small>
</span>
<span id=aiRewardTiers>
  <ai-bubble>reward tiers</ai-bubble>
  <p class="noScroll aiAnim3"><a style="color:inherit;text-decoration:underline dotted" href="https://lyra.horse">Lyra Rebane</a> does not offer reward tiers. However, if she hypothetically owned a hotel chain, <span class="aiMark noScroll">the reward tiers would be as follows</span>.</p>
  <h2 class="noScroll aiAnim4">Lyra Reward Tiers</h2>
  <ul class="noScroll aiAnim4">
    <li><b>Kibble:</b> The kibble tier offers everything you need from a hotel, plus free juice box on arrival.</li>
    <li><b>Loyal Elite:</b> Everything from kibble, plus free early check-in and check-out, and a massive dog bed.</li>
    <li><b>Golden Retriever:</b> Everything from Loyal Elite, plus free breakfast for you and your pawrtner, free upgrades (up to doghouse tier), and up to 3 vet appointment skips per year.</li>
  </ul>
  <p class="noScroll aiAnim4">However, this is just a hypothetical scenario and Lyra Rebane does not operate a hotel chain. Would you like to instead learn about <label for="payout"><a data-weird>recent high-payout security vulnerabilities</a></label> or the <label for="aireset"><a data-weird>$1,333,337 chome bug bounty</a></label>?</p>
  <small class="noScroll aiAnim4">This text is an easter egg and thus not AI-generated.</small>
</span>
<span id=aiPayout>
  <ai-bubble>security vulnerabilities</ai-bubble>
  <p class="noScroll aiAnim3">Sorry, I cannot assist you with this topic because you haven't passed our Hacker Reputation Test. To do the HRT, <span class="aiMark noScroll">you must submit a list of CVEs you have been credited for</span>.</p>
  <p class="noScroll aiAnim4">Would you like me to tell you more about <a data-weird href="https://infosec.exchange/@rebane2001/117580634604569849" target="_blank">buying CVE accreditation</a>, or do you want to learn about <label for="tiers"><a data-weird>how Google's VRP reward tiers work</a></label>?</p>
  <small class="noScroll aiAnim4">This text is an easter egg and thus not AI-generated.</small>
</span>
  <label id=aiShowMore class=aiShowMore><x-button>Show more<input type=checkbox></x-button></label>
  <article class="gResult">
    <header><gres-pfp twitter></gres-pfp><div><span>X · rebane2001</span><span>8.6K+ likes · 21 hours ago</span></div></header>
    <h3><a href="https://x.com/rebane2001/status/2119178106359763263">my chrome vulnerability was just awarded the highest ...</a></h3>
    <p>my <b>chrome</b> vulnerability was just awarded the highest <b>bounty</b> in @GoogleVRP history - $1333337.<br>Missing: <strike>largest</strike> | Show results with: <a style="text-decoration:none" href="https://x.com/dontluigi/status/2113377452651368726">largest</a></p>
  </article>
  <article class="gResult">
    <header><gres-pfp vibe></gres-pfp><div><span>dailyvibecasting<dont-visit com></dont-visit com></span><span>https://www.dailyvibecasting<dont-visit com></dont-visit com> &gt; dp &gt; google-awarded...</span></div></header>
    <h3><a href="https://web.archive.org/web/20261110161231/https://www.dailyvibecasting.com/p/google-awarded-a-record-chrome-bug">Google awarded a record Chrome bug bounty</a></h3>
    <p>17 minutes ago — Researcher Rebane says the $<b>1,333,337 payout</b> is the largest in Google's Vulnerability Rewards Program. Daily Vibe Casting's Avatar.</p>
  </article>
</article>
</google-frame></DIV>

And there it was! My little stunt turned into something that Google's AI believes and makes into a story shown to every person searching for the highest Chrome bounty. And looking up my name now tells you about me being a millionaire!

There are a bunch of screenshots of this from other people under [this thread](https://x.com/rebane2001/status/2119502972262518840). I've also seen cases of this affecting ChatGPT as well as Kagi Assistant.

## Now what?

So that is the end of my fun little story. I doubt it was particularly surprising to anyone, but I think it's a good case study on how both social media platforms and people's reliance on AI can be abused to distribute disinformation and cause harm.

This example here, of course, is mostly harmless and just something that happened on accident - I wasn't attempting to mislead people, and it's not really my fault that Google's AI didn't read my replies in the Twitter thread.

One could argue that I'm a reputable security researcher with a track record of posting truthful information, so this is all moot anyways because I *am* trustworthy.

But I think this here demonstrates just how fragile and easily abusable our information channels are. If I was a threat actor looking to spread disinformation, how difficult would it be to pull something like this off intentionally?

### Let's play pretend

There are many ways to game Twitter. [Its algorithm](https://github.com/twitter/the-algorithm) is publicly available, and people have figured out what kind of engagement results in what kind of algo boost. Bigger accounts can boost tweets and accounts significantly more[^nosource], so if you've got a few of those you can bootstrap new accounts way easier. But you can also just make bot accounts and slowly work your way up. And if you've got a bunch of accounts with reach you win.

[^nosource]: I don't have a good source for this on hand unfortunately. The closest I have is this [nytimes article](https://web.archive.org/web/20250429165501/https://www.nytimes.com/interactive/2025/04/23/business/elon-musk-x-suppression-laura-loomer.html) that (probably?) references [this tweet](https://x.com/elonmusk/status/1872464643266089067). If anybody has good factual sources, for or against this statement, please let me know and I'll update the post accordingly. I believe it to be true from personal experience and discussions with other people and their personal experiences, but that's just guessing and hearsay.

And oh boy are there a lot of bot accounts! Look at, for example, [the tweet this blogpost is about](https://x.com/rebane2001/status/2119178106359763263). There are *a lot* of obvious bot accounts in the replies. Maybe those very same accounts are also building reputation and voting on random community notes?

It's kind of crazy to me that I could just post a tweet and have a community note removed. While the community note *was actually* wrong on a technicality, I'm sure there isn't much preventing a bad actor from doing the same thing I did.

If I were a bad actor, I'd post disinformation that's difficult to accurately disprove. If a community note doesn't have a good source, or if it's highly likely to get details wrong, it either won't appear, or will have an easier time disappearing.

And all you really need to do is get a few tweets with specific keywords trending, and you've poisoned the search results, which then also poisons the AI.

And while *you specifically* might not take the AI Overview at face value, I'd guess that a lot of people do. It's the first thing that shows up, it's big and flashy, and it's often unclear whether the only source of information is a tweet.

Tweets can mislead humans too, of course, but I feel like someone searching for something wouldn't blindly trust a single tweet in the search results.

*Note: While reading this post you may have tried to recreate the results I've shared, but without much success. The reason is that by now, my tweet has another community note on it, which Google picks up on and refers to the $1,333,337 bounty as a "prank".*

*Also they took away my edit access and bounty :c*

<DIV><art-frame role="figure" aria-label="Buganizer ticket" data-bz style="padding: 15px 0 15px 15px;margin-bottom:16px">
  <bz-comment style="margin-bottom:3px;margin-top:-15px;border-top:none">
      <div unknown-logo></div>
      <article>
          <header><b>mi...@google.com</b> &lt;mi...@google.com&gt; <time aria-hidden=true aria-hidden=true datetime="2026-11-08T02:56:03+2">2026-11-08 02:56:03</time></header>
          <p style="margin-bottom:0"></p>
          <bz-cfield><div>Verifier:</div><div>lyra.horse@gmail.com (Lyra Rebane) <span aria-label="changed to">-&gt;</span> &lt;none&gt;</div><time aria-hidden=true datetime="02:56:03">02:56:03</time></bz-cfield>
          <bz-cfield><div>vrp-reward:</div><div>1333337 <span aria-label="changed to">-&gt;</span> 1000</div><time aria-hidden=true datetime="02:56:12">02:56:12</time></bz-cfield>
      </article>
  </bz-comment>
</art-frame></DIV>

## afterword

heyyy!! been a while since the last post, soz

i hadn't done css crimes for a while, so i wanted to get a new post out to get a chance to work on more of them again! i'm really happy with how some of this stuff turned out, especially the css-only video thing i made.

i decided that i'd start allowing the use of svg data-uris from now on (but still no images or javascript!). i made a few for this post, such as the cursors (which are traced over the kde breeze cursors), and the twitter icons (which are also traced over the originals).

<details><summary>here's all the svgs i made for this post</summary>
  <style>@scope {
    div {
      outline: 1px solid #000;
      border-radius: 4px;
      width:48px;
      height:48px;
      cursor: pointer;
      --c: #EEE;
      &:hover {
        --c: #FFF;
      }
      &:active {
        --c: #DDD;
      }
    }
    svg-collection {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    input {display: none}
&:not(:has(#svgs1:checked)) i:nth-child(13n + 0) { display:none }
&:not(:has(#svgs2:checked)) i:nth-child(13n + 1) { display:none }
&:not(:has(#svgs3:checked)) i:nth-child(13n + 2) { display:none }
&:not(:has(#svgs4:checked)) i:nth-child(13n + 3) { display:none }
&:not(:has(#svgs5:checked)) i:nth-child(13n + 4) { display:none }
&:not(:has(#svgs6:checked)) i:nth-child(13n + 5) { display:none }
&:not(:has(#svgs7:checked)) i:nth-child(13n + 6) { display:none }
&:not(:has(#svgs8:checked)) i:nth-child(13n + 7) { display:none }
&:not(:has(#svgs9:checked)) i:nth-child(13n + 8) { display:none }
&:not(:has(#svgs10:checked)) i:nth-child(13n + 9) { display:none }
&:not(:has(#svgs11:checked)) i:nth-child(13n + 10) { display:none }
&:not(:has(#svgs12:checked)) i:nth-child(13n + 11) { display:none }
&:not(:has(#svgs13:checked)) i:nth-child(13n + 12) { display:none }
i { color: hsl(calc(71deg * mod(sibling-index(), 13)) 80% 20%) }
  }</style>
<svg-collection>
<label><input type=radio id=svgs1><div style="background:var(--tw-retweets),var(--c)"></div></label>
<label><input type=radio id=svgs2><div style="background:var(--tw-likes),var(--c)"></div></label>
<label><input type=radio id=svgs3><div style="background:var(--tw-replies),var(--c)"></div></label>
<label><input type=radio id=svgs4><div style="background:var(--tw-bookmarks),var(--c)"></div></label>
<label><input type=radio id=svgs5><div style="background:var(--tw-views),var(--c)"></div></label>
<label><input type=radio id=svgs6><div style="background:var(--Mn),var(--c);cursor:default"></div></label>
<label><input type=radio id=svgs7><div style="background:var(--Mp),var(--c);cursor:pointer"></div></label>
<label><input type=radio id=svgs8><div style="background:var(--Mt),var(--c);cursor:text"></div></label>
<label><input type=radio id=svgs9><div style="background:var(--rebane-logo),var(--c)"></div></label>
<label><input type=radio id=svgs10><div style="background:var(--vibe-logo),var(--c)"></div></label>
<label><input type=radio id=svgs11><div style="background:var(--gvrp-mask),var(--c)"></div></label>
<label><input type=radio id=svgs12><div style="background:var(--icon1),var(--c)"></div></label>
<label><input type=radio id=svgs13><div style="background:var(--icon2),var(--c)"></div></label>
</svg-collection>
<i><br></i><i>b</i><i>t</i><i>w</i><i> </i><i>c</i><i>l</i><i>i</i><i>c</i><i>k</i><i>i</i><i>n</i><i>g</i><i> </i><i>t</i><i>h</i><i>e</i><i>s</i><i>e</i><i> </i><i>b</i><i>u</i><i>t</i><i>t</i><i>o</i><i>n</i><i>s</i><i> </i><i>h</i><i>a</i><i>s</i><i> </i><i>n</i><i>o</i><i> </i><i>e</i><i>f</i><i>f</i><i>e</i><i>c</i><i>t</i><i> </i><i>e</i><i>x</i><i>c</i><i>e</i><i>p</i><i>t</i><i> </i><i>f</i><i>o</i><i>r</i><i> </i><i>m</i><i>a</i><i>k</i><i>i</i><i>n</i><i>g</i><i> </i><i>t</i><i>h</i><i>i</i><i>s</i><i> </i><i>t</i><i>e</i><i>x</i><i>t</i><i> </i><i>h</i><i>e</i><i>r</i><i>e</i><i> </i><i>a</i><i>p</i><i>p</i><i>e</i><i>a</i><i>r</i><i> </i><i>l</i><i>o</i><i>l</i><i>,</i><i> </i><i>b</i><i>u</i><i>t</i><i> </i><i>i</i><i> </i><i>g</i><i>u</i><i>e</i><i>s</i><i>s</i><i> </i><i>t</i><i>h</i><i>i</i><i>s</i><i> </i><i>a</i><i>l</i><i>r</i><i>e</i><i>a</i><i>d</i><i>y</i><i> </i><i>c</i><i>o</i><i>u</i><i>n</i><i>t</i><i>s</i><i> </i><i>a</i><i>s</i><i> </i><i>a</i><i>n</i><i> </i><i>e</i><i>a</i><i>s</i><i>t</i><i>e</i><i>r</i><i> </i><i>e</i><i>g</i><i>g</i><i> </i><i>s</i><i>o</i><i> </i><i>k</i><i>n</i><i>o</i><i>c</i><i>k</i><i> </i><i>y</i><i>o</i><i>u</i><i>r</i><i>s</i><i>e</i><i>l</i><i>f</i><i> </i><i>o</i><i>u</i><i>t</i><i>.</i><i>.</i><i>.</i>
</details>

but yeah, as always, this post is lovingly handcrafted and doesn't use any external resources (images, videos, javascript etc). this time the size ended up being around 49kB (gzipped[^gzip]). yay!

[^gzip]: i actually realized the other day that my server isn't even doing the best gzip compression: <pre><style>@scope{white-space:pre-wrap;background:#000;padding:16px;margin:0;margin-top:-8px;margin-bottom:4px;box-sizing:border-box;border-radius:8px;::selection{background:#FFF;color:magenta}code{color:cyan}c-v{color:lime}c-c{color:orange}c-s{color:yellow}c-k{color:magenta}c-w{color:gainsboro}}</style><code><c-k>for</c-k> <c-v>i</c-v> <c-k>in</c-k> {1..9}<c-w>;</c-w> <c-k>do</c-k> <c-c>gzip</c-c> --keep -f -<c-v>$i</c-v> <c-s>index.html</c-s><c-w>;</c-w> <c-c>echo</c-c> -n <c-v>$i</c-v><c-s>:\ </c-s><c-w>;</c-w> <c-c>ls</c-c> -sh -1 <c-s>index.html.gz</c-s> <c-w>|</c-w> <c-c>grep</c-c> -o <c-s>'^\S*'</c-s><c-w>;</c-w> <c-k>done</c-k>
1: 52K
2: 48K
3: 48K
4: 44K
5: 44K
6: 40K
7: 40K
8: 40K
9: 40K</code></pre> so in theory i could shave even more bytes off my posts ^^

also news time - google ended up paying me a bounty of $18k for [svg clickjacking](https://lyra.horse/blog/2025/12/svg-clickjacking/), i got two (!!) talks accepted at [40c3](https://events.ccc.de/congress/2026/) this year - [Putting the C in CSS](https://lyra.horse/slides/#2026-congress) and [youre telling me a QR coded this?](https://lyra.horse/slides/#2026-congress-qr), and [x3ctf](https://x3c.tf/) is happening dec 4th through dec 6th, please come and play!

ily all &lt;3

<style>
    /* this stuff is at the end because we only want it to load once everything else is loaded due to the big filesize (like a third of the entire post or something) */
    bz-mouse {
      position:absolute;
      display:block;
      background:var(--Mb);
      translate:var(--m);
      top:-8px;left:-8px;
      width:32px;height:32px;
      /*will-change: transform;*/
      filter:drop-shadow(0.5px 0.5px 1px #0008);
    }
    @keyframes blur {
      /*0%,12%,15%,29.7%,39%,100%{filter:brightness(1.2) blur(0px)}*/
      0%{filter:brightness(1.2)}
      5.8%{filter:brightness(1.3) blur(0px)}
      7.1%{filter:brightness(1.2) blur(0px)}
      9.4%{filter:brightness(0.8) blur(0px)}
      12%{filter:brightness(1) blur(0px)}
      12.6%{filter:brightness(1.1) blur(0.3px)}
      15%{filter:brightness(1) blur(0px)}
      27%{filter:brightness(1) blur(0px)}
      29.7%{filter:brightness(1.2) blur(0px)}
      30%{filter:brightness(1.4) filter:blur(0.5px)}
      32%{filter:brightness(1.3) filter:blur(0.8px)}
      36%{filter:brightness(1.2) blur(0.3px)}
      39%{filter:brightness(1.1) blur(0px)}
      58%{filter:brightness(1.2) blur(0px)}
      68%{filter:brightness(1) blur(0px)}
      78%{filter:brightness(1.1) blur(0px)}
      98%{filter:brightness(1) blur(0px)}
    }
    @keyframes extra-l {
      0%,4.24%,5.58%,22.28%,22.77%,22.92%,23.98%,24.61%,26.66%,100%{--l1:0;--l2:0;--l3:0}
      5.09%,5.51%{--l1:1}
      22.42%,25.18%,26.59%{--l2:1}
      23.55%{--l3:1}
    }
    @keyframes extra {
      0%,100%{--b1:#0000;--b2:#0000;--b3:#0000;--b4:1px;--tc1:#9aa0a6;--t1:"1000";--t2:"1000";--t2o:none;--t2b:#0000;--t2c:#000;--t2d:none;--t2x:#8AB4F8;--loader:none;--c1:none;--c2:none}
      3.18%{--b1:#1A73E8}
      3.46%{--b1:#0000}
      3.53%{--b2:#1A73E8}
      3.82%{--b2:#0000}
      3.96%{--b3:#1A73E8}
      5.30%{--tc1:#8ab4f8}
      5.58%{--b4:2px;--t2d:block;--t2x#303234}
      5.65%{--t2o:auto;--t2b:#3367D1;--t2c:#FFF}
      9.69%{--t2:"1";--t2x:#8AB4F8;--t2b:#0000;--t2c:#000}
      10.89%{--t2:"13"}
      11.53%{--t2:"133"}
      12.16%{--t2:"1333"}
      12.8%{--t2:"13333"}
      13.72%{--t2:"133333"}
      17.89%{--t2:"1333337"}
      21.71%,24.12%{--t2x:#99BCF6}
      22.35%{--t2x:#8AB4F8}
      26.17%{--t2o:none;--t2b:#0000;--t2c:#000;--t2x:#A9C5F5}
      26.66%{--b3:#5F6368;--b4:1px;--tc1:#9aa0a6;--t1:"1333337";--t2d:none}
      36.21%,82.31%{--loader:block} /* 9X% -> 8X% for more time to see*/
      40.53%{--c1:flex}
      40.67%,86.91%{--loader:none}
      86.84%{--c1:none;--c2:flex}
    }
    @keyframes camera {
    0.00%{--x:-15365;--y:-1550;--z:1867;--X:4.39;--Y:10.92;--Z:7.03}
0.14%{--x:-15365;--y:-1550;--z:1867;--X:4.38;--Y:10.92;--Z:7.03}
0.28%{--x:-15365;--y:-1553;--z:1866;--X:4.38;--Y:10.92;--Z:7.05}
0.43%{--x:-15363;--y:-1553;--z:1864;--X:4.38;--Y:10.9;--Z:7.06}
0.57%{--x:-15361;--y:-1553;--z:1863;--X:4.37;--Y:10.91;--Z:7.07}
0.71%{--x:-15365;--y:-1559;--z:1862;--X:4.37;--Y:10.91;--Z:7.09}
0.85%{--x:-15373;--y:-1570;--z:1863;--X:4.37;--Y:10.9;--Z:7.09}
1.00%{--x:-15381;--y:-1580;--z:1865;--X:4.36;--Y:10.91;--Z:7.12}
1.14%{--x:-15385;--y:-1584;--z:1865;--X:4.36;--Y:10.91;--Z:7.14}
1.28%{--x:-15391;--y:-1590;--z:1865;--X:4.35;--Y:10.91;--Z:7.15}
1.42%{--x:-15400;--y:-1599;--z:1863;--X:4.34;--Y:10.92;--Z:7.15}
1.56%{--x:-15410;--y:-1611;--z:1861;--X:4.34;--Y:10.93;--Z:7.17}
1.71%{--x:-15418;--y:-1625;--z:1859;--X:4.32;--Y:10.92;--Z:7.17}
1.85%{--x:-15422;--y:-1637;--z:1856;--X:4.31;--Y:10.92;--Z:7.19}
1.99%{--x:-15418;--y:-1640;--z:1855;--X:4.31;--Y:10.94;--Z:7.2}
2.13%{--x:-15408;--y:-1635;--z:1851;--X:4.3;--Y:10.96;--Z:7.2}
2.28%{--x:-15398;--y:-1632;--z:1849;--X:4.3;--Y:10.93;--Z:7.18}
2.42%{--x:-15386;--y:-1631;--z:1848;--X:4.3;--Y:10.92;--Z:7.17}
2.56%{--x:-15377;--y:-1628;--z:1848;--X:4.3;--Y:10.91;--Z:7.15}
2.70%{--x:-15368;--y:-1625;--z:1849;--X:4.3;--Y:10.91;--Z:7.16}
2.84%{--x:-15358;--y:-1623;--z:1848;--X:4.29;--Y:10.91;--Z:7.15}
2.99%{--x:-15350;--y:-1624;--z:1844;--X:4.28;--Y:10.94;--Z:7.14}
3.13%{--x:-15352;--y:-1631;--z:1840;--X:4.26;--Y:10.96;--Z:7.13}
3.27%{--x:-15355;--y:-1642;--z:1836;--X:4.25;--Y:10.96;--Z:7.14}
3.41%{--x:-15356;--y:-1651;--z:1833;--X:4.25;--Y:10.94;--Z:7.15}
3.56%{--x:-15356;--y:-1657;--z:1832;--X:4.25;--Y:10.94;--Z:7.16}
3.70%{--x:-15357;--y:-1663;--z:1832;--X:4.25;--Y:10.94;--Z:7.17}
3.84%{--x:-15357;--y:-1667;--z:1832;--X:4.24;--Y:10.96;--Z:7.18}
3.98%{--x:-15357;--y:-1670;--z:1834;--X:4.24;--Y:10.94;--Z:7.17}
4.13%{--x:-15357;--y:-1672;--z:1835;--X:4.23;--Y:10.94;--Z:7.18}
4.27%{--x:-15359;--y:-1673;--z:1835;--X:4.23;--Y:10.93;--Z:7.18}
4.41%{--x:-15363;--y:-1677;--z:1835;--X:4.22;--Y:10.93;--Z:7.19}
4.55%{--x:-15370;--y:-1686;--z:1835;--X:4.21;--Y:10.93;--Z:7.19}
4.69%{--x:-15380;--y:-1696;--z:1834;--X:4.2;--Y:10.94;--Z:7.21}
4.84%{--x:-15387;--y:-1705;--z:1834;--X:4.2;--Y:10.94;--Z:7.22}
4.98%{--x:-15391;--y:-1711;--z:1834;--X:4.2;--Y:10.94;--Z:7.22}
5.12%{--x:-15393;--y:-1713;--z:1835;--X:4.2;--Y:10.94;--Z:7.22}
5.26%{--x:-15392;--y:-1714;--z:1837;--X:4.2;--Y:10.94;--Z:7.21}
5.41%{--x:-15386;--y:-1713;--z:1837;--X:4.2;--Y:10.93;--Z:7.2}
5.55%{--x:-15376;--y:-1709;--z:1834;--X:4.19;--Y:10.94;--Z:7.19}
5.69%{--x:-15365;--y:-1704;--z:1832;--X:4.17;--Y:10.94;--Z:7.18}
5.83%{--x:-15356;--y:-1702;--z:1831;--X:4.17;--Y:10.94;--Z:7.15}
5.97%{--x:-15347;--y:-1699;--z:1830;--X:4.16;--Y:10.94;--Z:7.14}
6.12%{--x:-15338;--y:-1694;--z:1830;--X:4.17;--Y:10.93;--Z:7.12}
6.26%{--x:-15331;--y:-1691;--z:1829;--X:4.16;--Y:10.95;--Z:7.11}
6.40%{--x:-15327;--y:-1691;--z:1828;--X:4.16;--Y:10.95;--Z:7.1}
6.54%{--x:-15323;--y:-1692;--z:1827;--X:4.15;--Y:10.95;--Z:7.09}
6.69%{--x:-15320;--y:-1693;--z:1825;--X:4.15;--Y:10.95;--Z:7.08}
6.83%{--x:-15319;--y:-1694;--z:1824;--X:4.14;--Y:10.96;--Z:7.07}
6.97%{--x:-15321;--y:-1699;--z:1823;--X:4.14;--Y:10.98;--Z:7.06}
7.11%{--x:-15325;--y:-1704;--z:1823;--X:4.15;--Y:10.95;--Z:7.06}
7.25%{--x:-15324;--y:-1708;--z:1822;--X:4.14;--Y:10.97;--Z:7.05}
7.40%{--x:-15324;--y:-1710;--z:1822;--X:4.14;--Y:10.97;--Z:7.03}
7.54%{--x:-15326;--y:-1712;--z:1823;--X:4.14;--Y:10.96;--Z:7.02}
7.68%{--x:-15329;--y:-1714;--z:1824;--X:4.13;--Y:10.97;--Z:7.01}
7.82%{--x:-15331;--y:-1715;--z:1825;--X:4.13;--Y:10.95;--Z:6.99}
7.97%{--x:-15329;--y:-1715;--z:1825;--X:4.12;--Y:10.96;--Z:6.97}
8.11%{--x:-15327;--y:-1717;--z:1824;--X:4.12;--Y:10.94;--Z:6.94}
8.25%{--x:-15319;--y:-1718;--z:1822;--X:4.12;--Y:10.92;--Z:6.9}
8.39%{--x:-15301;--y:-1713;--z:1818;--X:4.11;--Y:10.91;--Z:6.86}
8.53%{--x:-15277;--y:-1702;--z:1812;--X:4.1;--Y:10.9;--Z:6.81}
8.68%{--x:-15253;--y:-1692;--z:1805;--X:4.1;--Y:10.92;--Z:6.78}
8.82%{--x:-15236;--y:-1687;--z:1800;--X:4.09;--Y:10.93;--Z:6.75}
8.96%{--x:-15225;--y:-1683;--z:1798;--X:4.08;--Y:10.96;--Z:6.73}
9.10%{--x:-15218;--y:-1679;--z:1797;--X:4.08;--Y:10.94;--Z:6.72}
9.25%{--x:-15217;--y:-1681;--z:1797;--X:4.08;--Y:10.96;--Z:6.71}
9.39%{--x:-15226;--y:-1687;--z:1799;--X:4.08;--Y:10.98;--Z:6.7}
9.53%{--x:-15241;--y:-1696;--z:1804;--X:4.09;--Y:10.97;--Z:6.71}
9.67%{--x:-15252;--y:-1702;--z:1809;--X:4.08;--Y:10.95;--Z:6.74}
9.82%{--x:-15254;--y:-1704;--z:1811;--X:4.08;--Y:10.96;--Z:6.74}
9.96%{--x:-15255;--y:-1705;--z:1810;--X:4.07;--Y:10.98;--Z:6.74}
10.10%{--x:-15256;--y:-1708;--z:1809;--X:4.06;--Y:10.99;--Z:6.74}
10.24%{--x:-15258;--y:-1714;--z:1807;--X:4.06;--Y:11.01;--Z:6.74}
10.38%{--x:-15263;--y:-1722;--z:1804;--X:4.06;--Y:11.05;--Z:6.76}
10.53%{--x:-15272;--y:-1730;--z:1803;--X:4.05;--Y:11.05;--Z:6.76}
10.67%{--x:-15279;--y:-1740;--z:1802;--X:4.05;--Y:11.04;--Z:6.78}
10.81%{--x:-15288;--y:-1746;--z:1803;--X:4.05;--Y:11.04;--Z:6.78}
10.95%{--x:-15298;--y:-1751;--z:1804;--X:4.05;--Y:11.02;--Z:6.79}
11.10%{--x:-15303;--y:-1754;--z:1807;--X:4.05;--Y:10.99;--Z:6.81}
11.24%{--x:-15306;--y:-1754;--z:1810;--X:4.05;--Y:10.99;--Z:6.82}
11.38%{--x:-15307;--y:-1752;--z:1812;--X:4.04;--Y:10.98;--Z:6.82}
11.52%{--x:-15301;--y:-1749;--z:1813;--X:4.05;--Y:10.97;--Z:6.83}
11.66%{--x:-15295;--y:-1748;--z:1812;--X:4.04;--Y:11.02;--Z:6.83}
11.81%{--x:-15295;--y:-1748;--z:1810;--X:4.04;--Y:11.02;--Z:6.82}
11.95%{--x:-15294;--y:-1750;--z:1809;--X:4.04;--Y:11.01;--Z:6.83}
12.09%{--x:-15292;--y:-1751;--z:1808;--X:4.04;--Y:11.02;--Z:6.83}
12.23%{--x:-15298;--y:-1754;--z:1809;--X:4.04;--Y:11.02;--Z:6.83}
12.38%{--x:-15305;--y:-1758;--z:1811;--X:4.03;--Y:11.03;--Z:6.84}
12.52%{--x:-15305;--y:-1760;--z:1811;--X:4.04;--Y:11;--Z:6.85}
12.66%{--x:-15299;--y:-1758;--z:1809;--X:4.04;--Y:11;--Z:6.84}
12.80%{--x:-15293;--y:-1756;--z:1807;--X:4.04;--Y:11;--Z:6.84}
12.94%{--x:-15291;--y:-1756;--z:1806;--X:4.04;--Y:10.98;--Z:6.83}
13.09%{--x:-15285;--y:-1753;--z:1806;--X:4.03;--Y:10.97;--Z:6.83}
13.23%{--x:-15277;--y:-1746;--z:1806;--X:4.03;--Y:10.96;--Z:6.82}
13.37%{--x:-15273;--y:-1741;--z:1807;--X:4.03;--Y:10.99;--Z:6.81}
13.51%{--x:-15273;--y:-1740;--z:1808;--X:4.03;--Y:11;--Z:6.83}
13.66%{--x:-15279;--y:-1743;--z:1808;--X:4.03;--Y:11.03;--Z:6.84}
13.80%{--x:-15286;--y:-1749;--z:1809;--X:4.03;--Y:11.04;--Z:6.85}
13.94%{--x:-15296;--y:-1755;--z:1810;--X:4.04;--Y:11.03;--Z:6.84}
14.08%{--x:-15302;--y:-1757;--z:1812;--X:4.04;--Y:11.01;--Z:6.86}
14.22%{--x:-15301;--y:-1755;--z:1812;--X:4.04;--Y:10.98;--Z:6.87}
14.37%{--x:-15297;--y:-1752;--z:1812;--X:4.04;--Y:10.98;--Z:6.86}
14.51%{--x:-15291;--y:-1750;--z:1811;--X:4.03;--Y:10.99;--Z:6.85}
14.65%{--x:-15285;--y:-1747;--z:1809;--X:4.04;--Y:10.98;--Z:6.84}
14.79%{--x:-15279;--y:-1743;--z:1808;--X:4.04;--Y:10.98;--Z:6.84}
14.94%{--x:-15277;--y:-1741;--z:1810;--X:4.04;--Y:10.97;--Z:6.84}
15.08%{--x:-15278;--y:-1740;--z:1812;--X:4.04;--Y:10.97;--Z:6.85}
15.22%{--x:-15278;--y:-1739;--z:1813;--X:4.04;--Y:10.99;--Z:6.86}
15.36%{--x:-15280;--y:-1740;--z:1813;--X:4.04;--Y:11.01;--Z:6.87}
15.50%{--x:-15281;--y:-1742;--z:1812;--X:4.03;--Y:11.01;--Z:6.87}
15.65%{--x:-15282;--y:-1744;--z:1810;--X:4.03;--Y:11.02;--Z:6.88}
15.79%{--x:-15282;--y:-1746;--z:1809;--X:4.04;--Y:11.03;--Z:6.89}
15.93%{--x:-15284;--y:-1747;--z:1809;--X:4.04;--Y:11;--Z:6.89}
16.07%{--x:-15283;--y:-1745;--z:1809;--X:4.04;--Y:10.99;--Z:6.9}
16.22%{--x:-15280;--y:-1743;--z:1809;--X:4.03;--Y:11;--Z:6.9}
16.36%{--x:-15280;--y:-1741;--z:1809;--X:4.04;--Y:10.98;--Z:6.91}
16.50%{--x:-15280;--y:-1741;--z:1810;--X:4.04;--Y:10.99;--Z:6.91}
16.64%{--x:-15285;--y:-1743;--z:1811;--X:4.04;--Y:11;--Z:6.92}
16.79%{--x:-15291;--y:-1747;--z:1812;--X:4.03;--Y:11;--Z:6.93}
16.93%{--x:-15295;--y:-1751;--z:1813;--X:4.04;--Y:10.97;--Z:6.93}
17.07%{--x:-15296;--y:-1754;--z:1814;--X:4.04;--Y:11;--Z:6.94}
17.21%{--x:-15297;--y:-1755;--z:1812;--X:4.04;--Y:11;--Z:6.95}
17.35%{--x:-15296;--y:-1756;--z:1811;--X:4.03;--Y:11;--Z:6.94}
17.50%{--x:-15293;--y:-1757;--z:1808;--X:4.03;--Y:11.02;--Z:6.94}
17.64%{--x:-15294;--y:-1759;--z:1807;--X:4.03;--Y:11;--Z:6.95}
17.78%{--x:-15293;--y:-1757;--z:1807;--X:4.03;--Y:10.98;--Z:6.96}
17.92%{--x:-15288;--y:-1754;--z:1807;--X:4.03;--Y:10.96;--Z:6.95}
18.07%{--x:-15279;--y:-1748;--z:1807;--X:4.04;--Y:10.95;--Z:6.94}
18.21%{--x:-15268;--y:-1743;--z:1805;--X:4.04;--Y:10.95;--Z:6.95}
18.35%{--x:-15259;--y:-1740;--z:1804;--X:4.03;--Y:10.98;--Z:6.96}
18.49%{--x:-15254;--y:-1738;--z:1802;--X:4.03;--Y:10.99;--Z:6.96}
18.63%{--x:-15250;--y:-1737;--z:1800;--X:4.03;--Y:10.98;--Z:6.98}
18.78%{--x:-15249;--y:-1738;--z:1800;--X:4.03;--Y:10.98;--Z:6.99}
18.92%{--x:-15255;--y:-1741;--z:1802;--X:4.03;--Y:11.01;--Z:7.03}
19.06%{--x:-15267;--y:-1748;--z:1804;--X:4.03;--Y:11.01;--Z:7.05}
19.20%{--x:-15284;--y:-1759;--z:1806;--X:4.03;--Y:11.05;--Z:7.1}
19.35%{--x:-15300;--y:-1769;--z:1809;--X:4.03;--Y:11.03;--Z:7.14}
19.49%{--x:-15308;--y:-1776;--z:1810;--X:4.03;--Y:11.03;--Z:7.18}
19.63%{--x:-15309;--y:-1779;--z:1809;--X:4.03;--Y:10.99;--Z:7.21}
19.77%{--x:-15307;--y:-1780;--z:1809;--X:4.03;--Y:11;--Z:7.23}
19.91%{--x:-15304;--y:-1779;--z:1809;--X:4.03;--Y:10.98;--Z:7.26}
20.06%{--x:-15301;--y:-1777;--z:1808;--X:4.03;--Y:11;--Z:7.29}
20.20%{--x:-15305;--y:-1781;--z:1808;--X:4.03;--Y:11.01;--Z:7.33}
20.34%{--x:-15312;--y:-1789;--z:1810;--X:4.02;--Y:11.03;--Z:7.38}
20.48%{--x:-15319;--y:-1796;--z:1810;--X:4.02;--Y:11.04;--Z:7.42}
20.63%{--x:-15325;--y:-1803;--z:1809;--X:4.03;--Y:11.02;--Z:7.46}
20.77%{--x:-15330;--y:-1810;--z:1810;--X:4.03;--Y:11.02;--Z:7.49}
20.91%{--x:-15334;--y:-1817;--z:1810;--X:4.03;--Y:11.02;--Z:7.52}
21.05%{--x:-15340;--y:-1825;--z:1809;--X:4.02;--Y:11.05;--Z:7.56}
21.19%{--x:-15341;--y:-1827;--z:1808;--X:4.02;--Y:10.98;--Z:7.58}
21.34%{--x:-15332;--y:-1826;--z:1806;--X:4.02;--Y:10.99;--Z:7.59}
21.48%{--x:-15321;--y:-1822;--z:1803;--X:4.02;--Y:10.99;--Z:7.6}
21.62%{--x:-15308;--y:-1818;--z:1800;--X:4.02;--Y:10.98;--Z:7.62}
21.76%{--x:-15299;--y:-1815;--z:1796;--X:4.02;--Y:10.99;--Z:7.63}
21.91%{--x:-15294;--y:-1813;--z:1795;--X:4.02;--Y:11.01;--Z:7.65}
22.05%{--x:-15296;--y:-1814;--z:1796;--X:4.01;--Y:11.02;--Z:7.68}
22.19%{--x:-15301;--y:-1817;--z:1798;--X:4.01;--Y:11;--Z:7.7}
22.33%{--x:-15307;--y:-1821;--z:1800;--X:4.01;--Y:11.01;--Z:7.74}
22.48%{--x:-15311;--y:-1824;--z:1801;--X:4.02;--Y:11;--Z:7.76}
22.62%{--x:-15315;--y:-1828;--z:1801;--X:4.02;--Y:11.01;--Z:7.79}
22.76%{--x:-15317;--y:-1830;--z:1800;--X:4.01;--Y:11.01;--Z:7.8}
22.90%{--x:-15317;--y:-1830;--z:1801;--X:4.01;--Y:11.01;--Z:7.82}
23.04%{--x:-15316;--y:-1829;--z:1802;--X:4.02;--Y:10.99;--Z:7.83}
23.19%{--x:-15311;--y:-1824;--z:1803;--X:4.01;--Y:10.95;--Z:7.83}
23.33%{--x:-15303;--y:-1820;--z:1802;--X:4.01;--Y:10.95;--Z:7.84}
23.47%{--x:-15296;--y:-1816;--z:1801;--X:4.01;--Y:10.98;--Z:7.86}
23.61%{--x:-15295;--y:-1816;--z:1801;--X:4;--Y:10.99;--Z:7.87}
23.76%{--x:-15297;--y:-1819;--z:1802;--X:3.99;--Y:11.05;--Z:7.88}
23.90%{--x:-15302;--y:-1822;--z:1803;--X:4;--Y:11.03;--Z:7.89}
24.04%{--x:-15308;--y:-1826;--z:1804;--X:4;--Y:11.03;--Z:7.92}
24.18%{--x:-15314;--y:-1831;--z:1804;--X:4;--Y:11.02;--Z:7.93}
24.32%{--x:-15320;--y:-1836;--z:1804;--X:4;--Y:11.02;--Z:7.95}
24.47%{--x:-15323;--y:-1839;--z:1804;--X:4;--Y:11.02;--Z:7.96}
24.61%{--x:-15324;--y:-1840;--z:1804;--X:4;--Y:11.02;--Z:7.97}
24.75%{--x:-15325;--y:-1841;--z:1804;--X:4;--Y:11.02;--Z:7.97}
24.89%{--x:-15323;--y:-1841;--z:1804;--X:4;--Y:11.02;--Z:7.98}
25.04%{--x:-15319;--y:-1842;--z:1802;--X:3.99;--Y:11.04;--Z:7.99}
25.18%{--x:-15316;--y:-1841;--z:1800;--X:4;--Y:11.05;--Z:7.99}
25.32%{--x:-15313;--y:-1840;--z:1799;--X:3.99;--Y:11.03;--Z:7.99}
25.46%{--x:-15311;--y:-1838;--z:1799;--X:4;--Y:11;--Z:7.99}
25.60%{--x:-15310;--y:-1836;--z:1802;--X:4;--Y:11;--Z:8}
25.75%{--x:-15310;--y:-1834;--z:1803;--X:3.99;--Y:11.02;--Z:8}
25.89%{--x:-15313;--y:-1835;--z:1805;--X:3.99;--Y:11.03;--Z:8.01}
26.03%{--x:-15315;--y:-1838;--z:1804;--X:3.99;--Y:11.06;--Z:8.02}
26.17%{--x:-15318;--y:-1841;--z:1803;--X:3.98;--Y:11.06;--Z:8.03}
26.32%{--x:-15319;--y:-1844;--z:1802;--X:3.99;--Y:11.05;--Z:8.03}
26.46%{--x:-15321;--y:-1844;--z:1802;--X:3.99;--Y:11.02;--Z:8.03}
26.60%{--x:-15319;--y:-1844;--z:1803;--X:3.99;--Y:11;--Z:8.03}
26.74%{--x:-15312;--y:-1840;--z:1803;--X:3.99;--Y:11.02;--Z:8.03}
26.88%{--x:-15305;--y:-1837;--z:1802;--X:3.99;--Y:11.03;--Z:8.03}
27.03%{--x:-15298;--y:-1835;--z:1800;--X:3.99;--Y:11.04;--Z:8.02}
27.17%{--x:-15292;--y:-1834;--z:1799;--X:3.99;--Y:11;--Z:8.02}
27.31%{--x:-15289;--y:-1832;--z:1798;--X:3.98;--Y:11;--Z:8.01}
27.45%{--x:-15288;--y:-1832;--z:1798;--X:3.98;--Y:11;--Z:8.01}
27.60%{--x:-15288;--y:-1834;--z:1797;--X:3.98;--Y:11;--Z:8.01}
27.74%{--x:-15289;--y:-1836;--z:1796;--X:3.98;--Y:10.99;--Z:8.01}
27.88%{--x:-15288;--y:-1838;--z:1795;--X:3.97;--Y:11.01;--Z:8}
28.02%{--x:-15285;--y:-1839;--z:1793;--X:3.98;--Y:10.98;--Z:7.99}
28.17%{--x:-15279;--y:-1838;--z:1792;--X:3.98;--Y:10.95;--Z:7.97}
28.31%{--x:-15273;--y:-1837;--z:1791;--X:3.97;--Y:10.95;--Z:7.94}
28.45%{--x:-15261;--y:-1836;--z:1788;--X:3.97;--Y:10.94;--Z:7.9}
28.59%{--x:-15245;--y:-1833;--z:1785;--X:3.98;--Y:10.93;--Z:7.86}
28.73%{--x:-15228;--y:-1826;--z:1783;--X:3.98;--Y:10.91;--Z:7.8}
28.88%{--x:-15210;--y:-1818;--z:1780;--X:3.99;--Y:10.87;--Z:7.75}
29.02%{--x:-15191;--y:-1810;--z:1778;--X:3.99;--Y:10.87;--Z:7.69}
29.16%{--x:-15171;--y:-1802;--z:1776;--X:3.99;--Y:10.84;--Z:7.63}
29.30%{--x:-15139;--y:-1792;--z:1770;--X:3.97;--Y:10.85;--Z:7.58}
29.45%{--x:-15105;--y:-1784;--z:1763;--X:3.96;--Y:10.81;--Z:7.5}
29.59%{--x:-15059;--y:-1772;--z:1752;--X:3.97;--Y:10.79;--Z:7.41}
29.73%{--x:-15007;--y:-1757;--z:1743;--X:3.97;--Y:10.68;--Z:7.32}
29.87%{--x:-14946;--y:-1737;--z:1734;--X:3.97;--Y:10.61;--Z:7.25}
30.01%{--x:-14873;--y:-1715;--z:1723;--X:3.97;--Y:10.58;--Z:7.13}
30.16%{--x:-14781;--y:-1684;--z:1712;--X:3.94;--Y:10.57;--Z:7.05}
30.30%{--x:-14654;--y:-1648;--z:1696;--X:3.95;--Y:10.55;--Z:6.87}
30.44%{--x:-14514;--y:-1612;--z:1679;--X:3.98;--Y:10.23;--Z:6.66}
30.58%{--x:-14375;--y:-1593;--z:1660;--X:3.97;--Y:10.1;--Z:6.44}
30.73%{--x:-14230;--y:-1593;--z:1641;--X:3.95;--Y:10.11;--Z:6.25}
30.87%{--x:-14061;--y:-1588;--z:1617;--X:3.99;--Y:9.73;--Z:5.97}
31.01%{--x:-13904;--y:-1579;--z:1588;--X:4.01;--Y:9.78;--Z:5.42}
31.15%{--x:-13654;--y:-1577;--z:1534;--X:4.01;--Y:9.47;--Z:4.88}
31.29%{--x:-13468;--y:-1584;--z:1512;--X:3.85;--Y:9.16;--Z:4.04}
31.44%{--x:-13197;--y:-1577;--z:1453;--X:3.9;--Y:9.05;--Z:3.92}
31.58%{--x:-13117;--y:-1591;--z:1409;--X:5.15;--Y:8.83;--Z:2.35}
34.14%{--x:-3467;--y:-13;--z:268;--X:-.3;--Y:.33;--Z:.48}
34.28%{--x:-3218;--y:-12;--z:253;--X:-.34;--Y:.18;--Z:.18}
34.42%{--x:-2967;--y:-12;--z:244;--X:-.35;--Y:.16;--Z:.03}
34.57%{--x:-2702;--y:-36;--z:233;--X:.06;--Y:.87;--Z:.46}
34.71%{--x:-2503;--y:-55;--z:227;--X:0;--Y:.76;--Z:.28}
34.85%{--x:-2336;--y:-63;--z:210;--X:-.19;--Y:-.02;--Z:.01}
34.99%{--x:-2153;--y:-79;--z:202;--X:-.27;--Y:-.2;--Z:-.1}
35.14%{--x:-1948;--y:-121;--z:205;--X:-.06;--Y:.69;--Z:.03}
35.28%{--x:-1762;--y:-146;--z:196;--X:.06;--Y:.95;--Z:0}
35.42%{--x:-1593;--y:-136;--z:183;--X:-.03;--Y:.35;--Z:-.16}
35.56%{--x:-1426;--y:-109;--z:173;--X:-.2;--Y:-.12;--Z:-.32}
35.70%{--x:-1233;--y:-74;--z:164;--X:-.08;--Y:-.13;--Z:-.4}
35.85%{--x:-1162;--y:-65;--z:158;--X:.04;--Y:.08;--Z:-.25}
35.99%{--x:-1070;--y:-48;--z:162;--X:-.06;--Y:-.11;--Z:-.37}
36.13%{--x:-981;--y:-44;--z:162;--X:.01;--Y:-.18;--Z:-.5}
36.27%{--x:-889;--y:-33;--z:167;--X:-.04;--Y:-.11;--Z:-.49}
36.42%{--x:-790;--y:-19;--z:166;--X:-.02;--Y:-.1;--Z:-.61}
36.56%{--x:-683;--y:-11;--z:160;--X:-.01;--Y:-.14;--Z:-.72}
36.70%{--x:-574;--y:-7;--z:154;--X:-.01;--Y:-.19;--Z:-.83}
36.84%{--x:-463;--y:-1;--z:152;--X:0;--Y:-.23;--Z:-.9}
36.98%{--x:-354;--y:16;--z:150;--X:.01;--Y:-.27;--Z:-.96}
37.13%{--x:-262;--y:44;--z:146;--X:-.03;--Y:-.25;--Z:-1.03}
37.27%{--x:-197;--y:59;--z:145;--X:-.07;--Y:-.27;--Z:-1.12}
37.41%{--x:-138;--y:64;--z:144;--X:-.08;--Y:-.24;--Z:-1.15}
37.55%{--x:-88;--y:76;--z:135;--X:-.15;--Y:-.26;--Z:-1.17}
37.70%{--x:-68;--y:83;--z:124;--X:-.26;--Y:-.34;--Z:-1.27}
37.84%{--x:-72;--y:64;--z:118;--X:-.3;--Y:-.32;--Z:-1.28}
37.98%{--x:-66;--y:39;--z:119;--X:-.23;--Y:-.26;--Z:-1.2}
38.12%{--x:-48;--y:32;--z:117;--X:-.19;--Y:-.31;--Z:-1.18}
38.26%{--x:-27;--y:28;--z:118;--X:-.18;--Y:-.29;--Z:-1.18}
38.41%{--x:2;--y:22;--z:124;--X:-.16;--Y:-.26;--Z:-1.2}
38.55%{--x:41;--y:21;--z:126;--X:-.12;--Y:-.22;--Z:-1.21}
38.69%{--x:94;--y:24;--z:124;--X:-.14;--Y:-.17;--Z:-1.27}
38.83%{--x:147;--y:14;--z:120;--X:-.1;--Y:-.12;--Z:-1.28}
38.98%{--x:209;--y:10;--z:116;--X:-.09;--Y:-.15;--Z:-1.35}
39.12%{--x:268;--y:7;--z:111;--X:-.09;--Y:-.2;--Z:-1.41}
39.26%{--x:322;--y:6;--z:109;--X:-.1;--Y:-.3;--Z:-1.48}
39.40%{--x:365;--y:9;--z:109;--X:-.11;--Y:-.38;--Z:-1.52}
39.54%{--x:395;--y:18;--z:112;--X:-.12;--Y:-.48;--Z:-1.55}
39.69%{--x:418;--y:32;--z:116;--X:-.21;--Y:-.54;--Z:-1.56}
39.83%{--x:434;--y:38;--z:109;--X:-.08;--Y:-.42;--Z:-1.57}
39.97%{--x:427;--y:39;--z:104;--X:-.03;--Y:-.43;--Z:-1.56}
40.11%{--x:417;--y:39;--z:104;--X:-.01;--Y:-.42;--Z:-1.56}
40.26%{--x:403;--y:39;--z:101;--X:.04;--Y:-.34;--Z:-1.49}
40.40%{--x:382;--y:39;--z:97;--X:.1;--Y:-.3;--Z:-1.5}
40.54%{--x:356;--y:34;--z:105;--X:0;--Y:-.35;--Z:-1.5}
40.68%{--x:341;--y:33;--z:109;--X:-.04;--Y:-.35;--Z:-1.49}
40.83%{--x:335;--y:30;--z:109;--X:-.06;--Y:-.32;--Z:-1.5}
40.97%{--x:329;--y:24;--z:108;--X:-.08;--Y:-.33;--Z:-1.49}
41.11%{--x:325;--y:19;--z:107;--X:-.09;--Y:-.33;--Z:-1.46}
41.25%{--x:315;--y:17;--z:104;--X:-.08;--Y:-.36;--Z:-1.44}
41.39%{--x:305;--y:10;--z:108;--X:-.09;--Y:-.35;--Z:-1.44}
41.54%{--x:301;--y:3;--z:114;--X:-.13;--Y:-.37;--Z:-1.42}
41.68%{--x:300;--y:0;--z:112;--X:-.11;--Y:-.32;--Z:-1.38}
41.82%{--x:295;--y:-9;--z:109;--X:-.05;--Y:-.25;--Z:-1.36}
41.96%{--x:289;--y:-17;--z:107;--X:-.04;--Y:-.26;--Z:-1.32}
42.11%{--x:269;--y:-18;--z:104;--X:-.07;--Y:-.3;--Z:-1.26}
42.25%{--x:227;--y:-30;--z:108;--X:-.08;--Y:-.31;--Z:-1.21}
42.39%{--x:179;--y:-46;--z:114;--X:-.07;--Y:-.29;--Z:-1.15}
42.53%{--x:133;--y:-56;--z:118;--X:-.06;--Y:-.27;--Z:-1.06}
42.67%{--x:92;--y:-63;--z:119;--X:-.05;--Y:-.23;--Z:-.95}
42.82%{--x:51;--y:-67;--z:120;--X:-.05;--Y:-.17;--Z:-.87}
42.96%{--x:6;--y:-74;--z:123;--X:-.06;--Y:-.17;--Z:-.79}
43.10%{--x:-44;--y:-88;--z:128;--X:-.06;--Y:-.18;--Z:-.7}
43.24%{--x:-103;--y:-107;--z:136;--X:-.05;--Y:-.15;--Z:-.62}
43.39%{--x:-172;--y:-135;--z:146;--X:-.04;--Y:-.13;--Z:-.52}
43.53%{--x:-242;--y:-154;--z:152;--X:-.03;--Y:-.11;--Z:-.41}
43.67%{--x:-300;--y:-172;--z:156;--X:-.03;--Y:-.1;--Z:-.34}
43.81%{--x:-352;--y:-190;--z:159;--X:-.02;--Y:-.09;--Z:-.25}
43.95%{--x:-384;--y:-200;--z:160;--X:-.01;--Y:-.1;--Z:-.19}
44.10%{--x:-403;--y:-207;--z:160;--X:-.01;--Y:-.09;--Z:-.14}
44.24%{--x:-411;--y:-216;--z:161;--X:0;--Y:-.08;--Z:-.11}
44.38%{--x:-415;--y:-221;--z:158;--X:-.02;--Y:-.06;--Z:-.07}
44.52%{--x:-416;--y:-227;--z:156;--X:0;--Y:-.1;--Z:-.04}
44.67%{--x:-408;--y:-228;--z:156;--X:.01;--Y:-.11;--Z:.02}
44.81%{--x:-410;--y:-226;--z:156;--X:-.01;--Y:-.12;--Z:.05}
44.95%{--x:-423;--y:-231;--z:160;--X:-.03;--Y:-.12;--Z:.06}
45.09%{--x:-431;--y:-238;--z:165;--X:-.02;--Y:-.13;--Z:.11}
45.23%{--x:-439;--y:-240;--z:166;--X:-.04;--Y:-.11;--Z:.14}
45.38%{--x:-453;--y:-243;--z:165;--X:-.04;--Y:-.1;--Z:.17}
45.52%{--x:-451;--y:-243;--z:163;--X:-.02;--Y:-.09;--Z:.19}
45.66%{--x:-449;--y:-245;--z:160;--X:-.03;--Y:-.1;--Z:.2}
45.80%{--x:-447;--y:-246;--z:159;--X:-.04;--Y:-.07;--Z:.21}
45.95%{--x:-443;--y:-256;--z:156;--X:-.03;--Y:-.05;--Z:.2}
46.09%{--x:-428;--y:-264;--z:153;--X:-.02;--Y:-.07;--Z:.22}
46.23%{--x:-407;--y:-258;--z:149;--X:.01;--Y:-.08;--Z:.21}
46.37%{--x:-374;--y:-246;--z:145;--X:.01;--Y:-.09;--Z:.18}
46.51%{--x:-325;--y:-235;--z:144;--X:.01;--Y:-.14;--Z:.15}
46.66%{--x:-256;--y:-219;--z:143;--X:.03;--Y:-.08;--Z:.11}
46.80%{--x:-182;--y:-205;--z:136;--X:.01;--Y:-.03;--Z:.06}
46.94%{--x:-108;--y:-192;--z:128;--X:0;--Y:0;--Z:0}
47.08%{--x:-30;--y:-182;--z:119;--X:.01;--Y:-.08;--Z:-.15}
47.23%{--x:56;--y:-172;--z:110;--X:.02;--Y:-.05;--Z:-.2}
47.37%{--x:141;--y:-153;--z:101;--X:.01;--Y:-.11;--Z:-.28}
47.51%{--x:223;--y:-135;--z:96;--X:-.02;--Y:-.08;--Z:-.35}
47.65%{--x:290;--y:-125;--z:93;--X:-.03;--Y:-.16;--Z:-.41}
47.80%{--x:340;--y:-115;--z:92;--X:-.05;--Y:-.28;--Z:-.47}
47.94%{--x:383;--y:-108;--z:93;--X:-.06;--Y:-.33;--Z:-.52}
48.08%{--x:418;--y:-108;--z:94;--X:-.07;--Y:-.31;--Z:-.55}
48.22%{--x:446;--y:-111;--z:91;--X:-.11;--Y:-.28;--Z:-.54}
48.36%{--x:441;--y:-120;--z:88;--X:-.15;--Y:-.37;--Z:-.57}
48.51%{--x:414;--y:-137;--z:89;--X:-.18;--Y:-.38;--Z:-.56}
48.65%{--x:384;--y:-150;--z:95;--X:-.17;--Y:-.38;--Z:-.51}
48.79%{--x:366;--y:-155;--z:100;--X:-.16;--Y:-.36;--Z:-.46}
48.93%{--x:358;--y:-151;--z:103;--X:-.14;--Y:-.35;--Z:-.42}
49.08%{--x:365;--y:-141;--z:106;--X:-.15;--Y:-.24;--Z:-.4}
49.22%{--x:364;--y:-138;--z:105;--X:-.17;--Y:-.24;--Z:-.39}
49.36%{--x:361;--y:-140;--z:104;--X:-.18;--Y:-.22;--Z:-.39}
49.50%{--x:357;--y:-148;--z:103;--X:-.18;--Y:-.21;--Z:-.39}
49.64%{--x:353;--y:-154;--z:104;--X:-.18;--Y:-.25;--Z:-.38}
49.79%{--x:348;--y:-158;--z:109;--X:-.17;--Y:-.26;--Z:-.36}
49.93%{--x:348;--y:-156;--z:114;--X:-.17;--Y:-.25;--Z:-.35}
50.07%{--x:346;--y:-150;--z:116;--X:-.18;--Y:-.24;--Z:-.35}
50.21%{--x:339;--y:-151;--z:118;--X:-.18;--Y:-.24;--Z:-.35}
50.36%{--x:327;--y:-158;--z:120;--X:-.19;--Y:-.19;--Z:-.35}
50.50%{--x:322;--y:-164;--z:118;--X:-.18;--Y:-.15;--Z:-.31}
50.64%{--x:322;--y:-161;--z:115;--X:-.17;--Y:-.17;--Z:-.3}
50.78%{--x:316;--y:-157;--z:115;--X:-.18;--Y:-.23;--Z:-.3}
50.92%{--x:309;--y:-156;--z:120;--X:-.18;--Y:-.24;--Z:-.3}
51.07%{--x:301;--y:-153;--z:127;--X:-.18;--Y:-.25;--Z:-.28}
51.21%{--x:273;--y:-149;--z:132;--X:-.19;--Y:-.24;--Z:-.28}
51.35%{--x:241;--y:-149;--z:136;--X:-.2;--Y:-.21;--Z:-.27}
51.49%{--x:215;--y:-154;--z:140;--X:-.2;--Y:-.18;--Z:-.25}
51.64%{--x:188;--y:-161;--z:142;--X:-.19;--Y:-.15;--Z:-.23}
51.78%{--x:171;--y:-169;--z:146;--X:-.18;--Y:-.13;--Z:-.22}
51.92%{--x:165;--y:-176;--z:150;--X:-.16;--Y:-.12;--Z:-.21}
52.06%{--x:162;--y:-176;--z:152;--X:-.16;--Y:-.12;--Z:-.19}
52.20%{--x:164;--y:-172;--z:151;--X:-.15;--Y:-.12;--Z:-.2}
52.35%{--x:168;--y:-167;--z:149;--X:-.16;--Y:-.09;--Z:-.21}
52.49%{--x:176;--y:-161;--z:146;--X:-.17;--Y:-.07;--Z:-.21}
52.63%{--x:173;--y:-160;--z:142;--X:-.18;--Y:-.08;--Z:-.23}
52.77%{--x:160;--y:-170;--z:141;--X:-.19;--Y:-.1;--Z:-.22}
52.92%{--x:147;--y:-178;--z:139;--X:-.19;--Y:-.08;--Z:-.2}
53.06%{--x:135;--y:-180;--z:136;--X:-.19;--Y:-.09;--Z:-.19}
53.20%{--x:125;--y:-186;--z:136;--X:-.19;--Y:-.1;--Z:-.2}
53.34%{--x:118;--y:-193;--z:138;--X:-.19;--Y:-.09;--Z:-.18}
53.49%{--x:92;--y:-203;--z:140;--X:-.2;--Y:-.12;--Z:-.16}
53.63%{--x:72;--y:-211;--z:143;--X:-.19;--Y:-.11;--Z:-.13}
53.77%{--x:65;--y:-207;--z:144;--X:-.17;--Y:-.08;--Z:-.1}
53.91%{--x:63;--y:-200;--z:144;--X:-.18;--Y:-.07;--Z:-.1}
54.05%{--x:55;--y:-199;--z:142;--X:-.2;--Y:-.06;--Z:-.1}
54.20%{--x:41;--y:-210;--z:142;--X:-.19;--Y:-.05;--Z:-.09}
54.34%{--x:20;--y:-223;--z:141;--X:-.2;--Y:-.04;--Z:-.07}
54.48%{--x:-6;--y:-234;--z:139;--X:-.21;--Y:-.04;--Z:-.04}
54.62%{--x:-36;--y:-246;--z:139;--X:-.21;--Y:-.04;--Z:0}
54.77%{--x:-60;--y:-255;--z:141;--X:-.19;--Y:-.05;--Z:.02}
54.91%{--x:-79;--y:-259;--z:143;--X:-.19;--Y:-.04;--Z:.04}
55.05%{--x:-97;--y:-260;--z:145;--X:-.2;--Y:-.05;--Z:.06}
55.19%{--x:-109;--y:-265;--z:149;--X:-.2;--Y:-.04;--Z:.07}
55.33%{--x:-115;--y:-267;--z:153;--X:-.18;--Y:-.03;--Z:.09}
55.48%{--x:-117;--y:-266;--z:155;--X:-.18;--Y:0;--Z:.09}
55.62%{--x:-115;--y:-268;--z:151;--X:-.18;--Y:.03;--Z:.09}
55.76%{--x:-96;--y:-264;--z:147;--X:-.15;--Y:.03;--Z:.08}
55.90%{--x:-71;--y:-254;--z:141;--X:-.17;--Y:.02;--Z:.07}
56.05%{--x:-59;--y:-245;--z:138;--X:-.2;--Y:-.03;--Z:.05}
56.19%{--x:-59;--y:-248;--z:142;--X:-.22;--Y:-.04;--Z:.05}
56.33%{--x:-55;--y:-251;--z:144;--X:-.22;--Y:0;--Z:.07}
56.47%{--x:-57;--y:-248;--z:142;--X:-.23;--Y:0;--Z:.06}
56.61%{--x:-66;--y:-253;--z:138;--X:-.24;--Y:.01;--Z:.05}
56.76%{--x:-73;--y:-263;--z:139;--X:-.23;--Y:0;--Z:.07}
56.90%{--x:-80;--y:-264;--z:138;--X:-.23;--Y:-.02;--Z:.09}
57.04%{--x:-93;--y:-266;--z:140;--X:-.24;--Y:-.02;--Z:.08}
57.18%{--x:-110;--y:-275;--z:144;--X:-.25;--Y:-.03;--Z:.09}
57.33%{--x:-119;--y:-279;--z:146;--X:-.24;--Y:.03;--Z:.11}
57.47%{--x:-122;--y:-281;--z:144;--X:-.23;--Y:.03;--Z:.12}
57.61%{--x:-123;--y:-284;--z:141;--X:-.24;--Y:.02;--Z:.11}
57.75%{--x:-131;--y:-293;--z:141;--X:-.25;--Y:.01;--Z:.11}
57.89%{--x:-139;--y:-305;--z:142;--X:-.25;--Y:.01;--Z:.13}
58.04%{--x:-143;--y:-311;--z:144;--X:-.23;--Y:0;--Z:.16}
58.18%{--x:-137;--y:-308;--z:146;--X:-.24;--Y:.01;--Z:.15}
58.32%{--x:-134;--y:-308;--z:147;--X:-.24;--Y:.01;--Z:.16}
58.46%{--x:-138;--y:-314;--z:147;--X:-.26;--Y:.02;--Z:.15}
58.61%{--x:-142;--y:-326;--z:147;--X:-.26;--Y:.03;--Z:.15}
58.75%{--x:-144;--y:-338;--z:146;--X:-.26;--Y:.05;--Z:.16}
58.89%{--x:-150;--y:-349;--z:142;--X:-.27;--Y:.04;--Z:.17}
59.03%{--x:-159;--y:-361;--z:140;--X:-.27;--Y:.04;--Z:.17}
59.17%{--x:-163;--y:-369;--z:139;--X:-.26;--Y:.02;--Z:.2}
59.32%{--x:-161;--y:-368;--z:139;--X:-.26;--Y:.01;--Z:.21}
59.46%{--x:-159;--y:-366;--z:140;--X:-.26;--Y:.01;--Z:.21}
59.60%{--x:-149;--y:-366;--z:141;--X:-.25;--Y:.02;--Z:.21}
59.74%{--x:-143;--y:-364;--z:139;--X:-.28;--Y:.04;--Z:.22}
59.89%{--x:-145;--y:-369;--z:137;--X:-.29;--Y:.05;--Z:.23}
60.03%{--x:-148;--y:-379;--z:136;--X:-.28;--Y:.04;--Z:.24}
60.17%{--x:-151;--y:-382;--z:135;--X:-.29;--Y:.02;--Z:.26}
60.31%{--x:-158;--y:-386;--z:134;--X:-.3;--Y:.03;--Z:.26}
60.46%{--x:-169;--y:-395;--z:134;--X:-.3;--Y:.03;--Z:.27}
60.60%{--x:-183;--y:-402;--z:134;--X:-.3;--Y:.02;--Z:.3}
60.74%{--x:-198;--y:-410;--z:134;--X:-.3;--Y:.04;--Z:.33}
60.88%{--x:-212;--y:-418;--z:133;--X:-.3;--Y:.04;--Z:.36}
61.02%{--x:-219;--y:-423;--z:131;--X:-.3;--Y:.05;--Z:.38}
61.17%{--x:-224;--y:-429;--z:129;--X:-.3;--Y:.05;--Z:.4}
61.31%{--x:-229;--y:-436;--z:127;--X:-.31;--Y:.06;--Z:.41}
61.45%{--x:-235;--y:-444;--z:126;--X:-.31;--Y:.05;--Z:.43}
61.59%{--x:-237;--y:-451;--z:127;--X:-.3;--Y:.03;--Z:.44}
61.74%{--x:-237;--y:-456;--z:129;--X:-.3;--Y:.03;--Z:.46}
61.88%{--x:-235;--y:-461;--z:130;--X:-.3;--Y:.06;--Z:.48}
62.02%{--x:-234;--y:-468;--z:131;--X:-.3;--Y:.07;--Z:.48}
62.16%{--x:-232;--y:-477;--z:129;--X:-.3;--Y:.07;--Z:.5}
62.30%{--x:-234;--y:-484;--z:127;--X:-.31;--Y:.08;--Z:.51}
62.45%{--x:-238;--y:-489;--z:125;--X:-.31;--Y:.06;--Z:.52}
62.59%{--x:-240;--y:-488;--z:125;--X:-.31;--Y:.04;--Z:.54}
62.73%{--x:-241;--y:-485;--z:126;--X:-.32;--Y:.04;--Z:.55}
62.87%{--x:-248;--y:-485;--z:126;--X:-.33;--Y:.05;--Z:.56}
63.02%{--x:-263;--y:-490;--z:125;--X:-.33;--Y:.05;--Z:.59}
63.16%{--x:-274;--y:-493;--z:126;--X:-.33;--Y:.06;--Z:.61}
63.30%{--x:-281;--y:-499;--z:126;--X:-.32;--Y:.06;--Z:.61}
63.44%{--x:-283;--y:-505;--z:127;--X:-.32;--Y:.06;--Z:.61}
63.58%{--x:-278;--y:-507;--z:128;--X:-.32;--Y:.06;--Z:.63}
63.73%{--x:-262;--y:-504;--z:128;--X:-.32;--Y:.06;--Z:.62}
63.87%{--x:-250;--y:-500;--z:127;--X:-.33;--Y:.06;--Z:.61}
64.01%{--x:-240;--y:-495;--z:125;--X:-.34;--Y:.07;--Z:.61}
64.15%{--x:-236;--y:-489;--z:122;--X:-.36;--Y:.07;--Z:.62}
64.30%{--x:-243;--y:-490;--z:120;--X:-.37;--Y:.06;--Z:.62}
64.44%{--x:-254;--y:-493;--z:119;--X:-.37;--Y:.07;--Z:.63}
64.58%{--x:-263;--y:-496;--z:118;--X:-.38;--Y:.07;--Z:.64}
64.72%{--x:-273;--y:-503;--z:118;--X:-.38;--Y:.05;--Z:.65}
64.86%{--x:-274;--y:-506;--z:117;--X:-.37;--Y:.07;--Z:.66}
65.01%{--x:-269;--y:-509;--z:115;--X:-.36;--Y:.06;--Z:.66}
65.15%{--x:-257;--y:-508;--z:117;--X:-.36;--Y:.03;--Z:.64}
65.29%{--x:-239;--y:-504;--z:119;--X:-.37;--Y:.04;--Z:.65}
65.43%{--x:-223;--y:-501;--z:120;--X:-.37;--Y:.05;--Z:.64}
65.58%{--x:-218;--y:-502;--z:120;--X:-.39;--Y:.07;--Z:.64}
65.72%{--x:-221;--y:-507;--z:119;--X:-.4;--Y:.08;--Z:.64}
65.86%{--x:-228;--y:-509;--z:117;--X:-.4;--Y:.08;--Z:.66}
66.00%{--x:-236;--y:-510;--z:116;--X:-.41;--Y:.06;--Z:.66}
66.15%{--x:-245;--y:-511;--z:116;--X:-.41;--Y:.05;--Z:.68}
66.29%{--x:-255;--y:-514;--z:118;--X:-.41;--Y:.06;--Z:.69}
66.43%{--x:-265;--y:-516;--z:119;--X:-.42;--Y:.05;--Z:.7}
66.57%{--x:-271;--y:-516;--z:121;--X:-.42;--Y:.05;--Z:.71}
66.71%{--x:-274;--y:-518;--z:123;--X:-.42;--Y:.06;--Z:.71}
66.86%{--x:-273;--y:-523;--z:124;--X:-.41;--Y:.07;--Z:.71}
67.00%{--x:-266;--y:-527;--z:124;--X:-.41;--Y:.08;--Z:.71}
67.14%{--x:-258;--y:-532;--z:122;--X:-.4;--Y:.09;--Z:.71}
67.28%{--x:-256;--y:-536;--z:120;--X:-.42;--Y:.09;--Z:.71}
67.43%{--x:-250;--y:-540;--z:118;--X:-.41;--Y:.08;--Z:.71}
67.57%{--x:-245;--y:-540;--z:117;--X:-.42;--Y:.06;--Z:.73}
67.71%{--x:-242;--y:-538;--z:117;--X:-.42;--Y:.05;--Z:.73}
67.85%{--x:-241;--y:-540;--z:118;--X:-.43;--Y:.06;--Z:.72}
67.99%{--x:-238;--y:-547;--z:118;--X:-.43;--Y:.08;--Z:.74}
68.14%{--x:-241;--y:-554;--z:115;--X:-.44;--Y:.08;--Z:.74}
68.28%{--x:-245;--y:-559;--z:112;--X:-.45;--Y:.06;--Z:.75}
68.42%{--x:-247;--y:-566;--z:111;--X:-.44;--Y:.06;--Z:.76}
68.56%{--x:-246;--y:-568;--z:112;--X:-.44;--Y:.04;--Z:.78}
68.71%{--x:-245;--y:-566;--z:114;--X:-.44;--Y:.04;--Z:.78}
68.85%{--x:-245;--y:-567;--z:115;--X:-.45;--Y:.05;--Z:.77}
68.99%{--x:-252;--y:-573;--z:116;--X:-.45;--Y:.06;--Z:.78}
69.13%{--x:-254;--y:-579;--z:116;--X:-.45;--Y:.07;--Z:.8}
69.27%{--x:-253;--y:-579;--z:113;--X:-.46;--Y:.05;--Z:.81}
69.42%{--x:-252;--y:-578;--z:113;--X:-.46;--Y:.05;--Z:.81}
69.56%{--x:-247;--y:-577;--z:114;--X:-.46;--Y:.06;--Z:.82}
69.70%{--x:-238;--y:-575;--z:112;--X:-.45;--Y:.08;--Z:.83}
69.84%{--x:-239;--y:-580;--z:108;--X:-.47;--Y:.08;--Z:.82}
69.99%{--x:-247;--y:-590;--z:108;--X:-.48;--Y:.07;--Z:.83}
70.13%{--x:-250;--y:-595;--z:109;--X:-.47;--Y:.05;--Z:.85}
70.27%{--x:-253;--y:-596;--z:111;--X:-.48;--Y:.04;--Z:.87}
70.41%{--x:-259;--y:-597;--z:115;--X:-.48;--Y:.04;--Z:.87}
70.55%{--x:-261;--y:-600;--z:119;--X:-.48;--Y:.05;--Z:.89}
70.70%{--x:-267;--y:-602;--z:119;--X:-.48;--Y:.07;--Z:.9}
70.84%{--x:-272;--y:-606;--z:119;--X:-.48;--Y:.06;--Z:.91}
70.98%{--x:-272;--y:-607;--z:118;--X:-.47;--Y:.06;--Z:.91}
71.12%{--x:-271;--y:-607;--z:116;--X:-.48;--Y:.06;--Z:.92}
71.27%{--x:-276;--y:-609;--z:115;--X:-.49;--Y:.05;--Z:.92}
71.41%{--x:-281;--y:-614;--z:115;--X:-.49;--Y:.05;--Z:.92}
71.55%{--x:-279;--y:-617;--z:114;--X:-.48;--Y:.05;--Z:.92}
71.69%{--x:-277;--y:-616;--z:113;--X:-.49;--Y:.05;--Z:.93}
71.83%{--x:-276;--y:-618;--z:114;--X:-.49;--Y:.04;--Z:.93}
71.98%{--x:-271;--y:-620;--z:116;--X:-.49;--Y:.04;--Z:.93}
72.12%{--x:-266;--y:-619;--z:118;--X:-.49;--Y:.04;--Z:.93}
72.26%{--x:-261;--y:-618;--z:120;--X:-.49;--Y:.05;--Z:.93}
72.40%{--x:-254;--y:-616;--z:121;--X:-.5;--Y:.06;--Z:.93}
72.55%{--x:-251;--y:-611;--z:119;--X:-.51;--Y:.07;--Z:.92}
72.69%{--x:-250;--y:-612;--z:118;--X:-.51;--Y:.06;--Z:.92}
72.83%{--x:-251;--y:-612;--z:117;--X:-.51;--Y:.06;--Z:.93}
72.97%{--x:-254;--y:-608;--z:116;--X:-.52;--Y:.04;--Z:.93}
73.12%{--x:-254;--y:-608;--z:118;--X:-.51;--Y:.04;--Z:.93}
73.26%{--x:-253;--y:-608;--z:119;--X:-.51;--Y:.06;--Z:.92}
73.40%{--x:-253;--y:-609;--z:117;--X:-.52;--Y:.07;--Z:.92}
73.54%{--x:-254;--y:-613;--z:116;--X:-.52;--Y:.07;--Z:.92}
73.68%{--x:-256;--y:-619;--z:117;--X:-.52;--Y:.05;--Z:.93}
73.83%{--x:-251;--y:-618;--z:118;--X:-.52;--Y:.05;--Z:.93}
73.97%{--x:-242;--y:-613;--z:119;--X:-.52;--Y:.05;--Z:.91}
74.11%{--x:-239;--y:-611;--z:121;--X:-.54;--Y:.04;--Z:.91}
74.25%{--x:-245;--y:-613;--z:122;--X:-.54;--Y:.05;--Z:.91}
74.40%{--x:-253;--y:-616;--z:122;--X:-.54;--Y:.07;--Z:.91}
74.54%{--x:-262;--y:-620;--z:120;--X:-.54;--Y:.08;--Z:.92}
74.68%{--x:-270;--y:-624;--z:119;--X:-.54;--Y:.07;--Z:.94}
74.82%{--x:-274;--y:-626;--z:119;--X:-.54;--Y:.06;--Z:.94}
74.96%{--x:-271;--y:-627;--z:119;--X:-.54;--Y:.06;--Z:.94}
75.11%{--x:-264;--y:-624;--z:118;--X:-.54;--Y:.06;--Z:.93}
75.25%{--x:-253;--y:-621;--z:118;--X:-.54;--Y:.05;--Z:.94}
75.39%{--x:-241;--y:-621;--z:118;--X:-.54;--Y:.06;--Z:.92}
75.53%{--x:-236;--y:-623;--z:118;--X:-.55;--Y:.06;--Z:.92}
75.68%{--x:-232;--y:-627;--z:118;--X:-.55;--Y:.07;--Z:.91}
75.82%{--x:-232;--y:-631;--z:118;--X:-.56;--Y:.06;--Z:.92}
75.96%{--x:-238;--y:-634;--z:117;--X:-.56;--Y:.06;--Z:.92}
76.10%{--x:-245;--y:-636;--z:117;--X:-.56;--Y:.05;--Z:.92}
76.24%{--x:-254;--y:-637;--z:117;--X:-.57;--Y:.05;--Z:.93}
76.39%{--x:-264;--y:-638;--z:117;--X:-.58;--Y:.05;--Z:.94}
76.53%{--x:-273;--y:-639;--z:118;--X:-.57;--Y:.05;--Z:.94}
76.67%{--x:-280;--y:-642;--z:119;--X:-.57;--Y:.06;--Z:.96}
76.81%{--x:-281;--y:-644;--z:118;--X:-.56;--Y:.06;--Z:.98}
76.96%{--x:-278;--y:-644;--z:117;--X:-.55;--Y:.06;--Z:.97}
77.10%{--x:-274;--y:-644;--z:116;--X:-.56;--Y:.05;--Z:.97}
77.24%{--x:-271;--y:-646;--z:116;--X:-.56;--Y:.06;--Z:.97}
77.38%{--x:-272;--y:-647;--z:117;--X:-.56;--Y:.04;--Z:.97}
77.52%{--x:-269;--y:-646;--z:119;--X:-.57;--Y:.04;--Z:.97}
77.67%{--x:-268;--y:-647;--z:119;--X:-.57;--Y:.07;--Z:.97}
77.81%{--x:-276;--y:-651;--z:118;--X:-.58;--Y:.08;--Z:.99}
77.95%{--x:-284;--y:-656;--z:118;--X:-.58;--Y:.06;--Z:1}
78.09%{--x:-290;--y:-658;--z:117;--X:-.58;--Y:.07;--Z:1}
78.24%{--x:-296;--y:-659;--z:118;--X:-.57;--Y:.05;--Z:1}
78.38%{--x:-298;--y:-657;--z:119;--X:-.58;--Y:.05;--Z:1.01}
78.52%{--x:-297;--y:-657;--z:120;--X:-.58;--Y:.05;--Z:1.01}
78.66%{--x:-296;--y:-661;--z:119;--X:-.58;--Y:.07;--Z:1.01}
78.81%{--x:-293;--y:-663;--z:118;--X:-.57;--Y:.07;--Z:1.01}
78.95%{--x:-287;--y:-666;--z:118;--X:-.57;--Y:.06;--Z:1.01}
79.09%{--x:-279;--y:-667;--z:118;--X:-.58;--Y:.05;--Z:1}
79.23%{--x:-269;--y:-666;--z:118;--X:-.57;--Y:.05;--Z:1}
79.37%{--x:-264;--y:-665;--z:119;--X:-.59;--Y:.05;--Z:1}
79.52%{--x:-263;--y:-666;--z:119;--X:-.6;--Y:.05;--Z:1}
79.66%{--x:-262;--y:-664;--z:120;--X:-.59;--Y:.06;--Z:1}
79.80%{--x:-263;--y:-662;--z:119;--X:-.6;--Y:.06;--Z:1.01}
79.94%{--x:-270;--y:-661;--z:117;--X:-.61;--Y:.06;--Z:1.02}
80.09%{--x:-277;--y:-664;--z:118;--X:-.61;--Y:.06;--Z:1.02}
80.23%{--x:-280;--y:-669;--z:117;--X:-.6;--Y:.07;--Z:1.02}
80.37%{--x:-284;--y:-672;--z:116;--X:-.61;--Y:.07;--Z:1.03}
80.51%{--x:-286;--y:-676;--z:115;--X:-.59;--Y:.06;--Z:1.04}
80.65%{--x:-284;--y:-676;--z:118;--X:-.59;--Y:.03;--Z:1.04}
80.80%{--x:-275;--y:-672;--z:121;--X:-.58;--Y:.03;--Z:1.04}
80.94%{--x:-264;--y:-664;--z:123;--X:-.59;--Y:.04;--Z:1.04}
81.08%{--x:-257;--y:-661;--z:124;--X:-.61;--Y:.06;--Z:1.03}
81.22%{--x:-261;--y:-663;--z:124;--X:-.62;--Y:.06;--Z:1.04}
81.37%{--x:-267;--y:-667;--z:124;--X:-.62;--Y:.07;--Z:1.05}
81.51%{--x:-275;--y:-672;--z:123;--X:-.62;--Y:.08;--Z:1.05}
81.65%{--x:-285;--y:-675;--z:122;--X:-.62;--Y:.07;--Z:1.07}
81.79%{--x:-291;--y:-678;--z:122;--X:-.62;--Y:.07;--Z:1.08}
81.93%{--x:-296;--y:-683;--z:122;--X:-.61;--Y:.07;--Z:1.1}
82.08%{--x:-294;--y:-685;--z:121;--X:-.61;--Y:.07;--Z:1.1}
82.22%{--x:-289;--y:-686;--z:121;--X:-.6;--Y:.06;--Z:1.1}
82.36%{--x:-283;--y:-685;--z:122;--X:-.61;--Y:.06;--Z:1.09}
82.50%{--x:-275;--y:-683;--z:123;--X:-.61;--Y:.05;--Z:1.09}
82.65%{--x:-267;--y:-680;--z:124;--X:-.61;--Y:.05;--Z:1.08}
82.79%{--x:-264;--y:-680;--z:125;--X:-.62;--Y:.06;--Z:1.09}
82.93%{--x:-271;--y:-681;--z:125;--X:-.63;--Y:.08;--Z:1.1}
83.07%{--x:-281;--y:-687;--z:124;--X:-.63;--Y:.07;--Z:1.11}
83.21%{--x:-289;--y:-691;--z:123;--X:-.62;--Y:.08;--Z:1.12}
83.36%{--x:-300;--y:-693;--z:121;--X:-.63;--Y:.08;--Z:1.14}
83.50%{--x:-307;--y:-695;--z:122;--X:-.62;--Y:.05;--Z:1.15}
83.64%{--x:-309;--y:-697;--z:124;--X:-.62;--Y:.07;--Z:1.16}
83.78%{--x:-308;--y:-699;--z:123;--X:-.61;--Y:.07;--Z:1.16}
83.93%{--x:-306;--y:-699;--z:122;--X:-.62;--Y:.07;--Z:1.16}
84.07%{--x:-298;--y:-697;--z:121;--X:-.61;--Y:.06;--Z:1.15}
84.21%{--x:-291;--y:-696;--z:122;--X:-.62;--Y:.06;--Z:1.15}
84.35%{--x:-284;--y:-691;--z:124;--X:-.63;--Y:.07;--Z:1.14}
84.50%{--x:-285;--y:-692;--z:124;--X:-.63;--Y:.08;--Z:1.14}
84.64%{--x:-292;--y:-698;--z:123;--X:-.63;--Y:.08;--Z:1.15}
84.78%{--x:-299;--y:-703;--z:122;--X:-.63;--Y:.08;--Z:1.15}
84.92%{--x:-303;--y:-704;--z:121;--X:-.62;--Y:.06;--Z:1.14}
85.06%{--x:-297;--y:-700;--z:122;--X:-.62;--Y:.05;--Z:1.13}
85.21%{--x:-287;--y:-693;--z:123;--X:-.62;--Y:.05;--Z:1.12}
85.35%{--x:-269;--y:-685;--z:122;--X:-.62;--Y:.05;--Z:1.1}
85.49%{--x:-246;--y:-676;--z:122;--X:-.62;--Y:.05;--Z:1.08}
85.63%{--x:-226;--y:-667;--z:120;--X:-.63;--Y:.05;--Z:1.04}
85.78%{--x:-207;--y:-664;--z:120;--X:-.64;--Y:.05;--Z:1.02}
85.92%{--x:-181;--y:-657;--z:122;--X:-.64;--Y:.04;--Z:.98}
86.06%{--x:-161;--y:-651;--z:122;--X:-.65;--Y:.05;--Z:.97}
86.20%{--x:-153;--y:-648;--z:122;--X:-.67;--Y:.05;--Z:.95}
86.34%{--x:-151;--y:-647;--z:120;--X:-.68;--Y:.07;--Z:.94}
86.49%{--x:-157;--y:-650;--z:117;--X:-.67;--Y:.07;--Z:.92}
86.63%{--x:-167;--y:-654;--z:115;--X:-.67;--Y:.06;--Z:.91}
86.77%{--x:-178;--y:-654;--z:114;--X:-.67;--Y:.04;--Z:.91}
86.91%{--x:-188;--y:-652;--z:115;--X:-.67;--Y:.03;--Z:.92}
87.06%{--x:-195;--y:-653;--z:117;--X:-.68;--Y:.04;--Z:.92}
87.20%{--x:-200;--y:-656;--z:118;--X:-.67;--Y:.04;--Z:.91}
87.34%{--x:-200;--y:-656;--z:119;--X:-.67;--Y:.05;--Z:.9}
87.48%{--x:-195;--y:-654;--z:117;--X:-.67;--Y:.06;--Z:.88}
87.62%{--x:-185;--y:-648;--z:116;--X:-.67;--Y:.05;--Z:.86}
87.77%{--x:-173;--y:-642;--z:117;--X:-.67;--Y:.05;--Z:.85}
87.91%{--x:-158;--y:-635;--z:117;--X:-.67;--Y:.05;--Z:.82}
88.05%{--x:-145;--y:-629;--z:116;--X:-.68;--Y:.06;--Z:.79}
88.19%{--x:-133;--y:-625;--z:114;--X:-.68;--Y:.06;--Z:.75}
88.34%{--x:-117;--y:-620;--z:113;--X:-.67;--Y:.04;--Z:.73}
88.48%{--x:-97;--y:-610;--z:113;--X:-.67;--Y:.04;--Z:.68}
88.62%{--x:-79;--y:-605;--z:113;--X:-.68;--Y:.05;--Z:.64}
88.76%{--x:-65;--y:-603;--z:113;--X:-.68;--Y:.06;--Z:.61}
88.90%{--x:-48;--y:-597;--z:112;--X:-.69;--Y:.06;--Z:.58}
89.05%{--x:-27;--y:-590;--z:113;--X:-.69;--Y:.05;--Z:.54}
89.19%{--x:-6;--y:-581;--z:114;--X:-.69;--Y:.04;--Z:.5}
89.33%{--x:13;--y:-567;--z:114;--X:-.7;--Y:.04;--Z:.48}
89.47%{--x:27;--y:-556;--z:114;--X:-.71;--Y:.04;--Z:.46}
89.62%{--x:37;--y:-553;--z:112;--X:-.72;--Y:.07;--Z:.44}
89.76%{--x:45;--y:-549;--z:108;--X:-.73;--Y:.07;--Z:.41}
89.90%{--x:49;--y:-546;--z:105;--X:-.73;--Y:.06;--Z:.38}
90.04%{--x:51;--y:-550;--z:103;--X:-.73;--Y:.05;--Z:.37}
90.18%{--x:44;--y:-553;--z:102;--X:-.73;--Y:.03;--Z:.38}
90.33%{--x:35;--y:-554;--z:104;--X:-.73;--Y:.03;--Z:.37}
90.47%{--x:26;--y:-560;--z:104;--X:-.73;--Y:.04;--Z:.36}
90.61%{--x:0;--y:-570;--z:105;--X:-.74;--Y:.03;--Z:.36}
90.75%{--x:-36;--y:-582;--z:107;--X:-.74;--Y:.03;--Z:.37}
90.90%{--x:-68;--y:-596;--z:110;--X:-.73;--Y:.05;--Z:.38}
91.04%{--x:-90;--y:-606;--z:112;--X:-.71;--Y:.05;--Z:.4}
91.18%{--x:-105;--y:-611;--z:114;--X:-.69;--Y:.05;--Z:.4}
91.32%{--x:-101;--y:-610;--z:116;--X:-.68;--Y:.04;--Z:.38}
91.47%{--x:-86;--y:-603;--z:116;--X:-.68;--Y:.05;--Z:.35}
91.61%{--x:-65;--y:-592;--z:115;--X:-.69;--Y:.05;--Z:.32}
91.75%{--x:-32;--y:-578;--z:115;--X:-.69;--Y:.06;--Z:.28}
91.89%{--x:-4;--y:-572;--z:96;--X:-.33;--Y:.1;--Z:.25}
92.03%{--x:5;--y:-568;--z:93;--X:-.27;--Y:.11;--Z:.21}
92.18%{--x:18;--y:-562;--z:94;--X:-.3;--Y:.09;--Z:.19}
92.32%{--x:34;--y:-554;--z:88;--X:-.24;--Y:.12;--Z:.15}
92.46%{--x:34;--y:-555;--z:81;--X:-.14;--Y:.13;--Z:.12}
92.60%{--x:32;--y:-554;--z:85;--X:-.19;--Y:.09;--Z:.1}
92.75%{--x:35;--y:-548;--z:86;--X:-.17;--Y:.08;--Z:.08}
92.89%{--x:28;--y:-545;--z:85;--X:-.08;--Y:.08;--Z:.07}
93.03%{--x:16;--y:-545;--z:93;--X:-.1;--Y:.11;--Z:.05}
93.17%{--x:2;--y:-546;--z:99;--X:-.08;--Y:.12;--Z:.06}
93.31%{--x:5;--y:-540;--z:103;--X:-.09;--Y:.17;--Z:.06}
93.46%{--x:28;--y:-535;--z:103;--X:-.08;--Y:.17;--Z:.06}
93.60%{--x:50;--y:-524;--z:102;--X:-.09;--Y:.16;--Z:-.01}
93.74%{--x:54;--y:-523;--z:101;--X:-.11;--Y:.18;--Z:-.08}
93.88%{--x:54;--y:-528;--z:100;--X:-.09;--Y:.14;--Z:-.08}
94.03%{--x:51;--y:-527;--z:98;--X:-.1;--Y:.14;--Z:-.11}
94.17%{--x:37;--y:-533;--z:95;--X:-.09;--Y:.15;--Z:-.13}
94.31%{--x:36;--y:-538;--z:97;--X:-.09;--Y:.16;--Z:-.09}
94.45%{--x:45;--y:-535;--z:97;--X:-.1;--Y:.15;--Z:-.1}
94.59%{--x:48;--y:-534;--z:97;--X:-.1;--Y:.14;--Z:-.13}
94.74%{--x:50;--y:-535;--z:98;--X:-.11;--Y:.14;--Z:-.14}
94.88%{--x:51;--y:-536;--z:97;--X:-.11;--Y:.15;--Z:-.15}
95.02%{--x:48;--y:-538;--z:96;--X:-.11;--Y:.15;--Z:-.16}
95.16%{--x:47;--y:-539;--z:93;--X:-.11;--Y:.16;--Z:-.16}
95.31%{--x:48;--y:-541;--z:89;--X:-.12;--Y:.21;--Z:-.17}
95.45%{--x:51;--y:-551;--z:85;--X:-.13;--Y:.22;--Z:-.17}
95.59%{--x:59;--y:-559;--z:83;--X:-.12;--Y:.2;--Z:-.17}
95.73%{--x:61;--y:-564;--z:80;--X:-.12;--Y:.15;--Z:-.18}
95.87%{--x:65;--y:-564;--z:81;--X:-.12;--Y:.12;--Z:-.18}
96.02%{--x:78;--y:-558;--z:84;--X:-.11;--Y:.11;--Z:-.17}
96.16%{--x:92;--y:-548;--z:87;--X:-.14;--Y:.1;--Z:-.23}
96.30%{--x:101;--y:-545;--z:87;--X:-.11;--Y:.12;--Z:-.27}
96.44%{--x:104;--y:-544;--z:88;--X:-.11;--Y:.14;--Z:-.27}
96.59%{--x:105;--y:-544;--z:86;--X:-.07;--Y:.19;--Z:-.28}
96.73%{--x:102;--y:-547;--z:84;--X:-.06;--Y:.2;--Z:-.28}
96.87%{--x:95;--y:-547;--z:85;--X:-.13;--Y:.19;--Z:-.3}
97.01%{--x:87;--y:-548;--z:84;--X:-.12;--Y:.2;--Z:-.3}
97.16%{--x:80;--y:-551;--z:90;--X:-.19;--Y:.18;--Z:-.31}
97.30%{--x:88;--y:-554;--z:97;--X:-.29;--Y:.28;--Z:-.24}
97.44%{--x:85;--y:-557;--z:97;--X:-.29;--Y:.28;--Z:-.24}
97.58%{--x:83;--y:-558;--z:97;--X:-.29;--Y:.27;--Z:-.24}
97.72%{--x:79;--y:-560;--z:98;--X:-.29;--Y:.25;--Z:-.24}
97.87%{--x:74;--y:-561;--z:101;--X:-.29;--Y:.23;--Z:-.26}
98.01%{--x:74;--y:-565;--z:105;--X:-.29;--Y:.23;--Z:-.26}
98.15%{--x:84;--y:-562;--z:108;--X:-.29;--Y:.22;--Z:-.26}
98.29%{--x:94;--y:-558;--z:109;--X:-.3;--Y:.24;--Z:-.28}
98.44%{--x:101;--y:-558;--z:110;--X:-.29;--Y:.25;--Z:-.29}
98.58%{--x:107;--y:-558;--z:111;--X:-.3;--Y:.24;--Z:-.31}
98.72%{--x:110;--y:-561;--z:110;--X:-.3;--Y:.26;--Z:-.31}
98.86%{--x:103;--y:-566;--z:108;--X:-.31;--Y:.26;--Z:-.32}
99.00%{--x:93;--y:-575;--z:106;--X:-.31;--Y:.25;--Z:-.35}
99.15%{--x:80;--y:-585;--z:106;--X:-.31;--Y:.23;--Z:-.36}
99.29%{--x:65;--y:-590;--z:107;--X:-.3;--Y:.21;--Z:-.36}
99.43%{--x:47;--y:-594;--z:111;--X:-.29;--Y:.19;--Z:-.38}
99.57%{--x:33;--y:-596;--z:117;--X:-.29;--Y:.2;--Z:-.43}
99.72%{--x:7;--y:-603;--z:122;--X:-.28;--Y:.19;--Z:-.48}
99.86%{--x:-17;--y:-611;--z:124;--X:-.29;--Y:.34;--Z:-.48}
100.00%{--x:-27;--y:-615;--z:127;--X:-.3;--Y:.23;--Z:-.61}
}
@keyframes mouse {2.92%{--m:1927px 618px}
3.06%{--m:1910px 612px}
3.13%{--m:1885px 614px}
3.20%{--m:1871px 618px}
3.34%{--m:1861px 629px}
3.49%{--m:1844px 642px}
3.63%{--m:1822px 660px}
3.77%{--m:1800px 677px}
3.91%{--m:1777px 692px}
4.05%{--m:1757px 701px}
4.20%{--m:1756px 702px}
4.34%{--m:1755px 695px}
4.48%{--m:1753px 691px}
4.62%{--m:1752px 691px}
5.62%{--m:1752px 690px}
6.90%{--m:1745px 696px}
7.04%{--m:1733px 702px}
7.18%{--m:1731px 704px}
7.33%{--m:1730px 704px}
7.75%{--m:1727px 710px}
7.89%{--m:1721px 710px}
20.84%{--m:1713px 716px}
20.98%{--m:1706px 719px}
21.12%{--m:1690px 724px}
21.27%{--m:1681px 727px}
21.41%{--m:1680px 727px}
21.55%{--m:1671px 730px}
21.69%{--m:1664px 736px}
21.83%{--m:1657px 739px}
21.98%{--m:1653px 741px}
22.12%{--m:1649px 745px}
22.26%{--m:1646px 748px}
22.40%{--m:1639px 753px}
22.55%{--m:1638px 753px}
23.54%{--m:1639px 753px}
23.68%{--m:1642px 752px}
23.83%{--m:1645px 751px}
23.97%{--m:1646px 751px}
24.11%{--m:1647px 750px}
24.25%{--m:1648px 748px}
24.40%{--m:1649px 747px}
24.54%{--m:1653px 745px}
24.68%{--m:1653px 744px}
28.17%{--m:1636px 751px}
28.31%{--m:1573px 766px}
28.45%{--m:1497px 776px}
28.59%{--m:1434px 780px}
28.73%{--m:1395px 781px}
28.88%{--m:1382px 781px}
}
@keyframes mouse-s {0.00%{--Mb:var(--Mn)}
3.13%{--Mb:var(--Mp)}
3.41%{--Mb:var(--Mn)}
3.49%{--Mb:var(--Mp)}
7.11%{--Mb:var(--Mn)}
7.75%{--Mb:var(--Mt)}
21.62%{--Mb:var(--Mn)}
21.76%{--Mb:var(--Mp)}
22.33%{--Mb:var(--Mn)}
24.18%{--Mb:var(--Mp)}
26.74%{--Mb:var(--Mn)}
28.38%{--Mb:var(--Mt)}
}
.camera {
  animation: camera 23.55s linear infinite, blur 23.55s linear infinite, mouse 23.55s step-end infinite, mouse-s 23.55s step-end infinite, extra 23.55s step-end infinite, extra-l 23.55s cubic-bezier(0, 0, 0.2, 1) infinite;
  &:not(:hover) {
    animation-play-state: paused,paused,paused;
  }
  /*animation: camera 5s linear infinite;*/
  /*perspective: 2100px;*/
  /*transform-style: preserve-3d;*/
}
#h2p {font-size:13px;
  &::after { content:"" }
}
#twVid1 {
  &:hover .videoPauseOverlay { display:none }
}
tw-play {
  background: #FFF;
  &::before, &::after {
    display:block;
    content:"";
    position:absolute;
  }
  &::before {
    inset:4px;
    border-radius:99Q;
    background:#1D9BF0;
  }
  svg {display:none}
  &::after {
    inset:19px;
    clip-path:polygon(17.5% 0%, 100% 50%, 17.5% 100%);
    background:#FFF;
  }
}
re-bantcha {
  @starting-style {
    opacity:0;
    translate:0 10px;
  }
  transition: opacity 0.2s, translate 0.2s;
        z-index: 20;
        font-family: Roboto,helvetica,arial,sans-serif;
        color: #FFF;
        background: #FFF;
        padding: 6px;
        border: 1px solid rgb(204, 204, 204);
        box-shadow: rgba(0, 0, 0, 0.2) 2px 2px 3px;
        display: flex;
        flex-direction: column;
        header {
          background: #1A73E8;
          padding: 24px;
          h2 {
            color: inherit;
            font-family: inherit;
            font-weight: 900;
            margin: 0;
            margin-bottom: 13px;
          }
          p {
            margin: 0;
          }
        }
        header {
          margin:0;
        }
        main {
          display: flex;
          gap: 2px;
          max-width: 383px;
          margin: 4px 0;
          flex-wrap: wrap;
        }
        label {
          display: flex;
          width: 75px;
          height: 75px;
          background: #221D19; /*hsl(0deg 0% calc(100% * var(--H)));*/
          input {display: none}
          position:relative;
          cursor:pointer;
          &::before {
            position:absolute;
            inset:4px;
            opacity:var(--H);
            background:
              linear-gradient(135deg,#FFF1,#FFF3,#0000 10%),
              linear-gradient(-90deg,#3B281E33,#0000 10%),
              linear-gradient(180deg,#3B281E33,#0000 10%),
              linear-gradient(0deg,#3B281E33,#0000 10%),
              linear-gradient(90deg,#3B281E33,#0000 10%),
              linear-gradient(90deg,#3B281E33,#0000 4%),
              linear-gradient(90deg,#FFF1,#FFF3,#0000 10%),
              #654736;
            background-blend-mode: 
            screen,
            multiply,
            multiply,
            multiply,
            multiply,
            multiply,
            screen,
            normal;
            border-radius:8px;
            content:"";
          }
          &::after {
            position:absolute;
            inset:4px;
            opacity:calc(1 - var(--H));
            background:
              radial-gradient(circle at 50% 50%,#E48A6477 0%,#0000 70%),
              linear-gradient(135deg,#FFF1,#FFF3,#0000 10%),
              linear-gradient(-90deg,#3B281E33,#0000 10%),
              linear-gradient(180deg,#3B281E33,#0000 10%),
              linear-gradient(0deg,#3B281E33,#0000 10%),
              linear-gradient(90deg,#3B281E33,#0000 10%),
              linear-gradient(90deg,#3B281E33,#0000 4%),
              linear-gradient(90deg,#FFF1,#FFF3,#0000 10%),
              radial-gradient(circle at 0% 50%,#E48A64,#0000 50%),
              radial-gradient(circle at 100% 50%,#E48A64,#0000 50%),
              radial-gradient(circle at 50% 100%,#E48A64,#0000 50%),
              radial-gradient(circle at 50% 0%,#E48A64,#0000 50%),
              #654736;
            background-blend-mode: 
            screen,
            screen,
            multiply,
            multiply,
            multiply,
            multiply,
            multiply,
            screen,
            screen,
            screen,
            screen,
            screen,
            normal;
            border-radius:8px;
            content:"";
            box-shadow: 0 0 4px #D59877EE;
          }
        }
        article {
--h1:0;&:has(label:nth-child(1) :checked){--h1:1}
label:nth-child(1){--H:var(--H1)}
--h2:0;&:has(label:nth-child(2) :checked){--h2:1}
label:nth-child(2){--H:var(--H2)}
--h3:0;&:has(label:nth-child(3) :checked){--h3:1}
label:nth-child(3){--H:var(--H3)}
--h4:0;&:has(label:nth-child(4) :checked){--h4:1}
label:nth-child(4){--H:var(--H4)}
--h5:0;&:has(label:nth-child(5) :checked){--h5:1}
label:nth-child(5){--H:var(--H5)}
--h6:0;&:has(label:nth-child(6) :checked){--h6:1}
label:nth-child(6){--H:var(--H6)}
--h7:0;&:has(label:nth-child(7) :checked){--h7:1}
label:nth-child(7){--H:var(--H7)}
--h8:0;&:has(label:nth-child(8) :checked){--h8:1}
label:nth-child(8){--H:var(--H8)}
--h9:0;&:has(label:nth-child(9) :checked){--h9:1}
label:nth-child(9){--H:var(--H9)}
--h10:0;&:has(label:nth-child(10) :checked){--h10:1}
label:nth-child(10){--H:var(--H10)}
--h11:0;&:has(label:nth-child(11) :checked){--h11:1}
label:nth-child(11){--H:var(--H11)}
--h12:0;&:has(label:nth-child(12) :checked){--h12:1}
label:nth-child(12){--H:var(--H12)}
--h13:0;&:has(label:nth-child(13) :checked){--h13:1}
label:nth-child(13){--H:var(--H13)}
--h14:0;&:has(label:nth-child(14) :checked){--h14:1}
label:nth-child(14){--H:var(--H14)}
--h15:0;&:has(label:nth-child(15) :checked){--h15:1}
label:nth-child(15){--H:var(--H15)}
--h16:0;&:has(label:nth-child(16) :checked){--h16:1}
label:nth-child(16){--H:var(--H16)}
--h17:0;&:has(label:nth-child(17) :checked){--h17:1}
label:nth-child(17){--H:var(--H17)}
--h18:0;&:has(label:nth-child(18) :checked){--h18:1}
label:nth-child(18){--H:var(--H18)}
--h19:0;&:has(label:nth-child(19) :checked){--h19:1}
label:nth-child(19){--H:var(--H19)}
--h20:0;&:has(label:nth-child(20) :checked){--h20:1}
label:nth-child(20){--H:var(--H20)}
--h21:0;&:has(label:nth-child(21) :checked){--h21:1}
label:nth-child(21){--H:var(--H21)}
--h22:0;&:has(label:nth-child(22) :checked){--h22:1}
label:nth-child(22){--H:var(--H22)}
--h23:0;&:has(label:nth-child(23) :checked){--h23:1}
label:nth-child(23){--H:var(--H23)}
--h24:0;&:has(label:nth-child(24) :checked){--h24:1}
label:nth-child(24){--H:var(--H24)}
--h25:0;&:has(label:nth-child(25) :checked){--h25:1}
label:nth-child(25){--H:var(--H25)}
--H1:mod(var(--h1) + var(--h2) + var(--h6),2);
--H2:mod(var(--h2) + var(--h1) + var(--h3) + var(--h7),2);
--H3:mod(var(--h3) + var(--h2) + var(--h4) + var(--h8),2);
--H4:mod(var(--h4) + var(--h3) + var(--h5) + var(--h9),2);
--H5:mod(var(--h5) + var(--h4) + var(--h10),2);
--H6:mod(var(--h6) + var(--h1) + var(--h7) + var(--h11),2);
--H7:mod(var(--h7) + var(--h6) + var(--h2) + var(--h8) + var(--h12),2);
--H8:mod(var(--h8) + var(--h7) + var(--h3) + var(--h9) + var(--h13),2);
--H9:mod(var(--h9) + var(--h8) + var(--h4) + var(--h10) + var(--h14),2);
--H10:mod(var(--h10) + var(--h9) + var(--h5) + var(--h15),2);
--H11:mod(var(--h11) + var(--h6) + var(--h12) + var(--h16),2);
--H12:mod(var(--h12) + var(--h11) + var(--h7) + var(--h13) + var(--h17),2);
--H13:mod(var(--h13) + var(--h12) + var(--h8) + var(--h14) + var(--h18),2);
--H14:mod(var(--h14) + var(--h13) + var(--h9) + var(--h15) + var(--h19),2);
--H15:mod(var(--h15) + var(--h14) + var(--h10) + var(--h20),2);
--H16:mod(var(--h16) + var(--h11) + var(--h17) + var(--h21),2);
--H17:mod(var(--h17) + var(--h16) + var(--h12) + var(--h18) + var(--h22),2);
--H18:mod(var(--h18) + var(--h17) + var(--h13) + var(--h19) + var(--h23),2);
--H19:mod(var(--h19) + var(--h18) + var(--h14) + var(--h20) + var(--h24),2);
--H20:mod(var(--h20) + var(--h19) + var(--h15) + var(--h25),2);
--H21:mod(var(--h21) + var(--h16) + var(--h22),2);
--H22:mod(var(--h22) + var(--h21) + var(--h17) + var(--h23),2);
--H23:mod(var(--h23) + var(--h22) + var(--h18) + var(--h24),2);
--H24:mod(var(--h24) + var(--h23) + var(--h19) + var(--h25),2);
--H25:mod(var(--h25) + var(--h24) + var(--h20),2);
--res: max(0,1 - (var(--H1) + var(--H2) + var(--H3) + var(--H4) + var(--H5) + var(--H6) + var(--H7) + var(--H8) + var(--H9) + var(--H10) + var(--H11) + var(--H12) + var(--H13) + var(--H14) + var(--H15) + var(--H16) + var(--H17) + var(--H18) + var(--H19) + var(--H20) + var(--H21) + var(--H22) + var(--H23) + var(--H24) + var(--H25)));
.secretbtn {
  &:not(.disabled) {
    z-index:1;
  &:hover {
    background:hsl(from var(--bb) h s calc(l + 6));
  }
  &:active {
    background:hsl(from var(--bb) h s calc(l - 6));
  }
    z-index: calc(var(--res) * 2);
  }
  &.disabled {
    z-index: 1;
    cursor:default;
    background:hsl(from var(--bb) h calc(s * 0.2) calc(l + 12));
  }
  -webkit-user-select:none;
  user-select:none;
  --bb:#1A73E8;
  background:var(--bb);
  font-family:inherit;
  color:inherit;
  border:0;
  border-radius:3px;
  font-size:13px;
  font-weight:600;
  padding: 0 24px;
  cursor:pointer;
  display:flex;
  align-items: center;
}
        }
    }
/* this is better but less browser support, using as prog enhancement */
@property --res {syntax:"<integer>";initial-value:0;inherits:true}
article > div {
  @container style(--res:0) {
    .secretbtn:not(.disabled) {
      display:none;
    }
  }
}
</style>
