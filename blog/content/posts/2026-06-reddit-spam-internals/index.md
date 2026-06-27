+++
title = "A peek into Reddit's spam internals"
date = 2026-06-27T16:00:00Z
draft = false
tags = ["reddit"]
slug = "reddit-spam-internals"
summary = "How Reddit accidentally leaked spamurai to me."
+++

<style>
  bpm-emote {
    margin: 8px;
    &[left] {
      float: left;
    }
    &[right] {
      float: right;
    }
  }
  body:not(:has(.bpm-emote)) bpm-emote {
    display: none;
  }
</style>

<!--<span aria-hidden="true" style="font-size:0;float:left" inert data-emote-test>\[](/abspin)</span>-->
<p-s s="0.15467216"></p-s><bpm-emote aria-hidden=true right>\[](/lyrahai)</bpm-emote>5 years ago, back when I still used Reddit, something unusual happened. My app of choice, [Relay for reddit](https://play.google.com/store/apps/details?id=reddit.news), was bombarding me with a bunch of weird notifications about <spam-txet>removed spam</spam-txet>.



<p-s s="0.052270353"></p-s>Getting these notifications wasn't unusual in and of itself - I was a moderator of a few fairly small subreddits that'd from time to time get posts automatically <spam-txet>removed</spam-txet> for spam. However, when I went to actually look at the <spam-txet>removed spam</spam-txet>, I saw something I was never meant to see.

<p-s s="0.12595023"></p-s>I saw Reddit's anti-spam internals.<bpm-emote aria-hidden=true>\[](/txt! \"also hi! yes, we have ponymotes ^^\")</bpm-emote>

<svg style="position:absolute;top:-9999px;left:-9999px;" inert width="768" height="768" viewBox="0 0 768 768" xmlns="http://www.w3.org/2000/svg">
  <filter id="censor">
    <feTurbulence
      type="turbulence"
      baseFrequency="0.15"
      numOctaves="2"
      result="turbulence" />
    <feDisplacementMap
      in="SourceGraphic"
      in2="turbulence"
      scale="8"
      xChannelSelector="R"
      yChannelSelector="G" />
    <feOffset dx="-2" dy="-2" />
  </filter>
</svg>

<style>
  :root {
    --relay-border: 4px;
    --relay-font: Roboto, Inter, system-ui, sans-serif;
    --relay-condensed-font: "Roboto Condensed", Roboto, Inter, system-ui, sans-serif;
  }
  art-frame:has(relay-post), art-frame:has(relay-comment) {
    content-visibility: visible;
  }
  censor-ed, .censor, [data-censor] {
      filter: url(#censor);
  }
  .coin-shell {
    &:has(input:checked) { display:none }
    input { display: none }
  }
  .reddit {
    display: block;
    font: normal x-small verdana, arial, helvetica, sans-serif;
    background: #FFF;
    color: #000;
    ::selection {
        color: #FFF;
        background: #0041C6CC;
    }
  }
  relay-post {
    transition: background 0.1s;
    &:hover {
      background: #1C2A37;
    }
  }
  relay-comment {
    display: block;
    padding: 14px 10px 15px 14px;
    &:not(:first-child:last-child) {
      border-bottom: 1px solid #2E2E2E;
    }
    p {
      margin: 0;
    }
    &[d="0"], &:not([d]) {
      padding-left: 13px;
    }
    background: #0000;
    position:relative;
    transition: background 0.1s;
    overflow: clip;
    &:hover {
      background: #1C2A37;
    }
    &::after {
      display: none;
      content: "";
      pointer-events: none;
      position: absolute;
      inset: 50%;
      width: 20px;
      height: 20px;
      background: #FFF;
      border-radius: 50%;
      scale: 100;
      opacity: 0;
      transition: display 0.5s allow-discrete, scale 0.25s, opacity 0.5s;
    }
    &:active::after {
      display: block;
      scale: 100;
      opacity: 0.25;
      transition: display 0.5s allow-discrete, scale 0.25s, opacity 0.25s;
      @starting-style {
        scale: 1;
      }
    }
  }
  relay-thread, relay-post {
    ::selection {
      background: #7D7199;
      color: #FFF;
    }
    font-family: var(--relay-font);
    display: block;
    background: #000;
    color: #FFF;
    h1 {
      font-size: 1.15em;
      font-family: inherit;
      color: inherit;
      font-weight: 400;
      margin: 0;
      margin-bottom: 8px;
      a {
        color: inherit;
        text-decoration: inherit;
      }
    }
    a, fake-link {
      color: #8AC7C0;
      text-decoration: underline;
      cursor: pointer;
      word-wrap: break-word;
      line-break: anywhere;
    }
    /*
    &:hover { spam-text, spam-reason { 
      color: #F44;
    } }
    spam-text, spam-reason {
      transition: color 0.1s;
    }
    */
  }
  relay-comment[d="1"] { border-left: var(--relay-border) solid #007399; margin-left: var(--relay-border) }
  relay-comment[d="2"] { border-left: var(--relay-border) solid #73269A; margin-left: calc(var(--relay-border) * 2) }
  relay-comment[d="3"] { border-left: var(--relay-border) solid #4D7400; margin-left: calc(var(--relay-border) * 3) }
  relay-comment[d="4"] { border-left: var(--relay-border) solid #CF7002; margin-left: calc(var(--relay-border) * 4) }
  post-head {
    font-weight: 500;
    post-score {
      font-size: 1.5em;
      margin-right: 0.3em;
    }
  }
  comment-head {
    font-family: var(--relay-condensed-font);
    letter-spacing: -0.25px;
  }
  post-head, comment-head {
    display: block;
    color: #888;
    font-size: 0.9em;
    margin-bottom: 3px;
    comment-user {
      font-family: var(--relay-font);
      color: #889AB1;
      font-weight: 600;
      &[op] {
        color: #FFF;
        background: #007398;
        border-radius: 2px;
        padding: 2px 4px;
      }
    }
    spam-reason {
      white-space: pre-wrap;
      line-break: anywhere;
      /* this is the *actual* color but its a pretty bad accessibility fail */
      color: #AC2E2F;
      /* so i'm using this color instead ^^ */
      color: #E51F1F;
/*      color: #F11515;*/
/*      color: #F44;*/
      font-weight: 600;
    }
  }
  spam-text {
    color: #AC2E2F;
    font-weight: 600;
  }
  relay-post {
    padding: 15px;
    comment-head {
      margin-bottom: 0;
    }
  }
  body:has(#removal-reason:checked) {
    spam-txet {
      color: #AC2E2F;
      font-weight: 600;
    }
  }
  body:not(:has(#removal-reason:checked)) spam-rmev { display:none }
  html:has(#hell:checked){
    &, body {
      background: darkred;
      color: #ffb100;
      spam-text, spam-txet {
        color: #000;
      }
      main > h1, main > h2 {
        color: red;
      }
      a {
        color: red;
      }
    }
  }
</style>

<DIV><art-frame style="height:fit-content;position:relative;" aria-label="cover art, displaying a spamurai spam removal message with a lot of detailed information" role="figure">
  <relay-thread>
    <relay-comment style="margin-top:-1.1lh" d=3><p>so that's about it.</p></relay-comment>
    <relay-comment d=4>
      <comment-head><spam-reason>Removed: spamurai (*Removing potential spam content from unproved user*:
<!---->
 comment `t1_<censor-ed>pupp13</censor-ed>` (0.7294469 perspective spam) by u/<censor-ed>GoodBoyBacon</censor-ed> (0.06 days old, spammy: 11, hosted: false, -1 karma, 4 reports, org: `ComcastCable`, email: gmail.com) in r/<censor-ed>GoodBoysOnly</censor-ed> (guest) posting nil from `oauth.reddit.com` via `nil` from UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36 Edg/95.0.1020.30, RHS: oc:ac:kT:lw:bV:aX:af:a6:l5:y3:aT:m9:pt:f3:hZ:az:aR:aQ, LANG: en-US,en,q=0.9, TLS: j7bXVc3l/qer8FRj2aEiqOrx1ro=DDZ0TViWlY5HYgOPw1SZqDxwiO8= - referrer: https://www.reddit.com/, thumbnail: `` -
<!--.
```You see u/<censor-ed>BadGuy67</censor-ed>? He's the same guy as https://www.reddit.com/r/<censor-ed>ReallyBadGuys</censor-ed>/comments/<censor-ed>qw3rt1</censor-ed>/<censor-ed>if\_ur\_a\_bad\_guy\_post\_here\_please</censor-ed>/```
.
https://www.reddit.com/r/<censor-ed>GoodBoysOnly</censor-ed>/comments/<censor-ed>qw3141</censor-ed>/<censor-ed>if_you_see_an_account_called_badguy67_do_not</censor-ed>/<censor-ed>pupp13</censor-ed>-->)</spam-reason> • <comment-user data-censor>GoodBoyBacon</comment-user> • 1 points • 27 min</comment-head>
      <p>You see <fake-link>u/<censor-ed>BadGuy67</censor-ed></fake-link>? He's the same guy as <fake-link>https://www.reddit.com/r/<censor-ed>ReallyBadGuys</censor-ed>/comments/<censor-ed>qw3rt1</censor-ed>/<censor-ed>if_ur_a_bad_guy_post_here_please</censor-ed>/</fake-link></p>
    </relay-comment>
    <relay-comment style="margin-bottom:-1.1lh" d=2><comment-head><spam-reason>Removed: Reddit (shadowban applied on 10-27-2021)</spam-reason> • <comment-user data-censor>GoodBoyBacon</comment-user> • 0 points • 1 hr</comment-head>
      <p>I'm not the same guy as that other guy please read my comment</p>
    </relay-comment>
  </relay-thread>
  <div style="position: absolute; inset:0;background: linear-gradient(#0006, #0000 20%, #0000 80%, #0006); pointer-events: none;"></div>
</art-frame></DIV>

<div style="height:1em"></div>
<!-- So, what happened? -->

<div style="width:324px;height:262px;float:right;anchor-name:--mod"><style>@scope { & { display:block; @media (width < 720px) { & { display:none; } } } }</style></div>

## How Reddit moderation works

<p-s s="0.934485"></p-s>So Reddit is a site comprising of smaller sub-communities, which are called subreddits. For example, [/r/mylittlepony](https://old.reddit.com/r/mylittlepony) is a subreddit for fans of My Little Pony. These subreddits can be created by anyone, and they are moderated by a group of community moderators appointed by the creator of the subreddit.

<p-s s="0.8253275"></p-s>If we go[^modlist] on [/r/mylittlepony](https://old.reddit.com/r/mylittlepony) we can see the list of moderators on the sidebar: <span style="position:absolute;anchor-name:--modt"></span><span style="position:absolute;height:4px;translate: 16px 7px;background:#FFF;left:anchor(--modt left);right:anchor(--mod left);border-radius:0 100px 100px 0;corner-shape:bevel"></span><!--<span style="position:absolute;anchor-name:--modt;background:#8CFFDB;height:8px;translate: 0 5px;width:8px;border-radius:0 100px 100px 0;corner-shape:bevel;z-index: 1;"></span><span style="position:absolute;height:8px;translate: 0 5px;background:#FFF;left:anchor(--modt left);right:anchor(--mod left);border-radius:0 100px 100px 0;corner-shape:bevel"></span>-->

<article class="reddit" aria-label="reddit moderators sidebar" role="figure">
  <style>
    @scope {
      @media (width >= 720px) {
        @supports (anchor-name:--supports) {
          & {
            position: absolute;
            width: 300px;
            top: anchor(--mod top);
            right: anchor(--mod right);
          }
        }
      }
      & {
        padding: 8px;
        padding-top: 6px;
        border-radius: 3px;
      }
      &:not(:has(input:checked)) #sent {
        display: none;
      }
      h1 {
        display: inline;
        margin: 0;
        color: gray;
        font-family: inherit;
        font-size: 130%;
        font-weight: normal;
      }
      ul {
        margin: 0;
        padding: 5px;
        border: 1px solid gray;
        font-size: larger;
        list-style: none;
      }
      .message-button {
        padding: 5px 0 10px;
        text-align: center;
        label {
          display: inline-block;
          font-weight: bold;
          cursor: pointer;
          border: 1px solid transparent;
          padding: 4px 12px 3px;
          line-height: 20px;
          border-radius: 3px;
          -webkit-user-select: none;
          user-select: none;
          background-color: #4f86b5;
          border-bottom: 2px solid #4270a2;
          color: #FFF;
          text-decoration: none;
          &:hover, &:active {
            background-color: #4980ae;
          }
          &:active {
            border-bottom-width: 1px;
            margin-top: 1px;
          }
        }
      }
      a {
        cursor: pointer;
      }
      --b:-1;
      .more {
        --a: calc(var(--c, 0) + 1);
        --o: 0;
        a { color: gray }
        animation: x 1ms infinite, y 1ms infinite;
        animation-play-state: paused, paused;
        &:has(a:first-child:active) {
          animation-play-state: running, paused;
        }
        &:has(a:last-child:active) {
          animation-play-state: paused, running;
        }
        a:last-child {
            display: none;
        }
        @container style(--a > --b) {
          a:first-child {
            display: none;
          }
          a:last-child {
            display: block;
          }
          a::after {
            --o: 0;
          }
        }
        @container style(--a = --b) {
          a::after {
            --o: 1;
          }
        }
        margin-top: 5px;
        text-align: right;
        font-size: smaller;
        a::after {
          counter-reset: a calc(var(--a) * 2 + var(--o) + 17);
          content: counter(a) " more »";
          @container style(--a > 2) {
            white-space: pre-wrap;
            content: counter(a) " more ?";
          }
          @container style(--a > 10) {
            white-space: pre-wrap;
            content: counter(a) " more ??";
          }
          @container style(--a > 25) {
            white-space: pre-wrap;
            content: counter(a) " more ???";
          }
          @container style(--a > 55) {
            white-space: pre-wrap;
            content: 'Exception in thread "main" java.lang.ArithmeticException: ' counter(a) ' is out of range\a     at lyra.horse.blog.posts.RedditPost.increaseCounter(RedditPost.java:385)\a     at lyra.horse.blog.Main.POST_REQUEST(Blog.java:53)\a     at lyra.horse.blog.Main.serve(Blog.java:103)';
          }
          @container style(--a > 65) {
            white-space: pre-wrap;
            content: 'Exception in thread "main" java.lang.ArithmeticException: ' counter(a) ' is out of range\a     at lyra.horse.blog.posts.RedditPost.increaseCounter(RedditPost.java:385)\a     at lyra.horse.blog.Main.POST_REQUEST(Blog.java:53)\a     at lyra.horse.blog.Main.serve(Blog.java:103)\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a ';
          }
          @container style(--a > 80) {
            position: fixed;
            width: 100vw;
            height: 100lvh;
            top:0;
            left: 0;
            padding:64px;
            background: #000;
            z-index: 10;
            color: #F00;
            box-sizing: border-box;
            white-space: pre-wrap;
            content: 'Exception in thread "main" java.lang.ArithmeticException: ' counter(a) ' is out of range\a     at lyra.horse.blog.posts.RedditPost.increaseCounter(RedditPost.java:385)\a     at lyra.horse.blog.Main.POST_REQUEST(Blog.java:53)\a     at lyra.horse.blog.Main.serve(Blog.java:103)\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\a Segmentation fault (core dumped)\a root@lyra.horse #';
          }
        }
      }
    }
    @property --a {
      syntax: "<integer>";
      initial-value: 0;
      inherits: true;
    }
    @keyframes x { 0%, 100% { --c: var(--b, 0); } }
    @keyframes y { 0%, 100% { --b: var(--a, 0); } }
  </style>
  <h1>MODERATORS</h1>
  <ul>
    <li class="message-button"><label style="cursor:pointer;">MESSAGE THE MODS<input type=radio name=send style="display:none"></label></li>
    <li id="sent" style="color:red;text-align:center;margin-top:-6px;">message sent.</li>
    <li><a>Orschmann</a></li>
    <li><a>optimistic_outcome</a></li>
    <li><a>Chinch335</a></li>
    <li><a>IllusionOf_Integrity</a></li>
    <li><a>spokesthebrony</a></li>
    <li><a>TheeLinker</a></li>
    <li><a>Lankygit</a></li>
    <li><a>Raging_Mouse</a></li>
    <li><a>Searchbar_Trixie</a></li>
    <li><a>gbeaudette</a></li>
    <li class="more"><a>...and </a><a>...and </a></li>
  </ul>
</article>

<p-s s="0.19897911"></p-s><bpm-emote aria-hidden=true left>\[](/hellohuman)</bpm-emote>These moderators can remove posts, ban users, manage modmail etc, but they are just normal Reddit users.

<p-s s="0.25761342"></p-s>If you're a moderator you can see who removed a post or comment:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: rebane2001</spam-reason> • <comment-user>ExampleUser</comment-user> • 1 points • 1 hr</comment-head>
      <p>I'm breaking the rules 😈</p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.7261582"></p-s>This includes the [automod](https://old.reddit.com/r/reddit.com/wiki/automoderator) - a rules-based moderation system:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: AutoModerator</spam-reason> • <comment-user>ExampleUser</comment-user> • 1 points • 1 hr</comment-head>
      <p>bad word</p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.40763098"></p-s>But then you'll sometimes also see the mysterious "Auto":

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: Auto</spam-reason> • <comment-user>ExampleUser</comment-user> • 1 points • 1 hr</comment-head>
      <p>hi</p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.574405"></p-s>This is what happens when something gets caught in Reddit's mysterious spam filters, or when Reddit's sitewide admins <spam-txet>remove</spam-txet> something manually.

<p-s s="0.11612948"></p-s>In the moderator log, they'll show up as "reddit" and "Anti-Evil Operations":

<style>
  .reddit {
  nav {
    height: 18px;
    background: #F0F0F0;
    border-bottom: 1px solid #808080;
    text-transform: uppercase;
      white-space: nowrap;
    ul {
      font-size: 90%;
      line-height: 18px;
      list-style-type: none;
      list-style: none;
      display: inline;
      padding: 0;
      -webkit-user-select: none;
      user-select: none;
      li {
        display: inline;
        cursor: pointer;
        &:hover {
          text-decoration: underline;          
        }
        &::after {
          content: " -";
          white-space: pre;
          display: inline-block;
          color: gray;
          position: relative;
        }
        &.sep::after {
          content: " |";
        }
        &.arr {
          margin-right: 28px;
          padding-left: 5px;
        }
        &.arr::after {
          content: "";
          border: 6px solid #0000;
          border-top-color: grey;
          position: absolute;
          display: inline-block;
          translate: 4px 8px;
        }
      }
    }
  }
  header {
    display: flex;
    align-items: flex-end;
    height: 45px;
    background: #CEE3F8;
    border-bottom: 1px solid #5F99CF;
    font-size: larger;
    padding-left: 4px;
    margin-bottom: 0;
    h1 {
      margin: 0;
      margin-right: 1ex;
      font-family: inherit;
      font-variant: small-caps;
      font-weight: bold;
      font-size: 1.2em;
      color: #000;
      a {
        cursor: pointer;
        color: inherit;
        &:hover {
          text-decoration: underline;
        }
      }
    }
  }
  main {
    margin: 7px 5px 0px 5px;
  }
  .filter {
  select,::picker(select) {
    appearance: base-select;
  }
  select {
    border: none;
    padding: 0;
    margin: 0;
    min-height: 0;
    &:has(option:first-child:checked) {
      max-width: 50px;  
    }
    display: inline-flex;
    white-space: pre;
    text-decoration: underline;
    color: gray;
    font-weight: bold;
    cursor: pointer;
    margin-right: 16px;
    &:hover {
      background: #0000;
    }
  }
  ::picker(select) {
    border-color: grey;
  }
  option {
    padding: 2px 3px 1px 3px;
    line-height: normal;
    font-weight: normal;
    color: #369;
    display: block;
    min-height: 0;
    &:hover {
      background: #c7def7;
    }
    &:checked {
      font-weight: bold;
    }
  }
  ::checkmark {
    display: none;
  }
  }
}
</style>

<DIV><art-frame style="min-height: 300px" aria-label="reddit moderation log" role="figure">
  <article class="reddit">
    <nav aria-hidden=true>
      <ul>
        <li class="arr">my subreddits</li>
      </ul>
      <ul>
        <li>popular</li>
        <li>all</li>
        <li class="sep">users</li>
        <li>AskReddit</li>
        <li>pics</li>
        <li>funny</li>
        <li>movies</li>
        <li>gaming</li>
        <li>worldnews</li>
        <li>news</li>
        <li>todayilearned</li>
        <li>nottheonion</li>
        <li>explainlikeimfive</li>
        <li>mildlyinteresting</li>
        <li>DIY HRT</li>
      </ul>
    </nav>
    <header><h1><a><censor-ed>ExampleSubreddit</censor-ed></a>: moderation log</h1></header>
    <main>
<style>@scope {
  &:not(:has([data-rm]:checked)) tr:is([data-red],[data-aeo]) {
    display: none;
  }
  &:not(:has([value="all"]:checked)) tr[data-red] {
    display: none;
  }
  &:not(:has([value="all"]:checked)):not(:has([value="admins"]:checked)) tr[data-aeo] {
    display: none;
  }
  &:has([value="secret"]:checked) {
    color:red; /* TODO: secret */
  }
}</style>
      <div style="font-size: larger;padding: 5px 10px;margin: 5px;border-bottom: 1px dotted gray;" class="filter">filter by action: <select><option selected data-rm>all</option>
<option>accept moderator invite</option>
<option>add community topics</option>
<option>add contributor</option>
<option>add moderator</option>
<option>add note</option>
<option>add removal reason</option>
<option>adjust post crowd control level</option>
<option>approve award</option>
<option>approve comment</option>
<option>approve post</option>
<option>ban user</option>
<option>chat approve message</option>
<option>chat ban user</option>
<option>chat invite host</option>
<option>chat remove host</option>
<option>chat remove message</option>
<option>chat unban user</option>
<option>collections</option>
<option>community status</option>
<option>style community</option>
<option>community welcome_page</option>
<option>widgets</option>
<option>create award</option>
<option>create scheduled post</option>
<option>create removal reason</option>
<option>create rule</option>
<option>delete award</option>
<option>delete scheduled post</option>
<option>delete note</option>
<option>delete overridden subreddit classification</option>
<option>delete removal reason</option>
<option>delete rule</option>
<option>app changed</option>
<option>app disabled</option>
<option>app enabled</option>
<option>app installed</option>
<option>app uninstalled</option>
<option>disable award</option>
<option>disable post crowd control filtering</option>
<option>distinguish</option>
<option>edit comment requirements</option>
<option>edit post requirements</option>
<option>edit saved response</option>
<option>edit scheduled post</option>
<option>edit flair</option>
<option>edit rule</option>
<option>edit settings</option>
<option>enable award</option>
<option>enable post crowd control filtering</option>
<option>events</option>
<option>award hidden</option>
<option>ignore reports</option>
<option>invite moderator</option>
<option>invite subscriber</option>
<option>lock post</option>
<option>mark nsfw</option>
<option>mark as original content</option>
<option>mod award given</option>
<option>enroll in new modmail</option>
<option>mute user</option>
<option>override subreddit classification</option>
<option>remove community topics</option>
<option>remove comment</option>
<option>remove contributor</option>
<option data-rm>remove post</option>
<option>remove moderator</option>
<option>remove wiki contributor</option>
<option>reorder moderators</option>
<option>reorder removal reason</option>
<option>reorder rules</option>
<option>request assistance</option>
<option>set contest mode</option>
<option>permissions</option>
<option>set suggested sort</option>
<option>show comment</option>
<option>snooze reports</option>
<option>spam comment</option>
<option>spam post</option>
<option>mark spoiler</option>
<option>sticky post</option>
<option>submit content rating survey</option>
<option>submit scheduled post</option>
<!-- <option id="secret" value="secret">secret easter egg</option> -->
<option>unban user</option>
<option>unignore reports</option>
<option>uninvite moderator</option>
<option>unlock post</option>
<option>unmute user</option>
<option>unset contest mode</option>
<option>unsnooze reports</option>
<option>unmark spoiler</option>
<option>unsticky post</option>
<option id="removal-reason">update <spam-text>removal reason</spam-text></option>
<option>ban from wiki</option>
<option>add wiki contributor</option>
<option>delist/relist wiki pages</option>
<option>wiki page permissions</option>
<option>wiki revise page</option>
<option>unban from wiki</option></select> filter by moderator: <select><option selected value="all">all</option>
<option>rebane2001</option>
<option>AutoModerator</option>
<option value="admins">admins*</option>
</select></div>
      <style>
        @scope {
          table {
            margin: 0 5px;
            font-size: small;
            border-collapse: collapse;
            td {
              font-size: small;
              text-align: left;
              padding: 2px clamp(0px, calc(2vw - 6px), 10px);
            }
            a {
              cursor: pointer;
            }
            .stop {
              display: inline-block;
              outline: 1px solid #FFF8;
              margin: 2px;
              outline-offset: -2px;
              border-radius: 16px;
              width: 14px;
              height: 14px;
              background: linear-gradient(-15deg, #BB4125, #F0785F, #FF836D);
              position: relative;
              &::before{
                content: "";
                position: absolute;
                background: #FFF;
                left: 4px;
                top: 6px;
                height: 2px;
                width: 6px;
              }
              /*
              &::before{
                content: "";
                position: absolute;
                background: #FFF;
                left: 6px;
                top: 3px;
                height: 5px;
                width: 2px;
                border-bottom-left-radius: 1.4px;
              }
              &::after{
                content: "";
                position: absolute;
                background: #FFF;
                left: 6px;
                top: 9px;
                height: 2px;
                width: 2px;
                translate: 0 -0.5px;
              }
              */
            }
          }
        }
      </style><spam-rmev>You cannot be <spam-text>reasoned</spam-text> with.</spam-rmev>
      <table>
        <tbody>
          <tr data-aeo>
            <td>13 days ago</td>
            <td>
              <a>Anti-Evil Operations</a>
            </td>
            <td><i class="stop"></i></td>
            <td class="description">removed <a title="[ Removed by Reddit ]">link "[ Removed by Reddit ]" by <censor-ed>EvilPoster</censor-ed></a>
            </td>
          </tr>
          <tr data-aeo>
            <td>27 days ago</td>
            <td>
              <a>Anti-Evil Operations</a>
            </td>
            <td><i class="stop"></i></td>
            <td class="description">removed <a title="[ Removed by Reddit ]">link "[ Removed by Reddit ]" by <censor-ed>Rule_Breaker1337</censor-ed></a>
            </td>
          </tr>
          <tr data-red>
            <td>1 month ago</td>
            <td>
              <a>reddit</a>
            </td>
            <td><i class="stop"></i></td>
            <td class="description">removed <a title="buy my shirt">link "buy my shirt" by <censor-ed>xXx_ShirtSeller_xXx</censor-ed></a>
            </td>
          </tr>
          <tr data-red>
            <td>1 month ago</td>
            <td>
              <a>reddit</a>
            </td>
            <td><i class="stop"></i></td>
            <td class="description">removed <a title="sexy ladies">link "sexy ladies" by <censor-ed>SpamBot_00018341</censor-ed></a>
            </td>
          </tr>
          <tr data-aeo>
            <td>2 months ago</td>
            <td>
              <a>Anti-Evil Operations</a>
            </td>
            <td><i class="stop"></i></td>
            <td class="description">removed <a title="[ Removed by Reddit ]">link "[ Removed by Reddit ]" by <censor-ed>PuppyGirlHater</censor-ed></a>
            </td>
          </tr>
        </tbody>
      </table><bpm-emote aria-hidden=true right>[](/txt! "i was too lazy to moderate so i let reddit and AEO take care of it all teehee")[](/lyrahi)</bpm-emote>
    </main>
  </article>
</art-frame></DIV>

<p-s s="0.27704874"></p-s>These sitewide spam <spam-txet>removals</spam-txet> is what the rest of this post is going to be about.

## Oopsie

<p-s s="0.06256095"></p-s><bpm-emote aria-hidden=true left>\[](/lyranotone)</bpm-emote>What happened to me back in 2021 was that due to some kind of an error on Reddit's side, the usual <spam-text>Removed: Auto</spam-text> text had been replaced with the <spam-txet>actual removal reason</spam-txet>. Why this happened to me I do not know - it returned back to normal after an hour or so. All I was left with was a bunch of screenshots I managed to take while this stuff was still going on.

<p-s s="0.019303687"></p-s>But that doesn't mean we can't speculate!

<p-s s="0.011414415"></p-s>Up until 2017, Reddit's [source code](https://github.com/reddit-archive/reddit/) was publicly available. Of course, a lot has changed since then, but we can still analyze the archived code and hypothesize what might be happening.

<style>
  .sx-block, code-frame {
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
  }
  /* token-atom - #C4EED0 */
  sx-a { color: #C4EED0; }
  /* token-attribute - #A8C7FA */
  sx-r { color: #A8C7FA; }
  /* token-attribute-value - #FE8D59 */
  sx-v { color: #FE8D59; }
  /* token-comment - #ABABAB */
  sx-c { color: #ABABAB; }
  /* token-keyword - #BF67FF */
  sx-k { color: #BF67FF; color:#cd97ff; }
  /* token-number - #C4EED0 */
  sx-n { color: #C4EED0; }
  /* token-property - #FACC15 */
  sx-p { color: #FACC15; }
  /* token-string - #FE8D59 */
  sx-s { color: #FE8D59; }
  /* token-tag - #7CACF8 */
  sx-t { color: #7CACF8; }
  /* token-type - #7CACF8 */
  sx-y { color: #7CACF8; }
  /* token-variable - #C7C7C7 */
  sx-e { color: #C7C7C7; }
  /* token-variable-special - #6DD58C */
  sx-l { color: #6dd5ba; }
  /* @at-rules */
  sx-z { color: #ffa4e0; }
  /* media query attributes */
  sx-x { color: #f169db; }
  /* special comment */
  sx-m { color: #8CFFDB; font-style: italic }
</style>

<p-s s="0.70833623"></p-s>The function responsible for moderator removals is **[POST_remove](https://github.com/reddit-archive/reddit/blob/753b17407e9a9dca09558526805922de24133d53/r2/r2/controllers/api.py#L3037-L3090)**:

<pre class="sx-block"><code><sx-k>def</sx-k> <sx-t>POST_remove</sx-t>(<sx-k>self</sx-k>, <sx-t>thing</sx-t>, <sx-t>spam</sx-t>):
    <sx-s>"""Remove a link, comment, or modmail message."""</sx-s>
    <sx-c>...</sx-c>
    <sx-e>admintools</sx-e>.<sx-p>spam</sx-p>(<sx-e>thing</sx-e>, <sx-l>auto</sx-l>=<sx-a>False</sx-a>,
                    <sx-l>moderator_banned</sx-l>=<sx-k>not</sx-k> <sx-e>c</sx-e>.<sx-p>user_is_admin</sx-p>,
                    <sx-l>banner</sx-l>=<sx-e>c</sx-e>.<sx-p>user</sx-p>.<sx-p>name</sx-p>,
                    <sx-l>train_spam</sx-l>=<sx-e>train_spam</sx-e>)</code></pre>

<p-s s="0.38024524"></p-s>We can see it calls **admintools.spam** with a few arguments, notably: **moderator_banned**, which marks whether something was removed by a moderator or an admin, and **banner**, which notes down the username of whoever did the ban action.

<p id="get_mod_attributes"><p-s s="0.7298972"></p-s>Poking around a bit more, we find the <strong><a href="https://github.com/reddit-archive/reddit/blob/753b17407e9a9dca09558526805922de24133d53/r2/r2/lib/jsontemplates.py#L618-L639">get_mod_attributes</a></strong> function:</p>

<pre class="sx-block"><code><sx-m># Comments added by me for the blogpost</sx-m>
<sx-k>def</sx-k> <sx-t>get_mod_attributes</sx-t>(<sx-t>item</sx-t>):
    <sx-e>data</sx-e> = {}
    <sx-m># If user is logged in and a moderator</sx-m>
    <sx-k>if</sx-k> <sx-e>c</sx-e>.<sx-p>user_is_loggedin</sx-p> <sx-k>and</sx-k> <sx-e>item</sx-e>.<sx-p>can_ban</sx-p>:
        <sx-e>data</sx-e>[<sx-s>"num_reports"</sx-s>] = <sx-e>item</sx-e>.<sx-p>reported</sx-p>
        <sx-e>data</sx-e>[<sx-s>"report_<spam-txet>reasons</spam-txet>"</sx-s>] = <sx-e>Report</sx-e>.<sx-p>get_<spam-txet>reasons</spam-txet></sx-p>(<sx-e>item</sx-e>)

        <sx-e>ban_info</sx-e> = <sx-p>getattr</sx-p>(<sx-e>item</sx-e>, <sx-s>"ban_info"</sx-s>, {})
        <sx-m># If post was removed</sx-m>
        <sx-k>if</sx-k> <sx-e>item</sx-e>.<sx-p>_spam</sx-p>:
            <sx-e>data</sx-e>[<sx-s>"approved_by"</sx-s>] = <sx-k>None</sx-k>
            <sx-m># If post was removed by a mod</sx-m>
            <sx-k>if</sx-k> <sx-e>ban_info</sx-e>.<sx-p>get</sx-p>(<sx-s>'moderator_banned'</sx-s>):
                <sx-m># Show the banner name</sx-m>
                <sx-e>data</sx-e>[<sx-s>"banned_by"</sx-s>] = <sx-e>ban_info</sx-e>.<sx-p>get</sx-p>(<sx-s>"banner"</sx-s>)
            <sx-k>else</sx-k>: <sx-m># else, if post was removed by an admin</sx-m>
                <sx-m># Hide the banner name</sx-m>
                <sx-e>data</sx-e>[<sx-s>"banned_by"</sx-s>] = <sx-a>True</sx-a>
        <sx-k>else</sx-k>:
            <sx-e>data</sx-e>[<sx-s>"approved_by"</sx-s>] = <sx-e>ban_info</sx-e>.<sx-p>get</sx-p>(<sx-s>"unbanner"</sx-s>)
            <sx-e>data</sx-e>[<sx-s>"banned_by"</sx-s>] = <sx-k>None</sx-k>
    <sx-k>else</sx-k>:
        <sx-e>data</sx-e>[<sx-s>"num_reports"</sx-s>] = <sx-k>None</sx-k>
        <sx-e>data</sx-e>[<sx-s>"report_<spam-txet>reasons</spam-txet>"</sx-s>] = <sx-k>None</sx-k>
        <sx-e>data</sx-e>[<sx-s>"approved_by"</sx-s>] = <sx-k>None</sx-k>
        <sx-e>data</sx-e>[<sx-s>"banned_by"</sx-s>] = <sx-k>None</sx-k>
    <sx-k>return</sx-k> <sx-e>data</sx-e></code></pre>

<p-s s="0.19158998"></p-s>This is the part of the API that actually returns us the information about removals - the **banner** in *ban_info* is the <spam-text>red text</spam-text> I was seeing Relay. And it seems like it will only get returned if the removal was by a moderator, not an admin. But where does that <spam-text>Auto</spam-text> text come from? Reddit's API only returns an actual username, or `True`.

<p-s s="0.43001541"></p-s>Turns out that it's actually coming from Relay[^relaysource] itself:

<pre class="sx-block"><code><sx-c>// reddit/news/oauth/reddit/model/base/RedditLinkComment.java</sx-c>
<sx-k>if</sx-k> (<sx-k>this</sx-k>.<sx-p>bannedBy</sx-p>.<sx-p>equalsIgnoreCase</sx-p>(<sx-s>"true"</sx-s>)) {
    <sx-k>this</sx-k>.<sx-p>bannedBy</sx-p> = <sx-s>"Auto"</sx-s>;
} <sx-k>else if</sx-k> (<sx-k>this</sx-k>.<sx-p>bannedBy</sx-p>.<sx-p>equalsIgnoreCase</sx-p>(<sx-s>"null"</sx-s>)) {
    <sx-k>this</sx-k>.<sx-p>bannedBy</sx-p> = <sx-s>""</sx-s>;
}</code></pre>

<p-s s="0.106866576"></p-s>Okay, that explains that. But where am I getting these <spam-text>internal messages</spam-text> from?<bpm-emote aria-hidden=true right>\[](/lyrathink)</bpm-emote>

<p-s s="0.45305812"></p-s>Well, it seems like [Reddit is re-using](https://github.com/reddit-archive/reddit/blob/753b17407e9a9dca09558526805922de24133d53/r2/r2/controllers/api.py#L558-L564) the **banner** field for <spam-txet>internal removal reasons</spam-txet>:

<pre class="sx-block"><code><sx-k>def</sx-k> <sx-t>POST_submit</sx-t>(<sx-k>self</sx-k>, <sx-t>form</sx-t>, <sx-t>jquery</sx-t>, <sx-t>url</sx-t>, <sx-t>selftext</sx-t>, <sx-t>kind</sx-t>, <sx-t>title,
                sr</sx-t>, <sx-t>extension</sx-t>, <sx-t>sendreplies</sx-t>, <sx-t>resubmit</sx-t>):
    <sx-s>"""Submit a link to a subreddit."""</sx-s>
    <sx-c>...</sx-c>
    <sx-k>if not</sx-k> <sx-e>is_self</sx-e>:
        <sx-e>ban</sx-e> = <sx-p>is_banned_domain</sx-p>(<sx-e>url</sx-e>)
        <sx-k>if</sx-k> <sx-e>ban</sx-e>:
            <sx-e>g</sx-e>.<sx-p>stats</sx-p>.<sx-p>simple_event</sx-p>(<sx-s>'spam.domainban.link_url'</sx-s>)
            <sx-e>admintools</sx-e>.<sx-p>spam</sx-p>(<sx-e>l</sx-e>, <sx-l>banner</sx-l> = <sx-s>"domain (%s)"</sx-s> % <sx-e>ban</sx-e>.<sx-p>banmsg</sx-p>)
            <sx-e>hooks</sx-e>.<sx-p>get_hook</sx-p>(<sx-s>'banned_domain.submit'</sx-s>).<sx-p>call</sx-p>(<sx-l>item</sx-l>=<sx-e>l</sx-e>, <sx-l>url</sx-l>=<sx-e>url</sx-e>,
                                                        <sx-l>ban</sx-l>=<sx-e>ban</sx-e>)</code></pre>

<p-s s="0.510564"></p-s>The above code snippet runs whenever a new link is posted. It checks whether the domain is spam, and if it is it removes it with the **banner** set to "domain (<spam-text>REASON</spam-text>)".

<p-s s="0.3142368"></p-s>We can see it in action with this <spam-txet>removed</spam-txet> post for example:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>I_EAT_PONIES</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1><a href="http://24.media.tumblr.com/tumblr_m7yp9ysNCV1r361q4o1_400.gif">Conga!</a></h1>
    <comment-head><spam-reason>Removed: domain (banned as an experiment to see what happens with tubmlr spam ring. - em 5/31/12)</spam-reason> • 0 Comments • 24.media.tumblr.com • 9 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.4717271"></p-s>Seems like <spam-text>em</spam-text> was playing around with auto-removing all <spam-text>tubmlr</spam-text> <span style="color:green">[sic]</span> links on Reddit in 2012?

<p-s s="0.36631143"></p-s>Anyways, it seems like Reddit is stuffing its <spam-text>internal spam removal reasons</spam-text> in the **banner** field, but making it so that only sitewide admins can see <spam-text>them</spam-text>. And something in a codepath similar to **[get_mod_attributes](#get_mod_attributes)** was broken for a couple hours, allowing me to see those <spam-text>reasons</spam-text>.

<p-s s="0.13435893"></p-s>Let's take a look at the kinds of <spam-text>reasons</spam-text> I managed to get a glimpse of!

## domain (2012 - present)

<p-s s="0.25283572"></p-s>The first category is the domain <spam-txet>removals</spam-txet>, as shown earlier. Nearly all of these are just <spam-text>Removed: domain (spam)</spam-text>, though I did find this gem in there:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>presafur</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1>Just register and look for me here* h9OI5WUQZPL</h1>
    <comment-head><spam-reason>Removed: domain (le sexxxxy sex spam)</spam-reason> • 0 Comments • <censor-ed>www.example</censor-ed>.com • 5 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.35198227"></p-s>Perhaps I'm just childish, but I find the idea of someone going <spam-text>le sexxxxy sex spam</spam-text> while working on a spamfilter rather amusing.

<p-s s="0.7129027"></p-s>Reddit probably had some issues with Tumblr spam, because in addition to the <spam-text>tubmlr</spam-text> removal we saw earlier there was also this:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>JackofH3art</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1><a href="https://bartl3by.tumblr.com/post/41108523402">It hurts so good.</a></h1>
    <comment-head><spam-reason>Removed: domain (ban - 11/12/12 mg )</spam-reason> • <spam-reason>NSFW</spam-reason> • 0 Comments • bartl3by.tumblr.com • 8 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.4931129"></p-s>I'm quite certain that this <spam-txet>removal</spam-txet> was targeted at Tumblr in general, and not the specific blog linked, since [bartl3by.tumblr.com](https://bartl3by.tumblr.com) seems to be a legitimate (although somewhat perverse) blog.

<p-s s="0.16809195"></p-s>I believe domain <spam-txet>removals</spam-txet> are the only type of anti-spam we can actually see in the public Reddit source code. Though, even that is [partially hidden](https://github.com/reddit-archive/reddit/blob/753b17407e9a9dca09558526805922de24133d53/r2/r2/models/admintools.py#L338-L339).

## spammit (2012 - present)

<p-s s="0.08275926"></p-s>The next category is spammit, which *somehow* analyses a post and gives it a percentage rating:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>Kyderra</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1><a href="https://theponyarchive.com/archive/mlfw/mlfw/mlfw8871-155478_-_animated_nudge_rainbow_dash_spitfire_wingboner.gif">I'm very fondling of you</a></h1>
    <comment-head><spam-reason>Removed: spammit(72.98% spammy)</spam-reason> • 0 Comments • dashie.mylittlefacewhen.com • 8 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.019732786"></p-s>Yes, there's no space between <spam-text>spammit</spam-text> and the parenthesis.

<p-s s="0.15676004"></p-s>The percentages of removed posts were generally fairly high, with the lowest one being <spam-text>39.71% spammy</spam-text> and highest one <spam-text>98.19%</spam-text>.

<p-s s="0.4247034"></p-s><bpm-emote aria-hidden=true right>\[](/lyram02)</bpm-emote>That being said, spammit doesn't seem like a very accurate anti-spam measure for the subs I moderate because it seemed to hit a lot of legitimate Imgur posts with a 70-98% spammy rating.

## bans (2016 - present)

<p-s s="0.19312142"></p-s>Next, we have post <spam-txet>removals</spam-txet> for banned users.

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>kaitlynwwrettin</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1>Cost Reduction & Cost Saving Consultants | <censor-ed>Puppygirl Consulting</censor-ed></h1>
    <comment-head><spam-reason>Removed: banned user</spam-reason> • 0 Comments • <censor-ed>www.example</censor-ed>.com • 3 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.7246773"></p-s>Some of them are marked with just a <spam-text>Removed: banned user</spam-text>, though others get a fancy <spam-text>Removed: Reddit (banall performed)</spam-text>.

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>KerryVinebt403</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1>casino online</h1>
    <comment-head><spam-reason>Removed: Reddit (banall performed)</spam-reason> • 0 Comments • <censor-ed>example</censor-ed>.com • 3 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.60610497"></p-s>The posts I saw being <spam-text>removed</spam-text> like this were all very obvious spam. Mostly just ads for all kinds of services. I suspect this is the admins seeing an obvious spambot and just nuking it from orbit.

## shadowbans (2016 - present)

<p-s s="0.71428186"></p-s>It's known that Reddit shadowbans its users. A shadowban is a silent ban where seemingly nothing happens to your account and you're still able to post/comment, but nobody else will be able to see your posts and comments. In fact, there's even [a subreddit](https://old.reddit.com/r/ShadowBan/) for checking whether you're shadowbanned.

<p-s s="0.6041682"></p-s>But now we can actually see what a shadowban looks like to admins:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>pickertramontana</comment-user> in <comment-user>trixiemasterrace</comment-user></post-head>
    <h1>Blonde Teen Takes A Massive <censor-ed>Meow</censor-ed> In Her <censor-ed>Bark</censor-ed></h1>
    <comment-head><spam-reason>Removed: Reddit (shadowban applied on 11-06-2019)</spam-reason> • 0 Comments • self.trixiemasterrace • 1 yr</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.36274686"></p-s>I'm not going to share the specific conversation here, but there was a really funny comments thread going on where a person was blaming mods for <spam-text>removing</spam-text> all of their comments while in reality being shadowbanned by Reddit.

## spamurai (2020 - present)

<p-s s="0.73813266"></p-s><bpm-emote aria-hidden=true left>\[](/lyradevious)</bpm-emote>Now we get to the most interesting part of the entire spam filter thing. Unlike spammit, spamurai is a system that does have [some public references](https://www.ai-expo.net/global/wp-content/uploads/2019/04/0950_Anand_Mariappan_Reddit_ENT2.pdf) to it. According to slide #28, Reddit uses Minsky for "ML", and Spamurai for "Rules". I'm not sure how this is calculated into the <spam-text>removal reasons</spam-text>, so [I'm just going to ignore it](https://www.youtube.com/watch?v=ZLoXILYESOM) and assume everything is spamurai.

<p-s s="0.34744784"></p-s>First up, there seems to be some sort of a spamurai subsystem called <spam-text>echelon</spam-text>. It seems to remove certain keywords, such as the EqG elsagate spam seen below, and lewd (OF? Snapchat?) stuff like <spam-text><censor-ed>puppy</censor-ed>vids.69</spam-text>.

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>mypham71375</comment-user> in <comment-user>Pony_irl</comment-user></post-head>
    <h1>Equestria Girls Princess Animation Series - Twilight Sparkle Cutie Mark ...</h1>
    <comment-head><spam-reason>Removed: spamurai (echelon: Equestria Girls Princess Animation Series)</spam-reason> • 1 Comments • youtube.com • 2 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.09360283"></p-s>Then, there's some targeted <spam-text>removals</spam-text>, such as this one that targets clothing spam.

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: spamurai (approval required on hyperlink comment from high spam score account (suspected shirt affiliate spam))</spam-reason> • <comment-user>Adventurous-ties</comment-user> • 1 points • 5 months</comment-head>
      <p><fake-link><label style="cursor:pointer"><censor-ed>Dog-Women</censor-ed> consulting company will open the Ukrainian pharmaceutical market for you!<input style="opacity: 0;position: absolute;pointer-events: none;" type=checkbox id=ukraine></label></fake-link></p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<style>
  body:not(:has(#ukraine:checked)) {
    #ukrainian {
      display: none;
    }
  }
  body:has(#perspectrogen:checked) {
    .store-item2 {
      display: none;
    }
    .store-item3 {
      display: block;
    }
/*p-s { &::after { content: attr(s); color:red } }*/
/*p-s { &::after { content: "0.12571794";white-space:pre;line-height:1;font-weight: 600;position:absolute;user-select:none;translate: calc(-100% - 16px) 0;text-align:right; } }*/
p-s { &::after {
  content: "Spam: " attr(s);/*"Spam: 0.12571794";*/
  background:#451735;
  background:hsl(calc(100deg - attr(s type(<number>)) * 100deg) 100% 25%);
  color:#FFF;
  white-space:pre;
  line-height:1;
  padding:4px;
  border-radius:8px;
  font-weight: 600;
  position:absolute;
  user-select:none;
  top:50%;
  translate: calc(-100% - 16px) -50%;
  text-align:right;
  @media (width < 1111px) {
    position: static;
    margin-right: 4px;
    padding: 3px;
    font-size: 0.8em;
  }
} }

art-frame p-s::after {
    position: static;
    margin-right: 4px;
    padding: 3px;
    font-size: 0.8em;
}
p:has(>p-s) {
  @media (width >= 1111px) {
  border-left: 4px solid #451735;
  padding-left: 4px;
  translate: -8px 0;
  position: relative;
  }
}
/*p-s { &::after { content: ""; background: #F00; position: absolute; height: 1lh; width: 40px; translate: -50px 0; } }*/
  }
</style>

<DIV><art-frame id=ukrainian style="margin-top:1em">
  <style>/* TODO */
    @scope {
      & {
      interpolate-size: allow-keywords;
      transition: height 1s;
      overflow: clip;
      @starting-style {
          height: 0;
      }
      padding: 8px;
      h1,h2 {
        margin: 0;
        font-family: sans-serif;
        color: #000;
        line-height: 1;
      }
      h2 {
        font-weight: normal;
        font-size: 1.2em;
      }
      ua-flag {
        display: inline-block;
        width: 30px;
        height: 20px;
        background: linear-gradient(#0057B7 50%, #FFD700 50%);
        margin: 2px 6px 2px 2px;
      }
      main {
        display: flex;
        flex-wrap: wrap;
        gap: 8px 8px;
        /*justify-content: space-between;*/
      }
      .store-item {
        /*width: 200px;*/
        padding: 8px;
        border: 1px solid grey;
        border-radius: 4px;
        h1 {
          font-size: 1.5em;
        }
        & > div {
          width: 200px;
          height: 200px;
        }
        label {
          font-family: sans-serif;
          display: block;
          width: 200px;
          background: #E9F;
          color: #000;
          text-align: center;
          border-radius: 64px;
          padding: 4px 12px;
          box-sizing: border-box;
          margin-top: 8px;
          border: 1px solid #D8E;
          font-weight: 500;
          cursor: pointer;
          user-select: none;
          &:hover {
            background: #FAF;
          }
          &:active {
            background: #C7C;
          }
          input {
            opacity: 0;
            position: absolute;
            pointer-events: none;
          }
        }
      }
      .store-item2 {
        width: 100%;
        padding: 8px;
        border: 1px solid grey;
        border-radius: 4px;
        display: flex;
        gap: 8px;
          font-family: sans-serif;
        h1 {
          font-size: 1.5em;
          font-weight: 500;
        }
        /*min-height: 300px;*/
        p {
          margin: 0;
        }
        label {
          font-family: sans-serif;
          display: block;
          width: 200px;
          background: #E9F;
          color: #000;
          text-align: center;
          border-radius: 64px;
          padding: 4px 12px;
          box-sizing: border-box;
          margin-top: 8px;
          border: 1px solid #D8E;
          font-weight: 500;
          cursor: pointer;
          user-select: none;
          &:hover {
            background: #FAF;
          }
          &:active {
            background: #C7C;
          }
          input {
            opacity: 0;
            position: absolute;
            pointer-events: none;
          }
        }
      }
      .store-item3 {
        display: none;
           width: 100%;
        padding: 8px;
        border: 1px solid grey;
        border-radius: 4px;
        gap: 8px;
          font-family: sans-serif;
          p {
            margin:0;
          }
          min-height: 200px;
      }
      }
    }
  </style>
  <article>
  <h1><ua-flag></ua-flag>Hello this is the Ukrainian pharmaceutical market!</h1>
  <h2>This market has been opened to you by the <censor-ed style="font-family:serif">Dog-Women</censor-ed> consulting company!</h2>
  <p>So what would u like to order?</p>
  <main>
    <article class="store-item2"><div style="border:1px solid;padding: 20px;height: 212px;">
      <div style="border-radius:100%; zoom:1.25;rotate:-7deg;translate: 0 30px; width:170px;height:100px;box-sizing: border-box;overflow:clip;corner-shape: superellipse(0.85);position:relative">
        <div style="background:#61B9A7; border-radius:100%; width:170px;height:100px;box-sizing: border-box; border: 12px inset #76C9C2;filter:blur(8px);outline:10px solid #6E72A1"></div>
        <!-- <p style="position:absolute;top:50%;left:50%;margin:0;translate: -50% -50%;color:#32576988;font-size:48px;text-shadow: 1px 1px #b0dde188;">b</p> -->
        <div style="translate: 0px -44px;filter:drop-shadow(1px 1px #b0dde188);">
        <div style="position:absolute;top:50%;left:50%;margin:0;translate: -50% calc(-50% - 10px);outline: #32576988 solid 4px;width:20px;height:30px;border-radius: 12px;corner-shape: bevel;scale: 1 0.75"></div>
        <div style="position:absolute;top:50%;left:50%;margin:0;translate: calc(-50% - 12px) calc(-100% - 6px + 12px + 20px - 10px);width:4px;background:#32576988;height:20px"></div>
        </div>
      </div>
    </div>
    <div style="flex:1">
    <h1>Perspectrogen 2mg</h1>
    <p>star ratings</p>
    <p style="background:darkred;color:#FFF;width:fit-content;padding:8px;border-radius: 4px;font-weight:600;font-size: 0.8em;">Limited time deal</p>
    <p style="font-weight: 400;font-size:2em;color:darkred;"><span style="color:darkred;width:fit-content;border-radius: 4px;font-weight:400;font-size: 0.6em;margin-right: 4px;">-50%</span>349<span style="font-size:0.5em;font-weight: normal;">KARMA</span></p>
    <p style="font-weight: 400;font-size:1em;color:grey;text-decoration:line-through;">699 KARMA</p>
    <p style="font-size: 1.1em;margin-top:8px;font-weight:bold;">About this item</p>
    <p>With this item you can see the Perspective scores of <em>absolutely everything</em>!</p>
    </div>
    <div style="border: 1px solid #DDD; border-radius: 8px; padding: 8px;display:flex;flex-direction: column;height: fit-content;">
      <p style="font-weight: bold;">Buy New</p>
      <p style="font-weight: bold;font-size:2em;">349<span style="font-size:0.5em;font-weight: normal;">KARMA</span></p>
      <br>
      <p style="font-size: 1.5; color: green">In stock</p>
      <label>Buy now<input type=checkbox id="perspectrogen"></label>
      <p style="font-size: 0.5em;margin-top: 4px;color:grey">No refunds after purchase.</p>
    </div>
  </article>
  <article class="store-item3">
    <h1>Thank you for your purchase!</h1>
    <p>No refunds.</p>
  </article>
    <!-- <article class="store-item"><div></div><h1>Reddit gold</h1></article> -->
    <!-- <article class="store-item"><div></div><h1>Epic</h1></article> -->
  </main>
  <p style="margin:0"><small>Legal note: This is a joke, no pharmaceuticals can actually be ordered from this blog post about Reddit spam filters.</small></p>
  </article>
</art-frame></DIV>

<p-s s="0.06858262"></p-s>And some more general rules-based filters, such as this one for account age.

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: spamurai (comment from account under 30 minutes matching spam conditions)</spam-reason> • <comment-user data-censor>NewUser67</comment-user> • 1 points • 23 min</comment-head>
      <p>fuck you fuck you fuck you</p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.2713012"></p-s>But alright, let's try to figure out what's going on with the infodump <spam-text>removals</spam-text> like the one I put in the banner art of this post.

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>AnywhereAlone6851</comment-user> in <comment-user>Pony_irl</comment-user></post-head>
    <h1>18 Random Facts That Will Blo</h1>
    <comment-head><spam-reason>Removed: spamurai (*Removing potential spam content from unproved user*:
<!---->
 link `t3_phc4xx` (0.12571795 perspective spam) by u/AnywhereAlone6851 (2.948587962963 days old, spammy: 4.5, hosted: false, 28 karma, 5 reports, org: `Skyinfo Online`, email: gmail.com) in r/Pony_irl (guest) posting pinterest.com from `oauth.reddit.com` via `nil` from UA: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36, RHS: oc:ac:kT:lw:bV:aX:af:a6:l5:y3:aT:m9:pt:f3:hZ:az:aR:aQ, LANG: en-US,en,q=0.9, TLS: SwxwvfHLtTxt/9qbo1dvBLEMSIQ=tT1LosI8/xDmUS7LMVuhb/olIJQ= - referrer: https://www.reddit.com/, thumbnail: `https://b.thumbs.redditmedia.com/K_Q91r66a3AEopEbzGkjkxHOpisoQbxa3hIoHxDerjc.jpg` -
<!---->
```18 Random Facts That Will Blo ```
<!---->
https://www.reddit.com/r/Pony_irl/comments/phc4xx/18_random_facts_that_will_blo/ )</spam-reason> • 0 Comments • pinterest.com • 1 month</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.38923663"></p-s>That is a lot of information in there! Let's break it down bit by bit:

<p-s s="0.12361179"></p-s><spam-text>link t3_phc4xx</spam-text>: this is the ["fullname"](https://old.reddit.com/dev/api/#fullnames) ID of the post, it's what shows up in urls except it is prefixed: **t1** is comment, **t2** is user, **t3** is post, **t4** is private message, and **t5** is subreddit.

<p-s s="0.7955809"></p-s><spam-text>0.12571795 perspective spam</spam-text>: this is almost certainly using the **[Perspective API](https://perspectiveapi.com/)**. Perspective is a free[^perspectivefree] Google[^googleservice] service that uses machine learning to "reduce toxicity online".

<p-s s="0.52064466"></p-s>I'm sure of this because *perspective* is a pretty unique word, the [Perspective docs](https://developers.perspectiveapi.com/s/docs-sample-requests) display sample results with similar score numbers (e.g. 0.24173126 and 0.4445836), and [Perspective's case studies page](https://web.archive.org/web/20220126010922/https://www.perspectiveapi.com/case-studies/) contains this quote from the CTO of Reddit:

<DIV><art-frame>
<style>
  @scope { & {
    background: #F4EFF2;
    color: #000;
    padding: 8px;
    font-family: JigsawSans-Regular, Roboto, Arial, Helvetica, sans-serif;
    font-size: 1.1em;
    line-height: 1.5em;
/*    font-weight: 300;*/
    font-feature-settings: 'ss01' on, 'liga' off;
    text-align: center;
    text-wrap: balance;
    p {
      margin: 0;
    }
  } }
</style>
<p style="font-style: italic;margin-bottom: 0.5em"><p-s s="0.93607247"></p-s>“As Reddit scales, the integrity of our platform and ensuring healthy discourse among users and communities remains a priority. Perspective has been a valuable tool as we continue to strengthen the safety measures and tooling that we have in place.”</p>
<p>—Chris Slowe, Chief Technology Officer at Reddit</p>
</art-frame></DIV>

<p-s s="0.68879956"></p-s>It seems like Reddit is using [Perspective's "experimental" SPAM](https://developers.perspectiveapi.com/s/about-the-api-attributes-and-languages) attribute here though, which is intended to detect spam instead of toxicity. The data for this is trained on a SINGLE DATASET of the comments and moderation in the New York Times, which I find pretty interesting.<bpm-emote aria-hidden=true right>\[](/liera)<span style="position: absolute;translate: -60px 0">\[](/txt! \"i dont know anything about this\")</span></bpm-emote>

<p-s s="0.48633048"></p-s>Unfortunately, since February 2026, we can no longer create a new Perspective API project on Google Cloud, so it is not possible to try it out anymore.

<p-s s="0.07958816"></p-s>Well, that is unless we can find some leaked API keys :3. Which I may or may not have teehee..

<style>
.epicCircle, .epicCircle2 {
  position: relative;
  &::after {
    content: "";
    pointer-events: none;
    position: absolute;
    outline: 4px solid red;
    border-radius: 100%;
    inset: -10px -20px;
    filter: drop-shadow(1px 1px 12px #0008);
  }
}
.epicCircle2::after {
  inset: -5px -5px;
  outline: 3px solid red;
}
.epicArrow {
  position: relative;
  &::before {
    content: "";
    pointer-events: none;
    position: absolute;
    background: red;
    top:100%;
    left:100%;
    mask: linear-gradient(135deg, #000 50%, #0000 50%);
    width: 24px;
    height: 24px;
    rotate: 19deg;
    translate: -26px 8px;
    /*filter: drop-shadow(1px 1px 12px #0008);*/
  }
  &::after {
    content: "";
    pointer-events: none;
    position: absolute;
    background: red;
    top:100%;
    left:100%;
    width: 6px;
    height: 120px;
    rotate: calc(19deg - 45deg);
    translate: 6.5px 8px;
    /*filter: drop-shadow(1px 1px 12px #0008);*/
  }
}
</style>

<pre class="sx-block"><code><sx-c>$</sx-c> curl <sx-s>'https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=AIza<censor-ed>c29ycnkgdGhpcyBpcyBjZW5zb3JlZCBsb2w</censor-ed>'</sx-s> \
    <sx-p>--request</sx-p> <sx-t>POST</sx-t> \
    <sx-p>--header</sx-p> <sx-s>"Content-Type: application/json"</sx-s> \
    <sx-p>--data</sx-p> <sx-e>'{
              <sx-l>"comment"</sx-l>: {
                <sx-l>"text"</sx-l>:<sx-s class="epicArrow">"18 Random Facts That Will Blo "</sx-s>
              },
              <sx-l>"requested_attributes"</sx-l>: {
                <sx-l>"SPAM"</sx-l>: {<sx-l>"score_type"</sx-l>: <sx-s>"PROBABILITY"</sx-s>}
              }
            }'</sx-e>
{
  <sx-l>"attributeScores"</sx-l>: {
    <sx-l>"SPAM"</sx-l>: {
      <sx-l>"spanScores"</sx-l>: [
        {
          <sx-l>"begin"</sx-l>: <sx-n>0</sx-n>,
          <sx-l>"end"</sx-l>: <sx-n>30</sx-n>,
          <sx-l>"score"</sx-l>: {
            <sx-l>"value"</sx-l>: <sx-n>0.12571794</sx-n>,
            <sx-l>"type"</sx-l>: <sx-s>"PROBABILITY"</sx-s>
          }
        }
      ],
      <sx-l>"summaryScore"</sx-l>: {
        <sx-l>"value"</sx-l>: <sx-n class="epicCircle">0.12571794</sx-n>,
        <sx-l>"type"</sx-l>: <sx-s>"PROBABILITY"</sx-s>
      }
    }
  },
  <sx-l>"languages"</sx-l>: [
    <sx-s>"en"</sx-s>
  ],
  <sx-l>"detectedLanguages"</sx-l>: [
    <sx-s>"en"</sx-s>
  ]
}</code></pre>

<p-s s="0.5043182"></p-s>..and thus, we can be 100% sure that this is the API Reddit used, because we get back the same[^same] <spam-text>0.12571795</spam-text> as we saw in spamurai earlier.

<p-s s="0.8253275"></p-s>This is interesting because it means that this entire time it was possible for a bad actor to bypass one of the primary spamurai criterias by just changing their message until it's non-spammy for Perspective's free API.

<p-s s="0.3584468"></p-s>It's not even hard to do so, as SPAM score is extremely sensitive to changes of just a few characters:

<pre class="sx-block"><code><sx-c>$</sx-c> <sx-e>query</sx-e>=<sx-s>'Puppygirl Consulting is the best way to grow your revenue'</sx-s>
<sx-c>$</sx-c> ./perspective.sh <sx-s>"<sx-e>$query</sx-e>"</sx-s>
<sx-n>0.8638981</sx-n>: <sx-l>Puppygirl Consulting is the best way to grow your revenue</sx-l>
<sx-c>$</sx-c> <sx-k>for</sx-k> <sx-e>letters</sx-e> <sx-k>in</sx-k> <sx-a>{a..z}{a..z}</sx-a>
    <sx-k>do</sx-k> ./perspective.sh <sx-s>"<sx-e>$query $letters</sx-e>"</sx-s> | grep <sx-s>"0.0"</sx-s>
  <sx-k>done</sx-k>
<sx-n>0.010811162</sx-n>: <sx-l>Puppygirl Consulting is the best way to grow your revenue qp</sx-l></code></pre>

<p-s s="0.08478037"></p-s><bpm-emote aria-hidden=true left style="margin-bottom:-40px;translate: 0 -20px">\[](/lyrafacehoof)</bpm-emote>You can see how going through all 2-letter combinations got us from a 86% spam score down to 1%, which is significantly less than pretty much any normal text.

<p-s s="0.11808781"></p-s>It also ignores numbers and case for some reason:

<pre class="sx-block"><code><sx-c>$</sx-c> ./perspective.sh <sx-s>'Hi there, please call my work phone at 567890'</sx-s>
<sx-n>0.81438655</sx-n>: <sx-l>Hi there, please call my work phone at 567890</sx-l>
<sx-c>$</sx-c> ./perspective.sh <sx-s>'hi THEre, pleaSE Call my woRk phonE aT 022102'</sx-s>
<sx-n>0.81438655</sx-n>: <sx-l>hi THEre, pleaSE Call my woRk phonE aT 022102</sx-l></code></pre>


<p-s s="0.122776054"></p-s>As well as alternate alphabets:

<pre class="sx-block"><code><sx-c>$</sx-c> ./perspective.sh <sx-s>'привет'</sx-s>
<sx-n>0.35077864</sx-n>: <sx-l>привет</sx-l>
<sx-c>$</sx-c> ./perspective.sh <sx-s>'наххуи'</sx-s>
<sx-n>0.35077864</sx-n>: <sx-l>наххуи</sx-l></code></pre>

<p-s s="0.6208211"></p-s>Which means you can sometimes lower your spam score just by using cyrillic characters:

<pre class="sx-block"><code><sx-c>$</sx-c> <sx-e>query</sx-e>=<sx-s>'Buy my product'</sx-s>
<sx-c>$</sx-c> ./perspective.sh <sx-s>"<sx-e>$query</sx-e>"</sx-s>
<sx-n>0.6473346</sx-n>: <sx-l>Buy my product</sx-l>
<sx-c>$</sx-c> ./perspective.sh <sx-s>"</sx-s><sx-t>$(</sx-t>echo <sx-p>-n</sx-p> <sx-e>$query</sx-e> | sed <sx-p>s/p/р/</sx-p><sx-t>)</sx-t><sx-s>"</sx-s>
<sx-n>0.4452748</sx-n>: <sx-l>Buy my рroduct</sx-l></code></pre>

<p-s s="0.05824822"></p-s>Anyways, moving on...

<p-s s="0.6837946"></p-s><spam-text>by u/AnywhereAlone6851</spam-text>: username, self-explanatory<bpm-emote aria-hidden=true right>\[](/lyragimme)</bpm-emote>

<p-s s="0.009336848"></p-s><spam-text>2.948587962963 days old</spam-text>: account age as days, which is a pretty good indicator of spam accounts and ban evaders. But it does give us one interesting detail - I believe the account age is represented in seconds, because all the examples I have come out to a round number when multiplied by 86400 (amount of seconds per day).

<p-s s="0.061491933"></p-s><spam-text>spammy: 4.5</spam-text>: not sure what this is, could be the *Minsky* thing from earlier? Or the spammit score from earlier? Or a combination of multiple spamurai rules?

<p-s s="0.23310374"></p-s><spam-text>hosted: false</spam-text>: not sure, maybe to detect known hosting provider ip ranges?

<p-s s="0.04786274"></p-s><spam-text>28 karma</spam-text>: self-explanatory, karma is often used as a measure of an account's presence

<p-s s="0.38647154"></p-s><spam-text>5 reports</spam-text>: total number of reports an account and its posts have received

<p-s s="0.93607247"></p-s><spam-text>org: Skyinfo Online</spam-text>: the ISP of user. This can tell you where the user is from and whether they're using a VPN. In this case we can see that the spam is coming from Bangladesh, because that's where <a rel="nofollow" href="https://www.skyinfoonline.net/">SkyInfo Online</a> operates from. Their website is incredible.

<p-s s="0.8608853"></p-s><spam-text>email: gmail.com</spam-text>: e-mail domain of the user

<p-s s="0.08532518"></p-s><spam-text>in r/Pony_irl (guest)</spam-text>: the subreddit that the post is in. I believe the (guest) means that the user is not a subscriber of the subreddit. I assume that it would say something like "member", "approved", or "moderator" in other cases, but I don't actually have any examples of that.

<p-s s="0.6307072"></p-s><spam-text>posting pinterest.com</spam-text>: the domain that's being linked to

<p-s s="0.44167584"></p-s><spam-text>from oauth.reddit.com via nil</spam-text>: the user was authenticated with Reddit's oauth flow, which is the default, and I belive the *nil* (Lua's *null*) is where the name of a custom client would go, e.g. Relay in my case. I don't have any examples of this being anything other than *nil*, so this is just speculation.

<p-s s="0.5057613"></p-s><spam-text>from UA: Mozilla/5.0 (Win...</spam-text>: this is the user agent string of the browser that's being used. It tells us that the person is posting from the *Chrome* browser on *Windows 8.1*.

<p-s s="0.5112866"></p-s><spam-text>RHS: oc:ac:kT:lw:bV:aX...</spam-text>: this seems to be some sort of a fingerprinting hash Reddit uses. I believe this is Reddit's own engineering and not an existing open-source solution. This hash is the exact same between this Chrome 93 example, and the Edge 95 example from the beginning. This leads me to conclude that the hash fingerprints browsers (Edge and Chrome are both Chromium) and is meant to detect scripts pretending to be a browser.

<p-s s="0.18831055"></p-s><spam-text>LANG: en-US,en,q=0.9</spam-text>: the value of the *accept-language* header, it tells websites what languages you'd like to see websites in. This can be used to detect potential VPN usage, e.g. if someone has Latvian as their language but is joining from a New York IP.

<p-s s="0.43745738"></p-s><spam-text>TLS: SwxwvfHLtTxt/9qbo...</spam-text>: this is TLS fingerprinting similar to [JA3](https://github.com/salesforce/ja3). It seems to be Reddit's own engineering though, not an existing implementation.

<p-s s="0.8960908"></p-s><spam-text>referrer: https:\//www.reddit.com/</spam-text>: this is the page the user got onto Reddit from. Sometimes when opening Reddit links directly from other sites, your votes are not counted to discourage brigading, and this is what the referer is used for. In the case of spamurai it might be useful if the referer is something like *buy-reddit-comments.info* (or more realistically, a platform such as Fiverr).

<p-s s="0.77115434"></p-s><spam-text>thumbnail: https://...</spam-text>: the auto-generated thumbnail 

<p-s s="0.67741"></p-s><spam-text>- \`\`\`18 Random Facts That Will Blo \`\`\`</spam-text>: the markdown body of the post/comment

<p-s s="0.40902883"></p-s><spam-text>https:\//www.reddit.com/r/Pony_irl...</spam-text>: link to the post/comment

<p-s s="0.2609426"></p-s>So that's the full spamurai infodump with no clear reason for <spam-txet>removal</spam-txet>. There are also examples of spamurai clearly using the same data but with specific rules, such as the use of the spammy score here:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: spamurai (URL-only comment from account with high spammy score)</spam-reason> • <comment-user data-censor>GoodBoyBacon</comment-user> • 0 points • 24 min</comment-head>
      <p><fake-link>https://www.reddit.com/r/<censor-ed>ReallyBadGuys</censor-ed>/comments/<censor-ed>qw3rt1</censor-ed>/<censor-ed>if_ur_a_bad_guy_post_here_please</censor-ed>/</fake-link></p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.11762398"></p-s>Or the use of the perspective score here:

<DIV><art-frame style="height:fit-content;mask: linear-gradient(#000 50%, #FFF0);border-bottom-left-radius:0;border-bottom-right-radius:0;position:relative;overflow:visible" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: spamurai (REPORT: High spam perspective score on comment with hyperlink reported for spam. Removed but can be re-approved by mod.)</spam-reason> • <comment-user>BrattyErmine12</comment-user> • 0 points • 11 months</comment-head>
      <p><strong>Coins are a virtual good you can use to award exemplary posts or comments. Support Reddit and encourage your favorite contributors to keep making Reddit better.</strong></p>
      <br><p><strong>GET COINS</strong></p>
      <br><h2 style="font-family:inherit;color:inherit">Here’s what you can buy with coins</h2>
      <br><p><strong>Spend your coins on these Awards reserved exclusively for the finest Reddit contributors. Awarding a post or comment highlights it for all to see, and some Awards also grant the honoree special bonuses.</strong></p>
      <br><p>📷</p>
      <h3>Silver Award</h3><p>Shows a Silver Award on the post or comment and ... that’s it. You’ll need 100 Coins.</p>
    </relay-comment>
  </relay-thread>
  <div style="position:absolute;pointer-events:none;inset:100px 0 0 0;backdrop-filter:blur(0.5px);mask-image:linear-gradient(#0000, #FFF 12.5%);"></div>
  <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(1px);mask-image:linear-gradient(#0000, #FFF 25%);"></div>
    <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(1.5px);mask-image:linear-gradient(#0000, #FFF 37.5%);"></div>
    <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 50%);"></div>
    <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(3px);mask-image:linear-gradient(#0000, #FFF 62.5%);"></div>
    <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 75%);"></div>
    <div style="position:absolute;pointer-events:none;inset:120px 0 0 0;backdrop-filter:blur(8px);mask-image:linear-gradient(#0000, #FFF 100%);"></div>
</art-frame></DIV>
<style>
  .blurover {
    position:absolute;
    z-index:1;
    pointer-events:none;
    left: 0;
    @media (width > 900px) {
      width:868px;
      transform: translateX(calc(50vw - 50%));
    }
    @media (width <= 900px) {
      right: 0;
    }
  }
  @-moz-document url-prefix() {
    .blurover { background: #8CFFDB }
  }
  /*@supports (font: -apple-system-body) and (-webkit-appearance: none) {*/
    /*.blurover { background: #8CFFDB }*/
  /*}*/
</style>
<div class=blurover style="height:140px;translate: 0 -6lh;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 50%)"></div>
<div class=blurover style="height:80px;translate: 0 -4lh;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 70%)"></div>
<div class=blurover style="height:110px;translate: 0 -4lh;backdrop-filter:blur(8px);mask-image:linear-gradient(#0000, #FFF 70%)"></div>

<style>
  #supsupsoup {
    sup::before { content:'['; }
    sup::after { content:']'; }
    .footnote-ref {
      font-size: 0;
      &:hover {
        text-decoration: underline;
      }
      &::before { content:"why?"; font-size: 0.833333rem; font-style:italic; }
    }
  }
</style>
<span><p style="margin-top: -3lh;z-index:2;position:relative" id="supsupsoup"><p-s s="0.13198236"></p-s>The perspective spam score for the above post is either 0.9761621 or 0.9782609[^whyy]. Also what's interesting is that the specific rule there got triggered by someone reporting it for spam - thus we learn that sometimes user reports have an effect even without moderator intervention.</p></span>

<p-s s="0.3581675"></p-s>It's also interesting how some of the <spam-text>removals</spam-text> adjust based on mod actions:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>muyuwobsoq9q</comment-user> in <comment-user>Pony_irl</comment-user></post-head>
    <h1>영어 배우기! 알파벳송 인기- تعليم الاطفال مع - العاب أطفالأغاني الحضانة وأغنية الأط...</h1>
    <comment-head><spam-reason>Removed: spamurai (High karma-to-spam ratio on link content from 6+ spammy score account; mod approval of this content will reduce future removals)</spam-reason> • 1 Comments • youtube.com • 2 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>
<br>

## misc

<p-s s="0.033368606"></p-s>There's also a bunch of <spam-txet>removals</spam-txet> that don't really neatly fit into any of the above categories.

<p-s s="0.2300504"></p-s>For example, <spam-text>Pinterest</spam-text> redirect links get <spam-txet>removed</spam-txet>:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: pinterest redirect</spam-reason> • <comment-user>22_ghost_22</comment-user> • 1 points • 4 months</comment-head>
      <p><fake-link>https://pin.it/<censor-ed>Sc4mUr1</censor-ed></fake-link></p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.8606568"></p-s>As do <spam-text>mega.nz</spam-text> links:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: streamer spam</spam-reason> • <comment-user data-censor>EPIC_Gamer67</comment-user> • 1 points • 11 months</comment-head>
      <p><fake-link>https://mega.nz/folder/<censor-ed>Ep1cV1d30s</censor-ed></fake-link></p>
      <br>
      <p>The decryption key is</p>
      <br>
      <p>SW52YWxpZCBiYXNlNjQgc3RyaW5n</p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.30696046"></p-s>In the case of the comment above, it was actually a legitimate link to some archived YouTube videos, so it was falsefully <spam-text>removed</spam-text>.

<p-s s="0.6962727"></p-s>Another banned kind of link is a freely available subdomain:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>cpsryan</comment-user> in <comment-user>UnusAnnusArchival</comment-user></post-head>
    <h1>All of the Sauce for Unus Annus Archives</h1>
    <comment-head><spam-reason>Removed: freely available subdomains</spam-reason> • <span style="color:#8F5C5B">(Unus Annus Archiving)</span> • 0 Comments • self.UnusAnnusArchival • 11 months</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.36276242"></p-s>In the above case the post didn't contain those kinds of links per se, but it did contain a magnet link that reddit found and linkified the *2ftracker.opentrackr.org*[^2f] inside of. I'm not sure why opentrackr gets matched under "<spam-text>freely available subdomains</spam-text>" though.

<p-s s="0.17419557"></p-s>But speaking of trackers, certain strings are straight up regex banned:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>e4e5x0q8e1p</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1><censor-ed>레인보우 대시 프레젠츠</censor-ed> 26화 토렌.트 150927 26화 torrent HD 고화질 FULL <censor-ed>레인보우 대시가 선사하는</censor-ed> 26회 토렌.트 150927 26화 다시보기</h1>
    <comment-head><spam-reason>Removed: Matched forbidden regex u'torenteu'</spam-reason> • 2 Comments • self.MyLittleOutOfContext • 10 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.12750871"></p-s>Now, this one is super interesting to me because nowhere in the post does the string <spam-text>torenteu</spam-text> appear, yet we still somehow match our regex?

<p-s s="0.9590444"></p-s>The reason this happens is because [Reddit uses the unidecode library](https://github.com/reddit-archive/reddit/blob/753b17407e9a9dca09558526805922de24133d53/r2/r2/lib/utils/utils.py#L1261-L1264)[^unidecode] to convert post titles into ascii:

<pre class="sx-block"><code><sx-c>$</sx-c> python2
<sx-e>Python 2.7.18 (default, Dec  9 2024, 19:35:20)
[GCC 9.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.</sx-e>
>>> <sx-k>import</sx-k> unidecode
>>> <sx-e>unidecode</sx-e>.<sx-p>unidecode</sx-p>(<sx-s>u"<censor-ed>레인보우 대시 프레젠츠</censor-ed> 26화 토렌.트 150927 26화 torrent HD 고화질"</sx-s>)
<sx-s>'<censor-ed>reinbou daesi peurejenceu</censor-ed> 26hwa toren.teu 150927 26hwa torrent HD gohwajil'</sx-s>
>>></code></pre>

<p-s s="0.0118478825"></p-s>It then [processes the string a bit more]() and arrives at *"<span style="line-break:anywhere"><censor-ed style="line-break:anywhere">reinbou_daesi_peurejenceu</censor-ed>_26hwa\_<spam-text>torenteu</spam-text>\_150927</span>"*, which does match the <spam-text>u'torenteu'</spam-text> regex.

<p-s s="0.72949606"></p-s>I was curious as to whether this filter still exists, so I made some test posts on a subreddit I moderate using an alt account:

<style>
  .reddit {
    header {
      label {
        margin: 0px 3px;
        padding: 2px 6px 0 6px;
        font-weight: bold;
        color: #369;
        background: #EFF7FF;
        cursor: pointer;
        &:has(input:focus-visible) {
          outline: 2px solid #000;
          border-radius: 2px;
          outline-offset: -1px;
        }
        input {
          opacity: 0;
          position: absolute;
          pointer-events: none;
        }
        &:has(input:checked) {
          background: #FFF;
          color: orangered;
          border: 1px solid #5f99cf;
          border-bottom: 1px solid white;
          translate: 0 1px;
        }
      }
    }
    main {
      .linklisting {
        * {
          margin: 0;
          padding: 0;
        }
        & > .link {
          display: block;
          width: calc(100% - 3px);
          &, & > * {
            float: left;
          }
          &.spam {
            background-color: #fa8072;
          }
          margin-bottom: 8px;
          padding-left: 3px;
          .thumbnail {
            width: 50px;
            height: 50px;
            position: relative;
            background: #CCCCC7;
            border-radius: 100%;
            margin: 0 15px 2px 10px;
            &::before {
              content: "";
              position: absolute;
              background: linear-gradient(90deg, #0000 50%, #FFF 50%), linear-gradient(90deg, #FFF 4px, #0000 4px, #0000 22px, #FFF 22px), linear-gradient(#0000 4.5px, #CCCCC7 4.5px, #CCCCC7 5.5px, #0000 7px, #CCCCC7 9.5px, #0000 11.5px, #CCCCC7 12.5px, #CCCCC7 13.5px, #0000 14.5px, #CCCCC7 16.5px, #0000 18.5px), #FBFBFA;
              background-repeat: no-repeat,no-repeat,no-repeat,no-repeat;
              background-position: 0 14px, 0 0, 0 0, 0 0;
              inset: 14px 12px;
              border-radius: 4px;
            }
            &::after {
              content: "";
              inset: 34px 23px 12px;
              position: absolute;
              background: #FFF;
              rotate: 45deg;
            }
          }
          &:not(:has(.expando-check:checked)) .expando {
            display: none;
          }
          .expando {
            display: block;
            clear: left;
            margin: 5px;
            position: relative;
            background-color: #fafafa;
            border: 1px solid #369;
            border-radius: 7px;
            padding: 5px 10px;
            font-size: 14px;
          }
          .expando-button {
            float: left;
            position: relative;
            --bg: #CCCCC9;
            &:has(:focus-visible), &:hover, &:active {
              --bg: #466599;
            }
            cursor: pointer;
            border-radius: 2px;
            background: var(--bg);
            height: 23px;
            width: 23px;
            margin: 2px 5px 2px 0;
            input {
              opacity: 0;
              position: absolute;
              pointer-events: none;
            }
            &:has(:focus-visible) {
              outline: 2px solid #000;
            }
            &:not(:has(:checked)) {
              &::before {
                content: "";
                position: absolute;
                inset: 6px 4px 5px;
                background: linear-gradient(#0000, #FFF 1px, #FFF 2px, #0000 3px, #FFF 5px, #FFF 6px, #0000 7px, #0000 8px, #FFF 8px, #FFF 10px, #0000 11px), linear-gradient(#0000, #FFF 1px, #FFF 2px, #0000 3px, #FFF 6px, #0000 8px, #0000 8px, #FFF 8px, #FFF 10px, #0000 11px), #0000;
                background-repeat: no-repeat, no-repeat;
                background-size: 50% 100%, 100% 60%;
                background-position: 0 8px, 0 0;
              }
              &::after {
                color: #FFF;
                content: "+";
                position: absolute;
                bottom: 0;
                right: 1px;
                font-size: 8px;
              }
            }
            &:has(:checked) {
              border-radius: 100%;
              &::before, &::after {
                content: "";
                position: absolute;
                inset: 2px 9px;
                background: #FFF;
                border-radius: 10px;
                rotate: -45deg;
                scale: 0.75;
              }
              &::after {
                rotate: 45deg;
              }
            }
          }
          .clearleft {
            clear: left;
          }
          .votebuttons {
            margin: 0 7px;
            display: flex;
            flex-direction: column;
            min-height: 50px;
            justify-content: space-between;
            justify-content: space-between;
            align-items: center;
            .score {
              &::after {
                content: "•";
                text-align: center;
                color: #c6c6c6;
                font-weight: bold;
                font-size: small;
              }
            }
            .upvote, .downvote {
              display: block;
              mask: linear-gradient(#000 40%, #0008);
              padding:2px;
              translate: 0.5px 0;
              &::before {
                content: "";
                display: block;
                width: 12px;
                height: 12px;
                background: #B7B7B7;
                rotate: 45deg;
                mask: linear-gradient(-45deg, #0000 50%, #000 50%);
                /*outline: 1px solid #D3D3D388;*/
                outline-offset: -2px;
              }
              &::after {
                content: "";
                display: block;
                width: 3px;
                border-left: 1px solid #D3D3D3;
                border-right: 1px solid #D3D3D3;
                border-bottom: 1px solid #D3D3D3;
                height: 6px;
                margin-left: 3px;
                margin-top: -6px;
                translate: 0.5px 0;
                background: #B7B7B7;
              }
            }
            .downvote {
              rotate: 180deg;
            }
          }
          &.spam .votebuttons { .upvote, .downvote { &::after {
                border-left: 1px solid #DAA;
                border-right: 1px solid #DAA;
                border-bottom: 1px solid #DAA;
          } } }
          .tagline {
            color: #888;
            font-size: x-small;
            white-space: nowrap;
          }
          a {
            color: #369;
            cursor: pointer;
            &:not(.title):hover {
              text-decoration: underline;
            }
          }
          .title {
            font-size: medium;
            font-weight: normal;
            margin-bottom: 1px;
            white-space: nowrap;
          }
          .domain {
            color: #888;
            font-size: x-small;
            a {
              color: inherit;
              vertical-align: middle;
            }
          }
          a.title {
            color: #00F;
            margin-right: .4em;
          }
          ul {
            display: inline-block;
            list-style-type: none;
            margin: 0;
            padding: 1px 0;
            li {
              display: inline-block;
              border: none;
              padding-right: 4px;
              line-height: 1.6em;
              white-space: nowrap;
              a {
                color: #888;
                font-weight: bold;
                padding: 0 1px;
              }
            }
          }
          .big-mod-buttons {
            user-select: none;
            margin-right: 4px;
            form {
              display: inline;
            }
            & > form > * {
              display: inline-block;
              color: black;
              border: 1px solid #666;
              padding: 1px 6px;
              font-size: 10px;
              border-radius: 3px;
              margin-left: 5px;
              margin-bottom: 5px;
              cursor: pointer;
              background: linear-gradient(#D5D5D5 75%, #CACACA);
              &.negative {
                background: linear-gradient(#EDBDBE 75%, #D1B1B2);
              }
              &.positive {
                background: linear-gradient(#D1EAC0 75%, #C9D9BB);
              }
              &:has(input:checked) {
                color: #FFF;
                background: linear-gradient(#4F4F4F 75%, #676767);
                &.negative {
                  background: linear-gradient(#904446 75%, #AB4347);
                }
                &.positive {
                  background: linear-gradient(#4E6F30 75%, #60953A);
                }
              }
              &:has(input:focus-visible) {
                outline: 2px solid #000;
                border-radius: 2px;
                outline-offset: -1px;
              }
              input {
                opacity: 0;
                position: absolute;
                pointer-events: none;
              }
            }
          }
          .save {
            &:has(input:not(:checked)) {
              span { display: none; }
            }
            input {
              opacity: 0;
              position: absolute;
              pointer-events: none;
            }
          }
          @media (width < 540px) {
            .votebuttons, .thumbnail {
              display: none;
            }
          }
        }
      }
    }
  }
</style>
<DIV><art-frame style="min-height: 300px" aria-label="reddit user page, displaying various removed posts" role="figure">
  <article class="reddit">
    <style>
      @scope {
        .noresults {
          display: none;
          color: red;
          font-size: small;
          position: absolute;
          margin: 0;
        }
        &:has(#commentsTab:checked) {
          .linklisting {
            pointer-events: none;
            user-select: none;
            opacity: 0;
          }
          .noresults {
            display: block;
          }
        }
      }
    </style>
    <nav aria-hidden=true>
      <ul>
        <li class="arr">my subreddits</li>
      </ul>
      <ul>
        <li>popular</li>
        <li>all</li>
        <li class="sep">users</li>
        <li>AskReddit</li>
        <li>pics</li>
        <li>funny</li>
        <li>movies</li>
        <li>gaming</li>
        <li>worldnews</li>
        <li>news</li>
        <li>todayilearned</li>
        <li>nottheonion</li>
        <li>explainlikeimfive</li>
        <li>mildlyinteresting</li>
        <li>DIY HRT</li>
      </ul>
    </nav>
    <header role="radiogroup"><h1 class="pagename"><a>popstonia</a></h1> <label selected>overview<input type="radio" name="tab" checked></label> <label>comments<input type="radio" name="tab" id="commentsTab"></label> <label>submitted<input type="radio" name="tab"></label> </header>
    <main>
<div style="font-size: larger;padding: 5px 10px;margin: 5px;border-bottom: 1px dotted gray;" class="filter">sorted by: <select><option selected>new</option>
<option>hot</option>
<option>top</option>
<option>controversial</option>
</select></div>
<p class="noresults">there doesn't seem to be anything here</p>
<div class="linklisting">
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 10 control</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:43:37 2026 UTC" datetime="2026-06-24T14:43:37+00:00">5 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:45:15 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 9 UA-49307539- hi</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:40:41 2026 UTC" datetime="2026-06-24T14:40:41+00:00">8 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 8 UA-12345678- hi</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:40:15 2026 UTC" datetime="2026-06-24T14:40:15+00:00">8 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:41:57 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 7 foo.bareu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:36:21 2026 UTC" datetime="2026-06-24T14:36:21+00:00">12 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:38:02 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 6 toren.teu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:30:58 2026 UTC" datetime="2026-06-24T14:30:58+00:00">18 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:32:39 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 5 tor.exteu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:30:32 2026 UTC" datetime="2026-06-24T14:30:32+00:00">18 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:32:23 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 4 torenteu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:15:55 2026 UTC" datetime="2026-06-24T14:15:55+00:00">33 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 3 torenteu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <label class="expando-button"><input type="checkbox" class="expando-check"></label>
        <p class="tagline">submitted <time title="Wed Jun 24 14:10:58 2026 UTC" datetime="2026-06-24T14:10:58+00:00">38 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li></ul>
      </div>
      <div class="expando"><p>Test torenteu test</p></div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self spam">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 2 tor.enteu</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:09:18 2026 UTC" datetime="2026-06-24T14:09:18+00:00">39 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li><span class="big-mod-buttons"><form><label class="negative">spam<input type="radio" name="mod" class="spam"></label><label class="neutral">remove<input type="radio" name="mod" class="remove"></label><label class="positive">approve<input type="radio" name="mod" class="approve"></label></form></span><li title="removed at Wed Jun 24 14:11:07 2026 UTC"><b>[ removed ]</b></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
  <div class="link self">
    <div class="votebuttons"><span class="upvote"></span><span class="score"></span><span class="downvote"></span>
    </div>
    <a class="thumbnail self"></a>
    <div class="entry unvoted">
      <div class="top-matter">
        <p class="title"><a class="title" rel="nofollow">Test post 1</a> <span class="domain">(<a>self.greentwitterlogos</a>)</span></p>
        <p class="tagline">submitted <time title="Wed Jun 24 14:08:52 2026 UTC" datetime="2026-06-24T14:08:52+00:00">40 minutes ago</time> by <a style="margin-right:0.5em">popstonia</a> to <a>r/greentwitterlogos</a></p>
        <ul><li><a>comment</a></li><li><a>share</a></li><li class="save"><label><a><span>un</span>save</a><input type=checkbox></label></li><li><a>hide</a></li><li><a>report</a></li></ul>
      </div>
    </div>
  </div>
  <div class="clearleft"></div>
</div><div id="wrongCombo" style="color:red" title="0 - spam, 1 - remove, 2 - approve">Incorrect combination :3c</div><spam-rmev><label class="coin-shell"><input type=checkbox id=hell>There is no <spam-text>reason</spam-text> clicking here should do anything, and yet...</label></spam-rmev>
    </main>
  </article>
</art-frame></DIV>

<p-s s="0.15190066"></p-s><bpm-emote aria-hidden=true left>\[](/lyranotimpressed)</bpm-emote>It's hard to say? It seems like the string "<spam-text>torenteu</spam-text>" by itself does not get removed, so I assume the other removals are based on various other kinds of spam heuristics?

<p-s s="0.32080358"></p-s>Something I did find interesting is that *UA-12345678-* got removed, but *UA-49307539-* did not! It's interesting because there used to be a filter for that specific phrase too:

<DIV><art-frame style="height:fit-content;mask: linear-gradient(#000 50%, #FFF0);border-bottom-left-radius:0;border-bottom-right-radius:0; position: relative;overflow:visible">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: Failed inspection: Phrase(s) [u'UA-49307539-']</spam-reason> • <comment-user>c4c3u5o8c7n</comment-user> • 0 points • 11 months</comment-head>
      <p>다시보기 <censor-ed>강아지들</censor-ed> 토렌.트 torrent 토렌 DVD 1080p 720p HD Full HD DVD 1080p MKV</p>
<br>
<p><censor-ed>강아지들</censor-ed> 토렌.트 file</p>
<br>
<p>1080p MKV 다시보기 <censor-ed>강아지들</censor-ed> 토렌.트 토렌.트 토렌 Torrent Comprehensive 720p HD</p>
<br>
<p>Coverage aggregated from sources all 토렌.트 파일 (Torrent) :</p>
<br>
<p>파일 받기 : <fake-link>다시보기 <censor-ed>강아지들</censor-ed> 토렌.트 Torrent</fake-link></p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
<p>.</p>
    </relay-comment>
  </relay-thread>
  <div style="position:absolute;pointer-events:none;inset:100px 0 0 0;backdrop-filter:blur(0.5px);mask-image:linear-gradient(#0000, #FFF 12.5%);"></div>
  <div style="position:absolute;pointer-events:none;inset:320px 0 0 0;backdrop-filter:blur(1px);mask-image:linear-gradient(#0000, #FFF 25%);"></div>
    <div style="position:absolute;pointer-events:none;inset:320px 0 0 0;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 50%);"></div>
    <div style="position:absolute;pointer-events:none;inset:320px 0 0 0;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 75%);"></div>
</art-frame></DIV>
<div class=blurover style="height:140px;translate: 0 -6lh;backdrop-filter:blur(2px);mask-image:linear-gradient(#0000, #FFF 50%)"></div>
<div class=blurover style="height:80px;translate: 0 -4lh;backdrop-filter:blur(4px);mask-image:linear-gradient(#0000, #FFF 70%)"></div>
<div class=blurover style="height:110px;translate: 0 -4lh;backdrop-filter:blur(8px);mask-image:linear-gradient(#0000, #FFF 70%)"></div>
<p style="margin-top: -2lh;z-index:2;position:relative"><p-s s="0.008851731"></p-s>Though, this case is a little more curious than just that. Once again, the removal phrase does not appear in the comment, but this time not even after running the text transformations!</p>

<p style="z-index:2;position:relative"><p-s s="0.36406013"></p-s>The trick here is that the comment contains a link that goes through several redirects and then ends up on some Korean forum. And looking at the source code of said forum:</p>

<!--<DIV><art-frame>
  <style>
    @scope {
      nav {
        height: 53px;
        background: linear-gradient(#FFF 50%, #F6F7F8);
        border-bottom: 1px solid #A1A6AC;
      }
    }
  </style>
  <article>
    <nav></nav>
  </article>
</art-frame></DIV>-->

<pre class="sx-block"><code><sx-t>&lt;script&gt;</sx-t>
  (<sx-k>function</sx-k>(<sx-t>i</sx-t>,<sx-t>s</sx-t>,<sx-t>o</sx-t>,<sx-t>g</sx-t>,<sx-t>r</sx-t>,<sx-t>a</sx-t>,<sx-t>m</sx-t>){<sx-e>i</sx-e>[<sx-s>'GoogleAnalyticsObject'</sx-s>]=<sx-e>r</sx-e>;<sx-e>i</sx-e>[<sx-e>r</sx-e>]=<sx-e>i</sx-e>[<sx-e>r</sx-e>]||<sx-k>function</sx-k>(){
  (<sx-e>i</sx-e>[<sx-e>r</sx-e>].<sx-p>q</sx-p>=<sx-e>i</sx-e>[<sx-e>r</sx-e>].<sx-p>q</sx-p>||[]).<sx-p>push</sx-p>(<sx-e>arguments</sx-e>)},<sx-e>i</sx-e>[<sx-e>r</sx-e>].<sx-p>l</sx-p>=<sx-n>1</sx-n>*<sx-k>new</sx-k> <sx-y>Date</sx-y>();<sx-e>a</sx-e>=<sx-e>s</sx-e>.<sx-p>createElement</sx-p>(<sx-e>o</sx-e>),
  <sx-e>m</sx-e>=<sx-e>s</sx-e>.<sx-p>getElementsByTagName</sx-p>(<sx-e>o</sx-e>)[<sx-n>0</sx-n>];<sx-e>a</sx-e>.<sx-p>async</sx-p>=<sx-n>1</sx-n>;<sx-e>a</sx-e>.<sx-p>src</sx-p>=<sx-e>g</sx-e>;<sx-e>m</sx-e>.<sx-p>parentNode</sx-p>.<sx-p>insertBefore</sx-p>(<sx-e>a</sx-e>,<sx-e>m</sx-e>)
  })(<sx-e>window</sx-e>,<sx-e>document</sx-e>,<sx-s>'script'</sx-s>,<sx-s>'//www.google-anal<span style="font-size:0;user-select:none"> [break] </span>ytics.com/analy<span style="font-size:0;user-select:none"> [break] </span>tics.js'</sx-s>,<sx-s>'ga'</sx-s>);
<!---->
  <sx-e>ga</sx-e>(<sx-s>'create'</sx-s>, <sx-s class="epicCircle2">'UA-49307539-2'</sx-s>, <sx-s>'auto'</sx-s>);
  <sx-e>ga</sx-e>(<sx-s>'send'</sx-s>, <sx-s>'pageview'</sx-s>);
<!---->
<sx-t>&lt;/script&gt;</sx-t></code></pre>

<p-s s="0.28147563"></p-s>Aha! So the "<spam-text>inspection</spam-text>" means that Reddit literally opens the URL, follows redirects, and looks for the pattern on the page. In this case, the pattern matched is a Google Analytics ID, so that if the same spam ring was to change their IP and domain, the spam filter would still catch them.

<p-s s="0.2976659"></p-s>I wanted to try this on my own account, so I put the string **\<pre>UA-49307539-2\</pre>** on a website and posted a link to it on Reddit.

<style>
  #wrongCombo {display:none}
  @property --reddit {
    syntax: "<integer>";
    initial-value: 0;
    inherits: true;
  }
  html:has(.reddit .linklisting > :nth-child(1) input.spam:checked):has(.reddit .linklisting > :nth-child(5) input.approve:checked):has(.reddit .linklisting > :nth-child(7) input.approve:checked):has(.reddit .linklisting > :nth-child(9) input.remove:checked):has(.reddit .linklisting > :nth-child(11) input.spam:checked):has(.reddit .linklisting > :nth-child(17) input.approve:checked) {
    --reddit: 1;
&,body{
background: #FFFFFF;
    max-width: initial;
    margin: 0;
    padding: 0;
    --font-text: verdana, arial, helvetica, sans-serif;
    --font-head: verdana, arial, helvetica, sans-serif;
    #blogTitle {
      font-variant: small-caps;
      color: #000;
    }
    & > header > nav {
      background: #CEE3F8;
      & > ul {
        font-family: inherit;
        font-size: 1em;
        padding-top:20px;
        padding-left:8px;
        li a:not(#blogTitle) {
          font-size: 0.8em;
            padding: 2px 6px 0 6px;
            font-weight: bold;
            color: #369;
            background: #EFF7FF;
            cursor: pointer;
        }
      }
    }
    & > main {
      margin: 0 8px;
      background: #FAFAFA;
      border: 1px solid #336699;
      padding: 16px;
      border-radius: 8px;
      max-width: 60em;
    }
    main > h1, main > h2, main > h2 > a, main > h1 > a {
      color: #000;
    }
    art-frame {
      max-width: 768px;
    }
    .blurover {
      display: none;
    }
    #title, #subMeta  {
      text-align: left;
    }
    .sx-block {
      background: #FFFFFF;
      border: 1px solid #E6E6DE;
      font-family: monospace, monospace;
      * {
        color: #222222!important;
      }
      max-width: fit-content;
    }
    a {
      color: #0079d3;
    }
  }
  }
  html:has(.reddit .linklisting > :nth-child(1) input:checked):has(.reddit .linklisting > :nth-child(5) input:checked):has(.reddit .linklisting > :nth-child(7) input:checked):has(.reddit .linklisting > :nth-child(9) input:checked):has(.reddit .linklisting > :nth-child(11) input:checked):has(.reddit .linklisting > :nth-child(17) input:checked) {
    @container style(--reddit:0) {
      #wrongCombo {display:block}
    }
  }
</style>

<style>
</style>

<DIV><art-frame style="background: #0E1113" aria-label="This account has been banned" role="img">
  <style>
    @scope { &{
    ::selection {
        color: #FFF;
        background: #0041C6CC;
    }
      h1 {
        color: #B7CAD4;
        font-weight: 600;
        margin-top: 1rem;
        line-height: 28px;
        font-size: 28px;
        font-family: inherit;
      }
      div {
        display: inline-block;
        justify-self: center;
        background: #131313;
        width: 32px;
        height: 32px;
        padding: 16px;
        border-radius: 64px;
      }
      padding: 32px 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', sans-serif;
      text-align: center;
      button {
        width: 100%;
        max-width: 384px;
        font-family: inherit;
        cursor: pointer;
        background: #115BCA;
        border-radius: 999px;
        height: 32px;
        color: #FFF;
        border: none;
        font-size: 12px;
        font-weight: 600;
        &:hover {
          background: #1870F4;
        }
        &:active {
          background: #3A85F6;
        }
      }
    }}
  </style>
  <article>
    <div><svg fill="#B7CAD4" height="32" icon-name="ban-fill" viewBox="0 0 20 20" width="32" xmlns="http://www.w3.org/2000/svg">
      <g clip-path="url(#a)"><path d="M19.188 10.304a2.63 2.63 0 00-.776-1.873 2.825 2.825 0 00-1.493-.796c-.881-.156-1.77-.372-2.493-.899-1.177-.858-1.891-2.091-2.04-3.487-.065-.627-.374-1.236-.865-1.708-1.05-1.01-2.747-.91-3.776.12L3.905 5.5a2.63 2.63 0 00-.775 1.873c0 .707.275 1.372.776 1.872a2.792 2.792 0 001.664.82c.332.036.648.12.957.224l-4.901 4.9a2.25 2.25 0 103.182 3.18l4.9-4.9c.102.31.187.626.223.959.065.607.356 1.198.82 1.663a2.638 2.638 0 001.873.773c.678 0 1.357-.258 1.873-.773l3.915-3.915c.5-.5.776-1.165.776-1.872z"></path></g><defs><clipPath id="a"><path d="M0 0h20v20H0z"></path></clipPath></defs>
    </svg></div>
    <h1>This account has been banned</h1>
    <button>Explore Reddit Communities</button>
  </article>
</art-frame></DIV>

<p-s s="0.3642292"></p-s><bpm-emote aria-hidden=true left>\[](/lyragawp)</bpm-emote>My test account (5 years old!) got banned *immediately*, and all of its post history got wiped too. RIP <a style="white-space:pre" href="https://www.reddit.com/user/popstonia/" rel="nofollow">/u/popstonia</a>.

<p-s s="0.45527372"></p-s>For this reason, I changed the <spam-text>*real* number</spam-text> in this blogpost to <spam-text>*UA-49307539-*</spam-text>, which is in reality a random number - I would rather not put a piece of text out there that can kill people's accounts through just posting it.

<p-s s="0.019868873"></p-s>I tried to recreate the ban with a friend's account which had a little more history on it, and that one ended up being fine. So I'm guessing this string only killed my test account because it was already a certain level of suspicious for the anti-spam filters.

<p-s s="0.013416407"></p-s>I don't actually know for sure whether the filter is still active, or whether my account getting nuked was a coincidence, but I'm choosing not to publicize the specific string used just to be safe.

<p-s s="0.7207559"></p-s>Alright so this next one has a pretty interesting <spam-text>removal</spam-text> message:

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>1</post-score><comment-user>Redstoner7</comment-user> in <comment-user>UnusAnnusArchival</comment-user></post-head>
    <h1>Massive Torrent of Unus Annus content</h1>
    <comment-head><spam-reason>Removed: spam https://www.reddit.com/message/messages/8edha7</spam-reason> • <span style="color:#8F5C5B">(Unus Annus Archiving)</span> • 0 Comments • self.UnusAnnusArchival • 11 months (edited 11 months)</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.29816645"></p-s>The post here isn't all that interesting, but what is is that it got immediately <spam-text>removed</spam-text>. I have no idea why the removal message would link to a specific Reddit PM? Is this the message that was sent to the user? Was it sent to admins? Was it sent to modmail? Is it a DMCA message?

<p-s s="0.20940167"></p-s><bpm-emote aria-hidden=true right>\[](/lyrabeam)</bpm-emote>I wanted to get to the bottom of this so I did some OSINTing and tracked down the person who made that post, [Aria](https://aria.coffee/). I asked her to check the message link, but it turns out that it was not sent to her account. So this got me even more curious.

<p-s s="0.4113821"></p-s>Now, something we do have is the id of the message - <spam-text>8edha7</spam-text>. Just like the other ids on Reddit, it is sequential. This meant I could figure out when this linked message was sent based on the messages in my own message history. And this message appears to land in the latter half of May 2017!

<p-s s="0.2498296"></p-s>I still don't know what this message is and why it is linked in the <spam-text>removal reason</spam-text>, but it is a rather old message from before the Reddit account or the subreddit were even created.

<DIV><art-frame aria-label="reddit post" role="figure">
  <article><relay-post>
    <post-head><post-score>0</post-score><comment-user>neynime</comment-user> in <comment-user>MyLittleOutOfContext</comment-user></post-head>
    <h1>Sex video chat with Russian girls. Free registration. DtAyqbIm</h1>
    <comment-head><spam-reason>Removed: Janitor russian girls chat: Submitted by banned user neynime</spam-reason> • 0 Comments • <censor-ed>example</censor-ed>.com • 5 yrs</comment-head>
  </relay-post></article>
</art-frame></DIV>

<p-s s="0.6483569"></p-s>I'm not sure what's up with this one. Like obviously it's just sex spam or whatever, but what's up with that removal message? Is it talking about <spam-text>Janitor russian girls</spam-text> who chat, or is there a reddit <spam-text>janitor</spam-text> who did the removal? Why is it <spam-text>submitted by banned user</spam-text>? Is this like a <spam-text>banall</spam-text> from before that was a thing? So many questions, and unlike the previous post I can't even reach out to anyone to ask about it.

<p-s s="0.22236544"></p-s>Okay, but there's one more removal I found pretty interesting, and it's this one here:

<DIV><art-frame style="height:fit-content;" aria-label="reddit comment" role="figure">
  <relay-thread>
    <relay-comment><comment-head><spam-reason>Removed: some pages have personal info - 11/15/12 mg</spam-reason> • <comment-user>gnbman</comment-user> • 1 points • 8 years</comment-head>
      <p><a href="https://knowyourmeme.com/memes/woll-smoth" rel="nofollow">https://encyclopediadramatica.se/thumb/8/8a/Woll_Smoth_original.jpg/180px-Woll_Smoth_original.jpg</a></p>
    </relay-comment>
  </relay-thread>
</art-frame></DIV>

<p-s s="0.31346247"></p-s>For those out of the loop, <spam-text>Encyclopedia Dramatica</spam-text> is a parody wiki site centered around internet culture and making fun of people. It's pretty much like if 4chan was in charge of Wikipedia. A lot of the pages are pretty mean to their subjects, sometimes - as you might deduce from the removal message above - to the point of digging up and documenting their personal history.

<p-s s="0.21674608"></p-s>Thus, it seems like <spam-text>mg</spam-text> decided to ban the entire domain and auto-remove any links to it. I believe this is noteworthy as it is the only removal here that is not just spam, but instead a legitimate website that Reddit did not like the content of.

## Reddit engineering

<p-s s="0.071327575"></p-s>So that was all I was able to deduce from what I saw myself, but as it turns out, Reddit has been writing about their anti-spam systems too!

<p-s s="0.93607247"></p-s>There's a post from 2023 on [/r/RedditEng](https://old.reddit.com/r/RedditEng/) titled *[Protecting Reddit Users in Real Time at Scale](https://www.reddit.com/r/RedditEng/comments/16m3t7m/protecting_reddit_users_in_real_time_at_scale/)* that talks about internal systems called <spam-text>Rule-Executor-V1</spam-text> (REV1), <spam-text>REV2</spam-text>, and <spam-text>Snooron</spam-text>.

<p-s s="0.29669324"></p-s>The timeline is a bit messy, but how I understand it is that REV1 was created in 2016, then Snooron was developed in 2021 to modernize REV1, and two years later everything was migrated to REV2? I wonder if that migration is what led to me seeing the admin removal messages back in 2021.

<p-s s="0.5829535"></p-s>Both REV1 and REV2 run off of Lua rules such as this:

<pre class="sx-block"><code><sx-k>if</sx-k> <sx-p>body_match</sx-p>(<sx-s>"some bad text"</sx-s>) <sx-k>then</sx-k>
  <sx-p>action</sx-p>(<sx-e>user</sx-e>)
<sx-k>end</sx-k></code></pre>

<p-s s="0.14366198"></p-s>This leads me to believe that REV1 is what *we* know as spamurai. The timeline seems to match, and we've seen samurai emit strings such as "<spam-text>nil</spam-text>" that you'd expect from Lua.

<p-s s="0.67007405"></p-s>There have been [fairly recent user reports](https://old.reddit.com/r/ModSupport/comments/1pejhf7/safety_spamurai/) of posts getting removed by the users /u/Safety_Spamurai and /u/bot-bouncer, so the spamurai name is still at least *somewhat* in use, even for REV2 or snooron.

<p-s s="0.03224406"></p-s>But we also saw removals such as <spam-text>u'torenteu'</spam-text> and <spam-text>u'UA-49307539-'</spam-text>, which are clearly Python2.7 unicode strings. The former was way before 2016, so that makes sense, but what about the latter removal that we only saw in like 2020?

<p-s s="0.44590566"></p-s>Well, REV1 also ran on Python2.7, so I think there are two possible conclusions: either the REV1 code calls out the URL inspection code written in Python2.7, or the inspection code is entirely separate from REV1/spamurai. I suspect the latter, because all of the spamurai <spam-text>removal messages</spam-text> seem to be prefixed with "<spam-text>spamurai</spam-text>".

<p-s s="0.45667195"></p-s>I also learned that, [according to this talk](https://www.youtube.com/watch?v=lWCt4t1Dhvc), snooron runs on Flink Stateful Functions, classifies posted images, runs OCR on said images, and uses Python3 for its workers.

<p-s s="0.93535244"></p-s>I also found this [Australian eSafety PDF](https://www.esafety.gov.au/sites/default/files/2025-07/BOSE-responses-to-mandatory-notices-tvec-March2025-updatedJuly2025.pdf) which lists Reddit as using, as of 2024, the [Hive AI](https://thehive.ai/) for OCR and image/video classification, but also the [Google Vision OCR API](https://docs.cloud.google.com/vision/docs/ocr).

<p-s s="0.02786837"></p-s>They explain that Hive's OCR supports 12 languages, and thus they also need Google's OCR to support a lot more of them. They also mentioned that they're working on an internal tool that would support 80 languages.

<p-s s="0.30850345"></p-s>Though, the text classification itself is done in\-<span style="color:blue">house</span> using snooron. Snooron also has internal image hash-matching functionality. I don't know whether this is just using existing anti-abuse/anti-terrorism hash databases, or if it's also Reddit's own hashes for common spam and such.<bpm-emote aria-hidden=true right>\[](/lyrahi)</bpm-emote>

<p-s s="0.9590444"></p-s>Going back in time, I also found [this ticket](https://web.archive.org/web/2009/http://code.reddit.com/ticket/124) from 2009 where <a href="https://old.reddit.com/u/spez" style="color:#ff0011;font-weight:600">spez</a><span style="font-size:x-small;color:#888;translate: 1px -5px;display:inline-block;">\[<span style="color:#ff0011" title="reddit admin, speaking officially">A</span>]</span> confirms that a user called crm114 is a spam filter that can be trained by moderators. [CRM114](https://en.wikipedia.org/wiki/CRM114_(program)) is an old open-source spam classification software that, among other things, lets you "train" it with data to make its detection more reliable.

<p-s s="0.8253275"></p-s>This is also why the **admintools.spam** method in Reddit's source code has a **train_spam** keyword - it decides whether the anti-spam filters should be trained off of the performed moderator action. So, approve good posts in your sub if you want less false-positives?

<!--
notes:
- https://www.infoq.com/presentations/reddit-architecture-evolution/
- https://www.reddit.com/r/RedditEng/comments/16m3t7m/protecting_reddit_users_in_real_time_at_scale/
- https://www.reddit.com/r/RedditEng/comments/1eqkaiv/how_reddit_uses_signalsjoiner_in_its_realtime/
- https://www.reddit.com/r/RedditEng/comments/1lioedy/pest_control_eliminating_python_rabbitmq_and_some/
- https://www.reddit.com/r/RedditEng/comments/16g7pn7/reddits_llm_text_model_for_ads_safety/ (snooron-text-classification-worker)
- https://www.reddit.com/r/RedditEng/comments/q14tsw/evolving_reddits_ml_model_deployment_and_serving/ (Minsky/Gazette)
- https://www.reddit.com/r/RedditEng/comments/1sx8693/the_zero_trust_odyssey/
-->

## Why now?

<p-s s="0.18495865"></p-s><bpm-emote aria-hidden=true left style="scale: -1 1">\[](/amusedlyra)</bpm-emote>So why release all this information now and not 5 years ago? I believe the information in this post, if released back in 2021, would've been catastrophic for Reddit's spam issues. I don't care too much about large companies, but covering internet forums in spam is not something I strive to do. In 2026 however, I believe this information is no longer dangerous to publicly share.

<p-s s="0.21767464"></p-s>First of all, the [Perspective API is shutting down](https://web.archive.org/web/20260624230439/https://perspectiveapi.com/) by the end of this year. I doubt Reddit is still using this API, and even if they are, they'll have to migrate off of it soon anyways. Secondly, there's that elephant in the room. LLMs have changed the game and revolutionized... the spam industry. And thus, I think it's safe to assume that Reddit has had to overhaul *a lot* in their anti-spam systems to make it work in the year of 2026.


## afterword

<p-s s="0.45836225"></p-s><bpm-emote aria-hidden=true right>\[](/lyraheart)</bpm-emote>hiii! probably not the blogpost you were expecting, but hopefully a fun one nontheless! ^^

<p-s s="0.77797157"></p-s>as usual, i did the whole "handwritten html/css, no images, no external resources, no javascript" thing for this post too (46kB gzipped btw!), but while recreating the old reddit ui i was pleasantly surprised by just how nice its code is! it feels like it was written by someone who actually loves html and css and wants to give me a warm hug. i was amused by the css actually using the <span style="color:orangered">orangered</span> color *by name*, a rare sight these days!

<p-s s="0.64679396"></p-s>anyways, some other updates - many of you are probably awaiting my [x86css](https://lyra.horse/x86css/) blog post, and it is hopefully coming out at some point, but in the meanwhile i [gave a talk](https://lyra.horse/slides/#2026-cssday) about the project at css day (which was a really fun event!!). unfortunately, the recordings for the talk will initially be behind a paywall, but they should become public *eventually*. i'm also trying to get the same talk accepted at [40c3](https://events.ccc.de/congress/2026/), in which case the recordings will be available immediately. besides that, i'll likely be doing a few other talks this year too - check [my slides page](https://lyra.horse/slides/) for up to date info.

<p-s s="0.1713108"></p-s>other than that i'm really hoping to host [x3ctf](https://x3c.tf/) again this year. we're still not sure when it is happening, but i think we are all aiming to make it happen before the end of the year.

<p-s s="0.069555365"></p-s>thank you so much for reading &lt;3

<p-s s="0.9590444"></p-s>*If you’d like to reach out, feel free to message me on my socials or at lyra.horse [at] gmail.com.*

<p-s s="0.61226535"></p-s>**Discuss this post on:** twitter, mastodon, lobsters

<!-- # Todo: -->

<!-- - add more easter eggs -->
<!-- - fix safari support (maybe done?) -->
<!-- - add more ponymotes -->
<!-- - add summary metadata -->
<!-- - release date metadata -->
<!-- - maybe more stuff in reddit engineering -->
<!-- - write afterword -->


<!-- [^notif]: My memory is a bit foggy so I'm not actually sure if I got the mod spam as notifications, or if I just happened to visit the spam removals list that day. The former of the two sounds better in the intro though, so I'm going with that :P. TODO: rewrite this part - in reality i think i was getting modqueue notifications which included spam removals -->

[^modlist]: <p-s s="0.93607247"></p-s>In this post I will default to visiting [Old Reddit](https://old.reddit.com) pages with a logged-in account. Not all information may be visible on New Reddit or as a logged-out user.

[^relaysource]: <p-s s="0.80985177"></p-s>Relay for reddit is closed-source, but unobfuscated. The code snippet shown is a decompilation.

[^perspectivefree]: <p-s s="0.22059259"></p-s>It *seems* free to me. The [FAQ](https://web.archive.org/web/20220125234838/https://www.perspectiveapi.com/faq/) states that <span style="color:#6d2445;font-family:sans-serif">"Perspective API is free and entirely self-service"</span>. I did not look through their Privacy Policy, so I don't know whether they sell the data, but the API does have a **doNotStore** parameter: *"Do not store the comment or context sent in this request. By default, the service may store comments/context for debugging purposes."*.

[^googleservice]: <p-s s="0.73262775"></p-s>Perspective API is made by [Jigsaw](https://jigsaw.google.com/), an incubator within Google, and Google's Counter Abuse Technology team.

[^same]: <p-s s="0.024021113"></p-s>We got back **0.12571794**, which is technically off by *0.00000001* from <spam-text>0.12571795</spam-text>, but I believe this is just a rounding error.

[^whyy]: <p-s s="0.18280718"></p-s>Because I'm not sure how Reddit processes their markdown before shoving it into the Perspective API, so I tried two variants.

[^2f]: <p-s s="0.660754"></p-s>The domain, of course, is actually *tracker.opentrackr.org*, but it appears in the magnet link as <em style="line-break:anywhere">udp%3a%2f%<strong>2ftracker.opentrackr.org</strong>%3a1337%2fannounce</em>, so the **2f** from **%2f** gets prepended to the domain.

[^unidecode]: <p-s s="0.79370236"></p-s>[Unidecode](https://pypi.org/project/Unidecode) is a library that attempts to represent unicode strings as ASCII text, which I believe is called [romanization](https://en.wikipedia.org/wiki/Romanization_of_Korean) for languages such as Korean. For the demo in the blogpost I had to get the [Version 1.2.0](https://pypi.org/project/Unidecode/1.2.0/) and manually install it as it is the last version to support Python 2.7.

<!-- [^comment]: I'm going to be using the term "comment" by itself going forwards, even if what I say applies to both posts and comments. -->
