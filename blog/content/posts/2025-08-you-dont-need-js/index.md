+++
title = "You no longer need JavaScript"
date = 2025-08-28T20:40:00Z
draft = false
tags = ["css"]
slug = "you-dont-need-js"
summary = "An overview of what makes modern CSS so awesome."
+++

So much of the web these days is ruined by the bloat that is modern JavaScript frameworks. React apps that take several seconds to load. NextJS sites that throw random hydration errors. The *node_modules* folder that takes up gigabytes on your hard drive.

It's awful. And you don't need it.

<style>
  #cover-art {
    background: #282828;
    overflow: clip;
    div {
      transform: translate(-16px,35px) rotate(355deg) scale(1.4);
      translate: 22% 0;
      color-scheme: dark;
      height: 300px;
      font-family: system-ui, sans-serif;
      font-size: 12px;
      color: #E3E3E3;
      width: 75%;
      ::selection {
        color: #000;
        background: #A8C7FA;
      }
      dev-icon {
        display: inline-block;
        width: 8px;
        height: 8px;
        margin-top: 1px;
        margin-right: 4px;
        border: 2px solid;
        border-radius: 2px;
        &::after {
          text-align: center;
          width: 8px;
          height: 8px;
          font-size-adjust: 0.5;
        }
        &[html] {
          color: #7CACF8;
          &::after {
            content: '----\A ----\A ----\A --';
            text-align: left;
            white-space: pre;
            position: absolute;
            translate: 1px 0.5px;
            line-height: 1.5px;
            font-size: 5px;
            font-weight: 900;
            letter-spacing: -1px;
            font-size-adjust: 0.5;
          }
        }
        &[font] {
          color: #36A7C7;
          &::after {
            content: 'T';
            position: absolute;
            line-height: 8px;
            font-size: 8px;
            font-weight: 800;
          }
        }
        &[css] {
          color: #BB82E3;
          &::after {
            content: '🖌️';
            position: absolute;
            line-height: 8px;
            font-size: 6px;
            font-weight: 800;
            background: #8E66AB;
            color: #0001;
            background-clip: text;
          }
        }
        &[js] {
          color: #E38053;
          &::after {
            content: '<>';
            position: absolute;
            line-height: 8px;
            font-size: 6px;
            font-weight: 800;
          }
        }
      }
      table {
        --b: #5E5E5E;
        thead {
          border: 1px solid var(--b);
          td {
            padding: 5px 4px;
          }
        }
        width: 100%;
        background: #28292A;
        border-collapse: collapse;
        tr {
          &:nth-child(2n) {
            background: #1F1F1F;
          }
          &:hover {
            background: #3D3D3D;
          }
          cursor: default;
        }
        td {
          border-left: 1px solid var(--b);
          white-space: nowrap;
          padding: 1px 4px;
        }
        @media (width < 640px) { td:nth-child(2) { display:none } }
        @media (width < 480px) { td:nth-child(3) { display:none } }
        @media (width < 380px) { td:has(dev-icon[font]) span { display:none } }
      }
    }
  }
</style>
<DIV><art-frame flex id="cover-art" aria-label="Cover art of the Chrome DevTools showing a bunch of requests to assets, most of which are JavaScript files" role="img">
<div>
<table>
  <thead>
    <tr>
      <td>Name</td>
      <td>Status</td>
      <td>Type</td>
      <td>Size</td>
      <td>Time</td>
    </tr>
  </thead>
  <tbody>
    <tr><td><dev-icon html></dev-icon>app</td><td>200</td><td>document</td><td>153.8 kB</td><td>51 ms</td></tr>
    <tr><td><dev-icon font></dev-icon>6920616d20612066<span>-s.p.6f6e7421</span>.woff2</td><td>200</td><td>font</td><td>31.5 kB</td><td>32 ms</td></tr>
    <tr><td><dev-icon font></dev-icon>686579206d652074<span>-s.p.6f6f2121</span>.woff2</td><td>200</td><td>font</td><td>28.5 kB</td><td>116 ms</td></tr>
    <tr><td><dev-icon css></dev-icon>77687920646f6573.css</td><td>200</td><td>stylesheet</td><td>253 kB</td><td>47 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>2074686520646566.js</td><td>200</td><td>script</td><td>648 kB</td><td>83 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>61756c74206e6578.js</td><td>200</td><td>script</td><td>166 kB</td><td>363 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>746a732074616b65.js</td><td>200</td><td>script</td><td>83.3 kB</td><td>46 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>turbopack-20757020302e354d.js</td><td>200</td><td>script</td><td>38.0 kB</td><td>95 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>423f207468617427.js</td><td>200</td><td>script</td><td>414 B</td><td>34 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>73206d6f72652074.js</td><td>200</td><td>script</td><td>32.6 kB</td><td>49 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>68616e206d792065.js</td><td>200</td><td>script</td><td>15.1 kB</td><td>71 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>6e7469726520626c.js</td><td>200</td><td>script</td><td>143 kB</td><td>48 ms</td></tr>
    <tr><td><dev-icon js></dev-icon>6f6721 hey there!</td><td>200</td><td>script</td><td>4.1 kB</td><td>103 ms</td></tr>
  </tbody>
</table>
</div>
</art-frame></DIV>

The intro paragraph of this post is tongue-in-cheek. It's there to get you to read the rest of the post. I suspect the megabytes of tracking scripts intertwined with bad code is far more likely to be the real culprit behind all the terrible sites out there. Web frameworks have their time and place. And despite my personal distaste for them, I know they are used by many teams to build awesome well-optimized apps.

Despite that, I think there's some beauty in leaving it all behind. Not just the frameworks, but JavaScript altogether.<!-- [Figmas](https://www.figma.com/) and [Photopeas](https://www.photopea.com/) need their JavaScript. [Interactive](https://x3c.tf/archive/) [experiences](https://lyra.horse/antonymph/) do[^interactive]. But does your homepage or blog need it?--> Not every site needs JavaScript. Perhaps your [e-commerce site needs it for its complex carts and data visualization dashboards](https://justfuckingusereact.com/), but is it really a necessity for most of what's out there?

It's actually [pretty incredible](https://lyra.horse/css-clicker/) what HTML and CSS alone can achieve.

<!--I don't think that everyone should switch to a strict CSS-only diet, but I do believe that the average web developer could benefit from knowing just a little more about our cascading little friend.-->

## So, what do you say?

My goal with this article is to share my perspectives on the web, as well as introduce many aspects of modern HTML/CSS you may not be familiar with. I'm not trying to make you give up JavaScript, I'm just trying to show you everything that's possible, leaving it up to you to pick what works best for whatever you're working on.

I think there's a lot most web developers don't know about CSS.

And I think JS is often used where better alternatives exist.

So, let me show you what's out there.

<style>
  /*input[type=checkbox]*/
  code-frame, .code-frame, fake-frame {
    width: calc(100% - 4px);
    display: block;
    overflow: auto;
    border: 2px inset;
  }
  code-frame, .code-frame {
    font-family: var(--font-code);
    font-size: 0.8125rem;
    white-space: pre;
    background: #14191F;
    color: #EEE;
    border-color: #444;
  }
  fake-frame {
    background: #FFF;
    /*border-color: initial;*/
    border-color: #EEE;
  }
  code-compare {
    display: flex;
    width: calc(100% - 4px);
    height: fit-content;
    overflow: clip;
    border: 2px inset #999;
    @media (width < 768px) {
      flex-direction: column;
    }
    &[vertical] {
      flex-direction: column;
    }
  }
  no-wrap {
    white-space: nowrap;
  }
  .safari {
    /* CSS-only Safari Detection (stackoverflow.com/a/74381245/2251833/) */
    @supports (not (font: -apple-system-body)) and (-webkit-appearance: none) {
      display: none;
    }
  }
  :root {
    --inter-stack: Inter, -apple-system, BlinkMacSystemFont, "Open Sans", "Noto Sans", "Roboto", system-ui, sans-serif;
  }

  @media (width < 768px) {
    .over768 { display: none; visibility: none; }
  }
  @media (width >= 768px) {
    .under768 { display: none; visibility: none; }
  }
</style>

## "But CSS sucks"

I believe a lot of the negativity towards CSS stems from not really knowing how to use it. Many developers kind of just skip learning the CSS fundamentals in favor of the more interesting Java- and TypeScript, and then go on to complain about a styling language they don't understand.

I suspect this is due to many treating CSS as this silly third wheel for adding borders and box-shadows to a webapp. <!--rephrase-->It's undervalued and often compared to glorified crayons, rather than what it really is - a powerful domain-specific programming language.

It's telling when to this day the only CSS joke in the webdev circles is centering a div.

<!-- it was fun recreating all of the flexbox icons in css haha -->
<DIV><code-compare id="center-gadget" aria-label="a centered div and its code" role="figure"><fake-frame id="demo-center-gadget" style="min-height:9em" >
<div>i am a div</div>
</fake-frame>
<div id="center-gadget-devtools" style="min-height:12em"><div>body {</div><div class="line">  <span style="color:#5CD5FB">display</span>: flex;<label class="flex-icon" aria-label="Toggle Flex panel" aria-hidden="true"><input type=checkbox id="flex-panel-visible" checked><span>🁣 🁢 🁣<br>🁢 🁣 🁢</span></label><flex-popup aria-hidden="true">
<div><span style="color:#5CD5FB">flex-direction</span>: <flex-res dg-fd>row</flex-res><flex-res dg-fd>column</flex-res><flex-res dg-fd>row-reverse</flex-res><flex-res dg-fd>column-reverse</flex-res><flex-res-default dg-fd>row</flex-res-default></div>
<div class="buttons">
<label aria-label="row" style="line-height:0;flex-wrap:wrap;"><flex-icon norot><input type=radio name="dg-fd"><div style="border: 1px solid;width:4px;height:6px;margin:1px;background:none"></div><div style="border: 1px solid;width:4px;height:6px;margin:1px"></div><div style="margin-top: -8px" aria-hidden="true">⟶</div></flex-icon></label>
<label aria-label="column" style="line-height:0;flex-wrap:wrap;writing-mode: vertical-lr;"><flex-icon norot><input type=radio name="dg-fd"><div style="border: 1px solid;width:6px;height:4px;margin:1px;background:none"></div><div style="border: 1px solid;width:6px;height:4px;margin:1px"></div><div style="margin-right:1px" aria-hidden="true">⟶</div></flex-icon></label>
<label aria-label="row-reverse" style="line-height:0;flex-wrap:wrap;"><flex-icon norot><input type=radio name="dg-fd"><div style="border: 1px solid;width:4px;height:6px;margin:1px"></div><div style="border: 1px solid;width:4px;height:6px;margin:1px;background:none"></div><div style="margin-top: -8px" aria-hidden="true">⟵</div></flex-icon></label>
<label aria-label="column-reverse" style="line-height:0;flex-wrap:wrap;writing-mode: vertical-lr;"><flex-icon norot><input type=radio name="dg-fd"><div style="border: 1px solid;width:6px;height:4px;margin:1px"></div><div style="border: 1px solid;width:6px;height:4px;margin:1px;background:none"></div><div style="margin-right:1px" aria-hidden="true">⟵</div></flex-icon></label>
</div>
<div><span style="color:#5CD5FB">flex-wrap</span>: <flex-res dg-fw>nowrap</flex-res><flex-res dg-fw>wrap</flex-res><flex-res-default dg-fw>nowrap</flex-res-default></div>
<div class="buttons">
<label aria-label="nowrap" style="letter-spacing:-2px;font-kerning:none;font:8px monospace"><flex-icon><input type=radio name="dg-fw"><span aria-hidden="true">🁣 🁢 🁣 </span></flex-icon></label>
<label aria-label="wrap" style="letter-spacing:-2px;font-kerning:none;font:8px monospace"><flex-icon><input type=radio name="dg-fw"><span aria-hidden="true">🁣 🁢 🁣 <br>🁢 🁣 🁢 </span></flex-icon></label>
</div>
<div><span style="color:#5CD5FB">align-content</span>: <flex-res dg-ac>center</flex-res><flex-res dg-ac>flex-start</flex-res><flex-res dg-ac>flex-end</flex-res><flex-res dg-ac>space-around</flex-res><flex-res dg-ac>space-between</flex-res><flex-res dg-ac>stretch</flex-res><flex-res-default dg-ac>normal</flex-res-default></div>
<div class="buttons">
<label aria-label="center" column style="gap:2px"><flex-icon><input type=radio name="dg-ac"><div style="width:8px;height:3px"></div><div style="width:16px;height:2px;opacity:0.5"></div><div style="width:8px;height:3px"></div></flex-icon></label>
<label aria-label="flex-start" column style="gap:2px"><flex-icon rev><input type=radio name="dg-ac"><div style="width:16px;height:2px;opacity:0.5"></div><div style="width:8px;height:3px"></div><div style="width:8px;height:3px;margin:0 0 6px;"></div></flex-icon></label>
<label aria-label="flex-end" column rev style="gap:2px"><flex-icon rev><input type=radio name="dg-ac"><div style="width:16px;height:2px;opacity:0.5"></div><div style="width:8px;height:3px"></div><div style="width:8px;height:3px;margin-top:6px;"></div></flex-icon></label>
<label aria-label="space-around" column style="gap:2px"><flex-icon><input type=radio name="dg-ac"><div style="width:16px;height:2px;opacity:0.5"></div><div style="width:8px;height:3px"></div><div style="width:8px;height:3px;margin-top:2px;"></div><div style="width:16px;height:2px;opacity:0.5"></div></flex-icon></label>
<label aria-label="space-between" column style="justify-content: space-between;"><flex-icon><input type=radio name="dg-ac"><div style="width:16px;height:2px;opacity:0.5;margin-top:2px"></div><div style="width:8px;height:3px"></div><div style="width:8px;height:3px;margin-top:8px"></div><div style="width:16px;height:2px;opacity:0.5;margin:0 0 2px"></div></flex-icon></label>
<label aria-label="stretch" column style="justify-content: space-between;"><flex-icon><input type=radio name="dg-ac"><div style="width:16px;height:2px;opacity:0.5;margin-top:2px"></div><div style="width:8px;height:6px"></div><div style="width:8px;height:6px;margin-top:2px"></div><div style="width:16px;height:2px;opacity:0.5;margin:0 0 2px"></div></flex-icon></label>
</div>
<div><span style="color:#5CD5FB">justify-content</span>: <flex-res dg-jc>center</flex-res><flex-res dg-jc>flex-start</flex-res><flex-res dg-jc>flex-end</flex-res><flex-res dg-jc>space-around</flex-res><flex-res dg-jc>space-between</flex-res><flex-res dg-jc>space-evenly</flex-res><flex-res-default dg-jc>normal</flex-res-default></div>
<div class="buttons">
<label aria-label="center" style="gap:2px"><flex-icon><input type=radio name="dg-jc" checked><div style="height:8px;width:3px"></div><div style="height:16px;width:2px;opacity:0.5"></div><div style="height:8px;width:3px"></div></flex-icon></label>
<label aria-label="flex-start" style="gap:2px"><flex-icon flip><input type=radio name="dg-jc"><div style="height:16px;width:2px;opacity:0.5"></div><div style="height:8px;width:3px"></div><div style="height:8px;width:3px;margin-right: 6px;"></div></flex-icon></label>
<label aria-label="flex-end" rev style="gap:2px"><flex-icon flip><input type=radio name="dg-jc"><div style="height:16px;width:2px;opacity:0.5"></div><div style="height:8px;width:3px"></div><div style="height:8px;width:3px;margin-left:6px;"></div></flex-icon></label>
<label aria-label="space-around" style="justify-content: space-between;"><flex-icon><input type=radio name="dg-jc"><div style="height:16px;width:2px;opacity:0.5;margin-left:2px"></div><div style="height:8px;width:3px"></div><div style="height:8px;width:3px;margin-left:9px"></div><div style="height:16px;width:2px;opacity:0.5;margin-right: 2px"></div></flex-icon></label>
<label aria-label="space-between" style="gap:2px"><flex-icon><input type=radio name="dg-jc"><div style="height:16px;width:2px;opacity:0.5"></div><div style="height:8px;width:3px"></div><div style="height:8px;width:3px;margin-left:2px"></div><div style="height:16px;width:2px;opacity:0.5"></div></flex-icon></label>
<label aria-label="space-evenly" style="gap:2px"><flex-icon><input type=radio name="dg-jc"><div style="height:16px;width:2px;opacity:0.5;margin-right:1px"></div><div style="height:8px;width:3px"></div><div style="height:8px;width:3px;"></div><div style="margin-left:1px;height:16px;width:2px;opacity:0.5"></div></flex-icon></label>
</div>
<div><span style="color:#5CD5FB">align-items</span>: <flex-res dg-ai>center</flex-res><flex-res dg-ai>flex-start</flex-res><flex-res dg-ai>flex-end</flex-res><flex-res dg-ai>stretch</flex-res><flex-res dg-ai>baseline</flex-res><flex-res-default dg-ai>normal</flex-res-default></div>
<div class="buttons">
<label aria-label="center" style="gap:2px"><flex-icon rev><input type=radio name="dg-ai" checked><div style="background:none;display:flex;gap:3px;
    align-items:center;"><div style="height:14px;width:3px"></div><div style="height:8px;width:3px"></div></div><div style="position:absolute;width:16px;height:2px;opacity:0.5"></div></flex-icon></label>
<label aria-label="flex-start" column style="gap:1px"><flex-icon><input type=radio name="dg-ai"><div style="width:16px;height:2px;opacity:0.5"></div><div style="margin:0 0 1px;background:none;display:flex;gap:2px"><div style="height:11px;width:3px"></div><div style="height:7px;width:3px"></div></div></flex-icon></label>
<label aria-label="flex-end" column style="gap:1px"><flex-icon><input type=radio name="dg-ai"><div style="background:none;display:flex;gap:2px;align-items:flex-end;margin-top:3px"><div style="height:11px;width:3px"></div><div style="height:7px;width:3px"></div></div><div style="width:16px;height:2px;opacity:0.5"></div></flex-icon></label>
<label aria-label="stretch" column style="gap:1px"><flex-icon><input type=radio name="dg-ai"><div style="width:16px;height:2px;opacity:0.5;margin-top:1px"></div><div style="background:none;display:flex;gap:2px"><div style="height:10px;width:3px"></div><div style="height:10px;width:3px"></div></div><div style="width:16px;height:2px;opacity:0.5"></div></flex-icon></label>
<label aria-label="baseline" column style="gap:2px"><flex-icon norot><input type=radio name="dg-ai"><span style="margin:0 0 -2px;font-weight:500;">A</span><div style="width:16px;height:2px;opacity:0.5;margin:0 0 1px"></div></flex-icon></label>
</div>
</flex-popup></div><!--
--><div class="line">  <span style="color:#5CD5FB">flex-direction</span>: <flex-res dg-fd>row</flex-res><flex-res dg-fd>column</flex-res><flex-res dg-fd>row-reverse</flex-res><flex-res dg-fd>column-reverse</flex-res>;</div><!--
--><div class="line">  <span style="color:#5CD5FB">flex-wrap</span>: <flex-res dg-fw>nowrap</flex-res><flex-res dg-fw>wrap</flex-res>;</div><!--
--><div class="line">  <span style="color:#5CD5FB">align-content</span>: <flex-res dg-ac>center</flex-res><flex-res dg-ac>flex-start</flex-res><flex-res dg-ac>flex-end</flex-res><flex-res dg-ac>space-around</flex-res><flex-res dg-ac>space-between</flex-res><flex-res dg-ac>stretch</flex-res>;</div><!--
--><div class="line">  <span style="color:#5CD5FB">justify-content</span>: <flex-res dg-jc>center</flex-res><flex-res dg-jc>flex-start</flex-res><flex-res dg-jc>flex-end</flex-res><flex-res dg-jc>space-around</flex-res><flex-res dg-jc>space-between</flex-res><flex-res dg-jc>space-evenly</flex-res>;</div><!--
--><div class="line">  <span style="color:#5CD5FB">align-items</span>: <flex-res dg-ai>center</flex-res><flex-res dg-ai>flex-start</flex-res><flex-res dg-ai>flex-end</flex-res><flex-res dg-ai>stretch</flex-res><flex-res dg-ai>baseline</flex-res>;</div><!--
--><div>}</div></div>
</code-compare></DIV>
<style>
@property --tooltip-fade {
  syntax: '<percentage>';
  initial-value: 0%;
  inherits: true;
}
#center-gadget-devtools {
  width: calc(100% - 16px - 2px);
  background: #282828;
  color: #E3E3E3;
  white-space: pre;
  line-height: normal;
  font: 12px monospace;
  padding: 8px;
  .line {
    &:not(:has(flex-popup:hover)):hover {
      background: #3D3D3D;
    }
  }
  .flex-icon {
    -webkit-user-select: none;
    user-select: none;
    cursor: default;
    margin: -10px 0;
    padding: 2px;
    border-radius: 10px;
    display: inline-block;
    letter-spacing: -2px;
    font-kerning: none;
    line-height: 7px;
    font-size: 50%;
    translate: -1px 2px;
    &:hover {
      background: #FFFFFF1A;
    }
    input {
      opacity: 0;
      position: absolute;
      pointer-events: none;
    }
    &:has(input:focus-visible) {
      border-radius: 3px;
      outline: 2px solid white;
    }
  }
  &:has(#flex-panel-visible:not(:checked)) flex-popup { display: none; }
  flex-popup {
    transition: --tooltip-fade 0s 0.5s, opacity 0.1s 0.1s;
    --tooltip-fade: 0%;
    &:has(.buttons>label:hover) { transition: --tooltip-fade 0.2s 1.1s, opacity 0.1s 0.1s; --tooltip-fade: 100%; }
    padding: 6px;
    border-radius: 4px;
    box-shadow: 0 1px 2px 0 #0004, 0 2px 6px 2px #0002;
    font: 400 12px system-ui, sans-serif;
    position: absolute;
    z-index: 1;
    display: inline-flex;
    flex-direction: column;
    translate: -24px 16px;
    background: #3C3C3C;
    width: 170px;
    min-height: 100px;
    cursor: default;
    opacity: 1;
    & > div:not(.buttons):not(:first-child) {
      margin: 2px 0 1px;
    }
    .buttons {
      display: flex;
      height: 22px;
      width: fit-content;
      background: #282828;
      border: 1px solid #757575;
      border-radius: 3px;
      label {
        display:flex;
      }
      flex-icon {
        display:flex;
        justify-content:inherit;
        align-items:inherit;
        flex-direction:inherit;
        gap:inherit;
        flex-wrap: wrap;
        width: 100%;
        height: 100%;
      }
      label {
        &[rev] {
          flex-direction: row-reverse;
        }
        &[column] {
          flex-direction: column;
          &[rev] {
            flex-direction: column-reverse;
          }
        }
        div {
          background: currentColor;
        }
        justify-content:center;
        align-items:center;
        -webkit-user-select: none;
        user-select: none;
        color: #C7C7C7;
        &:hover {
          color: #E3E3E3;
          &::after {
            user-select: none;
            pointer-events: none;
            content: attr(aria-label);
            position: absolute;
            display: block;
            background: #FFF;
            color: #000;
            border: 1px solid #000;
            writing-mode: initial;
            font-family: system-ui, sans-serif;
            font-size: initial;
            letter-spacing: initial;
            line-height: initial;
            padding: 0 4px 2px;
            box-shadow: 2px 2px 3px 0 #0003;
            z-index: 1;
            translate: 16px 32px;
            opacity: var(--tooltip-fade);
          }
        }
        &:has(input:checked) {
          color: #7CACF8;
        }
        input {
          opacity: 0;
          position: absolute;
          pointer-events: none;
        }
        &:has(input:focus-visible) {
          border-radius: 3px;
          outline: 2px solid white;
        }
        cursor: pointer;
        display: flex;
        width: 22px;
        height: 100%;
        &:not(:last-child) {
          width: 23px;
          border-right: 1px solid #757575;
        }
      }
    }
  }
  &::selection, *::selection {
    background: #A8C7FA;
    color: #000;
  }
  flex-res-default {
    /* can't use currentColor in tor browser */
    color: #e3e3e361/*rgb(from currentColor r g b / 38%)*/;
  }
  &:has(.line:hover>flex-res) flex-popup { opacity: 0.25; }
  /* i wouldn't blame you if you were implementing *this* and chose to go for javascript instead, it's not where css shines even if it can be done */
  &:not(:has(flex-popup label:nth-of-type(1) input[name=dg-fd]:checked)) flex-res[dg-fd]:nth-of-type(1),
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-fd]:checked)) flex-res[dg-fd]:nth-of-type(2),
  &:not(:has(flex-popup label:nth-of-type(3) input[name=dg-fd]:checked)) flex-res[dg-fd]:nth-of-type(3),
  &:not(:has(flex-popup label:nth-of-type(4) input[name=dg-fd]:checked)) flex-res[dg-fd]:nth-of-type(4),
  &:not(:has(flex-popup label:nth-of-type(1) input[name=dg-fw]:checked)) flex-res[dg-fw]:nth-of-type(1),
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-fw]:checked)) flex-res[dg-fw]:nth-of-type(2),
  &:not(:has(flex-popup label:nth-of-type(1) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(1),
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(2),
  &:not(:has(flex-popup label:nth-of-type(3) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(3),
  &:not(:has(flex-popup label:nth-of-type(4) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(4),
  &:not(:has(flex-popup label:nth-of-type(5) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(5),
  &:not(:has(flex-popup label:nth-of-type(6) input[name=dg-ac]:checked)) flex-res[dg-ac]:nth-of-type(6),
  &:not(:has(flex-popup label:nth-of-type(1) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(1),
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(2),
  &:not(:has(flex-popup label:nth-of-type(3) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(3),
  &:not(:has(flex-popup label:nth-of-type(4) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(4),
  &:not(:has(flex-popup label:nth-of-type(5) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(5),
  &:not(:has(flex-popup label:nth-of-type(6) input[name=dg-jc]:checked)) flex-res[dg-jc]:nth-of-type(6),
  &:not(:has(flex-popup label:nth-of-type(1) input[name=dg-ai]:checked)) flex-res[dg-ai]:nth-of-type(1),
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-ai]:checked)) flex-res[dg-ai]:nth-of-type(2),
  &:not(:has(flex-popup label:nth-of-type(3) input[name=dg-ai]:checked)) flex-res[dg-ai]:nth-of-type(3),
  &:not(:has(flex-popup label:nth-of-type(4) input[name=dg-ai]:checked)) flex-res[dg-ai]:nth-of-type(4),
  &:not(:has(flex-popup label:nth-of-type(5) input[name=dg-ai]:checked)) flex-res[dg-ai]:nth-of-type(5),
  &:not(:has(flex-popup input[name=dg-fd]:checked)) div.line:has(>flex-res[dg-fd]),
  &:not(:has(flex-popup input[name=dg-fw]:checked)) div.line:has(>flex-res[dg-fw]),
  &:not(:has(flex-popup input[name=dg-ac]:checked)) div.line:has(>flex-res[dg-ac]),
  &:not(:has(flex-popup input[name=dg-jc]:checked)) div.line:has(>flex-res[dg-jc]),
  &:not(:has(flex-popup input[name=dg-ai]:checked)) div.line:has(>flex-res[dg-ai]),
  &:has(flex-popup input[name=dg-fd]:checked) flex-res-default[dg-fd],
  &:has(flex-popup input[name=dg-fw]:checked) flex-res-default[dg-fw],
  &:has(flex-popup input[name=dg-ac]:checked) flex-res-default[dg-ac],
  &:has(flex-popup input[name=dg-jc]:checked) flex-res-default[dg-jc],
  &:has(flex-popup input[name=dg-ai]:checked) flex-res-default[dg-ai] {
    display:none;
  }
  &:not(:has(flex-popup label:nth-of-type(2) input[name=dg-fw]:checked)) div.line:has(>flex-res[dg-ac]) {
    opacity: 0.5;
  }
  &:has(flex-popup label:nth-of-type(2) input[name=dg-fd]:checked) label,
  &:has(flex-popup label:nth-of-type(4) input[name=dg-fd]:checked) label {
    &:not(:has(flex-icon[norot])) {
      flex-icon { rotate: 90deg; &[rev] { rotate: -90deg; } }
      &:not(:last-child) flex-icon { translate: -0.5px -0.5px; }
    }
  }
   &:has(flex-popup label:nth-of-type(3) input[name=dg-fd]:checked) flex-popup label flex-icon[flip] { rotate: 180deg }
   &:has(flex-popup label:nth-of-type(4) input[name=dg-fd]:checked) flex-popup label:not(:last-child) flex-icon[flip] { rotate: 270deg; translate: -0.5px 0.5px; }
}
/*.flexGadgetPadding { transition: 0.4s max-width, 0.4s max-height; max-width: 768px; max-height: 100px; }*/
body:has(#flex-panel-visible:not(:checked)) .flexGadgetPadding { max-width: 0; max-height: 0; }
#demo-center-gadget {
  div { border: 1px solid red; }
  display: flex;
}
#center-gadget {
  &:has(flex-popup label:nth-of-type(1) input[name=dg-fd]:checked) #demo-center-gadget { flex-direction: row };
  &:has(flex-popup label:nth-of-type(2) input[name=dg-fd]:checked) #demo-center-gadget { flex-direction: column };
  &:has(flex-popup label:nth-of-type(3) input[name=dg-fd]:checked) #demo-center-gadget { flex-direction: row-reverse };
  &:has(flex-popup label:nth-of-type(4) input[name=dg-fd]:checked) #demo-center-gadget { flex-direction: column-reverse };
  &:has(flex-popup label:nth-of-type(1) input[name=dg-fw]:checked) #demo-center-gadget { flex-wrap: nowrap };
  &:has(flex-popup label:nth-of-type(2) input[name=dg-fw]:checked) #demo-center-gadget { flex-wrap: wrap };
  &:has(flex-popup label:nth-of-type(1) input[name=dg-ac]:checked) #demo-center-gadget { align-content: center };
  &:has(flex-popup label:nth-of-type(2) input[name=dg-ac]:checked) #demo-center-gadget { align-content: flex-start };
  &:has(flex-popup label:nth-of-type(3) input[name=dg-ac]:checked) #demo-center-gadget { align-content: flex-end };
  &:has(flex-popup label:nth-of-type(4) input[name=dg-ac]:checked) #demo-center-gadget { align-content: space-around };
  &:has(flex-popup label:nth-of-type(5) input[name=dg-ac]:checked) #demo-center-gadget { align-content: space-between };
  &:has(flex-popup label:nth-of-type(6) input[name=dg-ac]:checked) #demo-center-gadget { align-content: stretch };
  &:has(flex-popup label:nth-of-type(1) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: center };
  &:has(flex-popup label:nth-of-type(2) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: flex-start };
  &:has(flex-popup label:nth-of-type(3) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: flex-end };
  &:has(flex-popup label:nth-of-type(4) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: space-around };
  &:has(flex-popup label:nth-of-type(5) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: space-between };
  &:has(flex-popup label:nth-of-type(6) input[name=dg-jc]:checked) #demo-center-gadget { justify-content: space-evenly };
  &:has(flex-popup label:nth-of-type(1) input[name=dg-ai]:checked) #demo-center-gadget { align-items: center };
  &:has(flex-popup label:nth-of-type(2) input[name=dg-ai]:checked) #demo-center-gadget { align-items: flex-start };
  &:has(flex-popup label:nth-of-type(3) input[name=dg-ai]:checked) #demo-center-gadget { align-items: flex-end };
  &:has(flex-popup label:nth-of-type(4) input[name=dg-ai]:checked) #demo-center-gadget { align-items: stretch };
  &:has(flex-popup label:nth-of-type(5) input[name=dg-ai]:checked) #demo-center-gadget { align-items: baseline };
}
</style>

<div class="over768 flexGadgetPadding" style="width:290px;height:100px;float:right"></div>
<div class="under768 flexGadgetPadding" style="width:100%;height:90px"></div>

Yes, the syntax isn't the prettiest, but is it *really* that hard?

Besides, your devtools probably[^firefox-flex] come with a fun little gadget that lets you fiddle with the flexbox by just clicking around. You don't even need to remember the syntax.

<!--i wanted to write about: maybe something about box-model and clock directions-->

I don't think CSS is fundamentally any more difficult than JS, but if you skip the basics on one and only focus on the other, it's no surprise it feels that way.

## "But it's painful to write"

Another source of disdain for CSS is how awful it has been to write in the past. This is very much true, and is probably why things like [Sass](https://sass-lang.com/) and [Tailwind](https://tailwindcss.com/)[^tailwind] exist.

But that's the thing, it *used* to be bad.

<DIV><twoot-embed aria-label="a twoot from rebane2001" role="figure">
<div class="topbar">
<!-- fallback for no svg (eg tor browser) -->
<div class="pfp svgFallback" style="position:absolute;font-size: 36px;width:48px;text-align:center">🦊</div>
<!-- tried to make a very compact inline svg of my logo, it's not super accurate but looks fine at small sizes -->
<svg class="pfp" version="1.1" viewBox="4 4 260 260" xmlns="http://www.w3.org/2000/svg" fill="#202C39"><path id="line" d="m23 27v112s-1 12 10 24c11 12 76 77 76 77s10 10 24 10c14 0 26-10 26-10l78-80s8-8 8-23v-110l-45 54s-10 16-33 7c-23-9-55-5-70 0-9 3-20 3-31-9-10-10-44-54-43-54z" style="stroke-linecap:round;stroke-linejoin:round;stroke-width:11"/><use href="#line" fill="#EB8258" stroke="none" /><circle cx="83" cy="144" r="15"/><circle cx="187" cy="144" r="15"/><path d="m84 170s-15 1-16 14 3 15 3 15l47 47 35 1 48-52s5-11-4-20c-9-9-22-0-22-0s-29 14-39 14c-13 0-45-17-45-17z" fill="#fff" /><use href="#line" fill="none" stroke="#202C39" /><path d="m116 245s4-16 17-16c13-0 19 17 19 17z"/><style>.svgFallback{display:none}</style></svg>
<div class="username"><span>Rebane</span><span>@rebane2001</span></div><div class="links"><a href="https://twitter.com/rebane2001/status/1909531218816712986" style="--c:/*#179CF0*/#24A4F3" title="Link to Tweet">🐦</a><a href="https://bsky.app/profile/rebane2001.bsky.social/post/3lmc4ax3m7k2y" style="--c:#1889FE" title="Link to Bluesky">🦋</a><a href="https://infosec.exchange/@rebane2001/114301515053488121" style="--c:#5E53ED" title="Link to Toot">🐘</a></div></div>
<div class="content">btw u should write css like
<span role="code">
cool-thing {
    display: flex;
    &[shadow] {
        box-shadow: 1px 1px #0007;
    }<!-- edit: changed screen to width -->
    @media (width &lt; 480px) {
        flex-direction: column;
    }
}
</span>
and html like
<!---->
&lt;cool-thing shadow&gt;wow&lt;/cool-thing&gt;
<!---->
because it's allowed & modern & neat!</div>
<time datetime="2025-04-08T08:58:14.000Z">11:58 AM · Apr 8, 2025</time>
<hr>
<div class="interactions"><span>❤️</span> 1.5K</div>
</twoot-embed></DIV>
<style>
  twoot-embed {
    --size-mult: 1;
    @media (width < 440px) { --size-mult: 0.8; }
    @media (width < 360px) { --size-mult: 0.7; }
    --fg: #0F1419;
    --bg: #FFF;
    --bg-hover: #F7F9F9;
    --dim: #536471;
    --border: #CFD9DE;
    @media (prefers-color-scheme: dark) {
      --fg: #F7F9F9;
      --bg: #15202B;
      --bg-hover: #1E2732;
      --dim: #8B98A5;
      --border: #425364;
    }
    *::selection {
      background: Highlight;
      color: HighlightText;
    }
    color: var(--fg);
    font: calc(var(--size-mult)*19px) -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    border-radius: 12px;
    border: 1px solid var(--border);
    padding: 12px 16px;
    margin-bottom: -8px;
    transition: 0.2s background;
    background: var(--bg);
    &:hover { background: var(--bg-hover); }
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
        background: var(--bg);
        overflow: clip;
        margin-right: 4px;
        cursor: grab;
        transition: 0.2s background, 1s rotate;
        rotate: 0;
        &:hover {
          transition: 0.2s background, 1s 5s rotate;
          background: rgb(127 127 127 / 0.5);
          rotate: 360deg;
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
      .links {
        display: flex;
        gap: 2px;
        margin-left: auto;
        font-size: calc(var(--size-mult)*28px);
        a {
          background: var(--c);
          color: #0002;
          background-clip: text;
          transition: 0.2s background, 0.2s color;
          &:hover {
            background: hsl(from var(--c) h calc(s + 25) calc(l + 10.5));
            color: #0001;
            background-clip: text;
          }
        }
      }
    }
    .content {
      line-height: 1.21053em;
      margin: 12px 0;
      white-space: pre-wrap;
    }
    time {
      font-size: calc(var(--size-mult)*14px);
      color: var(--dim);
      cursor: pointer;
      &:hover {
        text-decoration: underline;
      }
    }
    hr {
      height: 1px;
      background: var(--border);
      border: none;
    }
    .interactions {
      cursor: default;
      font-size: calc(var(--size-mult)*14px);
      font-weight: 700;
      span {
        background: #F91880;
        color: transparent;
        background-clip: text;
      }
    }
  }
</style>

*(yes! the code above is standards compliant[^compliant])*

In the past few years, CSS has received a ton of awesome quality-of-life additions, making it nice to do stuff that has historically required preprocessors or JavaScript.

Nesting is definitely one of my favorite additions!

In the past, you've had to write code that looks like this:

<pre class="sx-block"><code>:<sx-l>root</sx-l> {
  <sx-e>--like-color</sx-e>: <sx-n>#24A4F3</sx-n>;
  <sx-e>--like-color-hover</sx-e>: <sx-n>#54B8F5</sx-n>;
  <sx-e>--like-color-active</sx-e>: <sx-n>#0A6BA8</sx-n>;
}

.<sx-y>post</sx-y> {
  <sx-p>display</sx-p>: <sx-a>block</sx-a>;
  <sx-p>background</sx-p>: <sx-n>#EEE</sx-n>;
  <sx-p>color</sx-p>: <sx-n>#111</sx-n>;
}

.<sx-y>post</sx-y> .<sx-y>avatar</sx-y> {
  <sx-p>width</sx-p>: <sx-n>48px</sx-n>;
  <sx-p>height</sx-p>: <sx-n>48px</sx-n>;
}

.<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> {
  <sx-p>display</sx-p>: <sx-a>flex</sx-a>;
}

.<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> .<sx-y>label</sx-y> {
  <sx-p>font-size</sx-p>: <sx-n>24px</sx-n>;
  <sx-p>padding</sx-p>: <sx-n>8px</sx-n>;
}

.<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> .<sx-y>like</sx-y> {
  <sx-p>cursor</sx-p>: <sx-a>pointer</sx-a>;
  <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color</sx-e>);
}

.<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> .<sx-y>like</sx-y>:<sx-l>hover</sx-l> {
  <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color-hover</sx-e>);
}

.<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> .<sx-y>like</sx-y>:<sx-l>active</sx-l> {
  <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color-active</sx-e>);
}

<sx-z>@media</sx-z> <sx-k>screen</sx-k> (<sx-p>max-width</sx-p>: <sx-n>800px</sx-n>) {
  .<sx-y>post</sx-y> &gt; .<sx-y>buttons</sx-y> .<sx-y>label</sx-y> {
    <sx-p>font-size</sx-p>: <sx-n>16px</sx-n>;
    <sx-p>padding</sx-p>: <sx-n>4px</sx-n>;
  }
}

<sx-z>@media</sx-z> (<sx-x>prefers-color-scheme</sx-x>: <sx-a>dark</sx-a>) {
  .<sx-y>post</sx-y> {
    <sx-p>background</sx-p>: <sx-n>#222</sx-n>;
    <sx-p>color</sx-p>: <sx-n>#FFF</sx-n>;
  }
}
</code></pre>
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
  sx-k { color: #BF67FF; }
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
</style>
And yeah, that's pretty awful to work with. For anything that involves multiple chained selectors, you kind of have to keep a mental map of how every parent selector relates to its children, and the more CSS you add the harder it gets.

But let's try it with nesting:

<pre class="sx-block"><code>:<sx-l>root</sx-l> {
  <sx-e>--like-color</sx-e>: <sx-n>#24A4F3</sx-n>;
  <sx-e>--like-color-hover</sx-e>: <sx-k>hsl</sx-k>(<sx-a>from</sx-a> <sx-k>var</sx-k>(<sx-e>--like-color</sx-e>) <sx-a>h</sx-a> <sx-a>s</sx-a> <sx-k>calc</sx-k>(<sx-a>l</sx-a> + <sx-n>10</sx-n>));
  <sx-e>--like-color-active</sx-e>: <sx-k>hsl</sx-k>(<sx-a>from</sx-a> <sx-k>var</sx-k>(<sx-e>--like-color</sx-e>) <sx-a>h</sx-a> <sx-a>s</sx-a> <sx-k>calc</sx-k>(<sx-a>l</sx-a> - <sx-n>20</sx-n>));
}

.<sx-y>post</sx-y> {
  <sx-p>display</sx-p>: <sx-a>block</sx-a>;
  <sx-p>background</sx-p>: <sx-n>#EEE</sx-n>;
  <sx-p>color</sx-p>: <sx-n>#111</sx-n>;
  <sx-z>@media</sx-z> (<sx-x>prefers-color-scheme</sx-x>: <sx-a>dark</sx-a>) {
    <sx-p>background</sx-p>: <sx-n>#222</sx-n>;
    <sx-p>color</sx-p>: <sx-n>#FFF</sx-n>;
  }
  .<sx-y>avatar</sx-y> {
    <sx-p>width</sx-p>: <sx-n>48px</sx-n>;
    <sx-p>height</sx-p>: <sx-n>48px</sx-n>;
  }
  &amp; &gt; .<sx-y>buttons</sx-y> {
    <sx-p>display</sx-p>: <sx-a>flex</sx-a>;
    .<sx-y>label</sx-y> {
      <sx-p>font-size</sx-p>: <sx-n>24px</sx-n>;
      <sx-p>padding</sx-p>: <sx-n>8px</sx-n>;
      <sx-z>@media</sx-z> (<sx-p>width</sx-p> &lt;= <sx-n>800px</sx-n>) {
        <sx-p>font-size</sx-p>: <sx-n>16px</sx-n>;
        <sx-p>padding</sx-p>: <sx-n>4px</sx-n>;
      }
    }
    .<sx-y>like</sx-y> {
      <sx-p>cursor</sx-p>: <sx-a>pointer</sx-a>;
      <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color</sx-e>);
      &amp;:<sx-l>hover</sx-l> { <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color-hover</sx-e>); }
      &amp;:<sx-l>active</sx-l> { <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--like-color-active</sx-e>); }
    }
  }
}
</code></pre>

That is way nicer to read[^bem]! All the relevant parts are right next to each other, so it's a lot easier to understand what's going on. Seeing the `&:hover` and `&:active` right next to the `.like` button is especially nice imo.

And since you can sort of see the structure - the parent selectors "guarding" the child ones - it also makes it a lot easier to get away with short and simple class names (or even referring to elements themselves).

You may have noticed that I'm also making use of relative colors in the second example. I think the [MDN article](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_colors/Relative_colors) has a lot of awesome examples, but the jist of it is that you can take an existing color, modify it in many different ways across multiple color spaces, and mix it with other colors using [color-mix()](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value/color-mix).

<pre class="sx-block"><code><sx-c>/* remove blue from a color */</sx-c>
<sx-k>rgb</sx-k>(<sx-a>from</sx-a> <sx-n>#123456</sx-n> <sx-a>r</sx-a> <sx-a>g</sx-a> <sx-n>0</sx-n>);
<sx-c>/* make a color transparent */</sx-c>
<sx-k>rgb</sx-k>(<sx-a>from</sx-a> <sx-n>#123456</sx-n> <sx-a>r</sx-a> <sx-a>g</sx-a> <sx-a>b</sx-a> / <sx-n>0.5</sx-n>);
<sx-c>/* make a color lighter */</sx-c>
<sx-k>hsl</sx-k>(<sx-a>from</sx-a> <sx-n>#123456</sx-n> <sx-a>h</sx-a> <sx-a>s</sx-a> <sx-k>calc</sx-k>(<sx-a>l</sx-a> + <sx-n>10</sx-n>));
<sx-c>/* change the hue in oklch color space */</sx-c>
<sx-k>oklch</sx-k>(<sx-a>from</sx-a> <sx-n>#123456</sx-n> <sx-a>l</sx-a> <sx-a>c</sx-a> <sx-k>calc</sx-k>(<sx-a>h</sx-a> + <sx-n>10</sx-n>));
<sx-c>/* mix two colors in oklab color space */</sx-c>
<sx-k>color-mix</sx-k>(<sx-t>in</sx-t> <sx-t>oklab</sx-t>, <sx-n>#8CFFDB</sx-n>, <sx-n>#04593B</sx-n> 25%);
</code></pre>
These snippets are really useful for when you want something to be just ever so slightly darker or brighter, such as a button hover effect or a matching border color, and they're way nicer to use than doing all those color conversions in JavaScript. If you're feeling particularly adventurous, you could even go ahead and generate your entire color scheme in just CSS.

<DIV><color-demo id="color-picker" role="img" aria-label="A color picker written in CSS that lets you pick a color, and generates color swatches of varying brightness, varying hue, and complimentary/secondary colors."><color-bg></color-bg><color-picker><color-result><div><color-style>
<color-swatch monochrome><div>100</div><div>200</div><div>300</div><div>400</div><div>500</div><div>600</div><div>700</div><div>800</div><div>900</div></color-swatch>
<color-swatch analogous><div>-40°</div><div>-20°</div><div>0°</div><div>+20°</div><div>+40°</div></color-swatch>
<color-swatch primary><div>primary</div><div>complimentary</div><div>secondary</div></color-swatch>
<color-swatch success><div>success</div><div>danger</div><div>warning</div><div>info</div></color-swatch>
</color-style></div></color-result><color-point style="width: calc(var(--w) * 0.5px); height: calc(var(--h) * 0.69px);"></color-point><color-indicator></color-indicator></color-picker></color-demo></DIV>
<details style="float:right;width:100%"><summary style="float:right;color:#0078B1;cursor:pointer;list-style:none;font-style:italic">view-source</summary>

<style spellcheck="false" contenteditable="plaintext-only" style="display:block;white-space:pre-wrap;font-family:'Nimbus Mono PS','Courier New',monospace;font-size:12px;padding:8px;background:#263238;color:#EEE;margin-top:24px;border-radius:4px;z-index:1;position:relative;margin-bottom:12px">/* This is editable ^_^ */
@property --cqw {
  syntax: '<length>';
  inherits: true;
  initial-value: 1cqw;
}
@property --cqh {
  syntax: '<length>';
  inherits: true;
  initial-value: 1cqh;
}
@property --vw {
  syntax: '<length>';
  inherits: true;
  initial-value: 100vw;
}
@property --vh {
  syntax: '<length>';
  inherits: true;
  initial-value: 100vh;
}
@property --svh {
  syntax: '<length>';
  inherits: true;
  initial-value: 100svh;
}
@property --dvh {
  syntax: '<length>';
  inherits: true;
  initial-value: 100dvh;
}
@property --lvh {
  syntax: '<length>';
  inherits: true;
  initial-value: 100lvh;
}
/* oklch easter egg */
color-demo:has(color-style:active):not(:has(color-swatch:active)) {
  color-bg {
    background-image: linear-gradient(in oklch to right,
      oklch(75% 100% 0),
      oklch(75% 100% 120deg),
      oklch(75% 100% 240deg),
      oklch(75% 100% 360deg)
    ), linear-gradient(#000, #FFF);
  }
  color-result>div {
    --picked-color: oklch(calc(tan(atan2(var(--cqh), 1px)) / calc(var(--h) / 200)) 100% calc(tan(atan2(var(--cqw), 1px)) / calc(var(--w) / 720)));
  }
}
color-demo, color-picker, color-point, color-result, color-bg {
  display: block;
}
color-demo {
  display: grid;
  grid-template-rows: 1fr;
  grid-template-columns: 1fr;
  container-type: size;
  /*--w: 720;*/
  /*--h: 400;*/
  --w: min(calc(tan(atan2(var(--vw), 1px)) - 48), 768);
  --h: 300;
  width: calc(var(--w) * 1px);
  height:calc(var(--h) * 1px + 324px);
  border-radius: 6px;
  background: #FFF;
  overflow: clip;
  /*
  background:  linear-gradient(in hsl to right,
    hsl(0 100% 50%),
    hsl(120deg 100% 50%),
    hsl(240deg 100% 50%),
    hsl(360deg 100% 50%)
  ), linear-gradient(#000, #FFF);
  background-size: calc(100% - 16px) calc(100% - 16px);
  background-position: center;
  background-repeat: no-repeat;
  background-blend-mode: overlay;
  */
  position: relative;
  color-bg {
    color-scheme: only light;
    grid-area: 1 / 1;
    width: calc(100% - 16px);
    height: calc(var(--h) * 1px - 16px);
    margin: 8px;
    border-radius: 4px;
    background:  linear-gradient(in hsl to right,
      hsl(0 100% 50%),
      hsl(120deg 100% 50%),
      hsl(240deg 100% 50%),
      hsl(360deg 100% 50%)
    ), linear-gradient(#000, #FFF);
    background-position: center;
    background-repeat: no-repeat;
    background-blend-mode: overlay;
    box-shadow: 1px 1px 5px 0 #0002;
  }
  color-picker {
    color-scheme: only light;
    display: grid;
    grid-area: 1 / 1;
    position: relative;
    grid-template-columns: 1fr;
    grid-template-rows: 1fr;
    width:fit-content;
    height:fit-content;
    &>*{
      grid-column: 1; grid-row: 1;
    }
    color-indicator {
      --sw1: 0;
      --sw2: 0;
      --sw3: 0;
      --sw4: 0;
      --sw5: 0;
      --sw6: 0;
      --sw7: 0;
      --sw8: 0;
      --sw9: 0;
    }
    &:has(>color-result color-swatch > :nth-child(1):hover) color-indicator { --sw1: 2px }
    &:has(>color-result color-swatch > :nth-child(2):hover) color-indicator { --sw2: 2px }
    &:has(>color-result color-swatch > :nth-child(3):hover) color-indicator { --sw3: 2px }
    &:has(>color-result color-swatch > :nth-child(4):hover) color-indicator { --sw4: 2px }
    &:has(>color-result color-swatch > :nth-child(5):hover) color-indicator { --sw5: 2px }
    &:has(>color-result color-swatch > :nth-child(6):hover) color-indicator { --sw6: 2px }
    &:has(>color-result color-swatch > :nth-child(7):hover) color-indicator { --sw7: 2px }
    &:has(>color-result color-swatch > :nth-child(8):hover) color-indicator { --sw8: 2px }
    &:has(>color-result color-swatch > :nth-child(9):hover) color-indicator { --sw9: 2px }
    &:has(>color-result color-swatch[analogous]:hover) color-indicator {
      /*filter: drop-shadow(37px 0px 0px #EEE) drop-shadow(0px 20px 0px #EEE);*/
      box-shadow: 0 0 1px 1px #0005 inset, 0 0 0px 1px #0008 inset,
                  0 0 0 var(--sw3) #000,
                  calc(var(--w) * -.111px) 0px 0px var(--sw1) #A4F9,
                  calc(var(--w) * -.055px) 0px 0px var(--sw2) #C2F9,
                  calc(var(--w) * 0.055px) 0px 0px var(--sw4) #F2C9,
                  calc(var(--w) * 0.111px) 0px 0px var(--sw5) #F4A9;
    }
    &:has(>color-result color-swatch[primary]:hover) color-indicator {
      box-shadow: 0 0 1px 1px #0005 inset, 0 0 0px 1px #0008 inset,
                  0 0 0 var(--sw2) #000,
                  calc(var(--w) * -.5px) 0px 0px var(--sw1) #3039,
                  0 0 0 #0000,
                  0 0 0 #0000,
                  calc(var(--w) * 0.5px) 0px 0px var(--sw3) #3039;
    }
    &:has(>color-result color-swatch[monochrome]:hover) color-indicator {
      bottom: calc(100% - 14px - var(--h) * 0.1px);
      outline: 1px solid #0000;
      box-shadow: 0 0 1px 1px #0005 inset, 0 0 0px 1px #0008 inset,
                  0 0 0 var(--sw1) #000,
                  0 calc(var(--h) * 0.1px) 0 var(--sw2) #F6F9,
                  0 calc(var(--h) * 0.2px) 0 var(--sw3) #E5E9,
                  0 calc(var(--h) * 0.3px) 0 var(--sw4) #C4C9,
                  0 calc(var(--h) * 0.4px) 0 var(--sw5) #A3A9,
                  0 calc(var(--h) * 0.5px) 0 var(--sw6) #8289,
                  0 calc(var(--h) * 0.6px) 0 var(--sw7) #4149,
                  0 calc(var(--h) * 0.7px) 0 var(--sw8) #2029,
                  0 calc(var(--h) * 0.8px) 0 var(--sw9) #0009;
    }
    &:has(>color-result color-swatch[success]:hover) color-indicator {
      bottom: calc(100% - 14px - var(--h) * 0.48px);
      right: calc(100% - 14px - var(--w) * 0.0166px);
      outline: 1px solid #0000;
      box-shadow: 0 0 1px 1px #0005 inset, 0 0 0px 1px #0008 inset,
                  0 0 0 var(--sw1) #000,
                  calc(var(--w) * 0.117px) 0 0 var(--sw2) #5529,
                  calc(var(--w) * 0.372px) 0 0 var(--sw3) #2A29,
                  calc(var(--w) * 0.544px) 0 0 var(--sw4) #2289,
                  calc(var(--w) * 0.711px) 0 0 var(--sw5) #0000;
    }
  }
  color-point {
    width: 16px;
    height: 16px;
    background: #0003;
    resize: both;
    overflow: auto;
    max-width: 100cqw;
    max-height: calc(var(--h) * 1px);
    opacity: 0;
    clip-path: polygon(calc(100% - 16px) calc(100% - 16px), calc(100% - 16px) 100%, 100% 100%, 100% calc(100% - 16px));
    /* for mobile support */
    touch-action: none;
  }
  color-indicator {
    display: block;
    position: absolute;
    width: 8px;
    height: 8px;
    border-radius: 16px;
    pointer-events: none;
    border: 2px solid #FFF;
    outline: 1px solid #000;
    box-shadow: 0 0 1px 1px #0005 inset, 0 0 0px 1px #0008 inset;
    transition: box-shadow 0.5s, bottom 0.5s, right 0.5s, outline 0.5s;
    right: 2px;
    bottom: 2px;
    /* make it easier to grab the thing on mobile */
    @media (pointer: coarse) {
      right: -2px;
      bottom: -2px;
    }
  }
  color-result {
    container-type: size;
    width: 100%;
    pointer-events: none;
    &>div {
      --cqw: calc(50cqw);
      --cqh: calc(50cqh);
      --picked-color: hsl(calc(tan(atan2(var(--cqw), 1px)) / calc(var(--w) / 720)) 100% calc(tan(atan2(var(--cqh), 1px)) / calc(var(--h) / 200)));
      --picked-color-hue: calc(tan(atan2(var(--cqw), 1px)) / calc(var(--w) / 720));
      display: flex;
      position: absolute;
      width: calc(var(--w) * 1px);
      height: 400px;
      top: calc(var(--h) * 1px);
    }
  }
  color-style {
    color-scheme: initial;
    /*--background: lch(from var(--picked-color) calc((1 - round(l / 128)) * 255) c h);*/
    --primary: var(--picked-color);
    --primary-contrast: lch(from var(--primary) calc((1 - round(l / 128)) * 255) 0 0);
    --secondary: lch(from var(--primary) l calc(min(255 - c * 10,148 - 100*round(l/100))) var(--picked-color-hue));
    --secondary-contrast: lch(from var(--secondary) calc((1 - round(l / 128)) * 255) 0 0);
    --complimentary: lch(from var(--primary) l c calc(h + 180));
    --complimentary-contrast: lch(from var(--complimentary) calc((1 - round(l / 128)) * 255) 0 0);
    --analogous-a: hsl(from var(--primary) calc(h - 40) s l);
    --analogous-b: hsl(from var(--primary) calc(h - 20) s l);
    --analogous-c: hsl(from var(--primary) calc(h + 20) s l);
    --analogous-d: hsl(from var(--primary) calc(h + 40) s l);
    --success: hsl(from var(--primary) 140deg 70 50%);
    --danger: hsl(from var(--primary) 6deg 76 50%);
    --warning: hsl(from var(--primary) 48deg 83 50%);
    --info: hsl(from var(--primary) 202deg 70 50%);
    --monochrome-100: lch(from var(--primary) 10% c h);
    --monochrome-200: lch(from var(--primary) 20% c h);
    --monochrome-300: lch(from var(--primary) 30% c h);
    --monochrome-400: lch(from var(--primary) 40% c h);
    --monochrome-500: lch(from var(--primary) 50% c h);
    --monochrome-600: lch(from var(--primary) 60% c h);
    --monochrome-700: lch(from var(--primary) 70% c h);
    --monochrome-800: lch(from var(--primary) 80% c h);
    --monochrome-900: lch(from var(--primary) 90% c h);

    --background: lch(from var(--primary) 100% calc(c / 5) h);

    /* https://github.com/system-fonts/modern-font-stacks?tab=readme-ov-file#geometric-humanist */
    font-family: Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif;
    pointer-events: all;
    border: 1px solid color-mix(in hsl, var(--primary), #4444);
    background: var(--background);
    border-radius: 4px;
    margin: 8px;
    display: block;
    height: fit-content;
    width: 100%;
    @media (width < 480px) {
      font-size: 75%;
    }
    @media (width < 360px) {
      font-size: 50%;
    }
    &:not(:has(>color-swatch>div:active)) > color-swatch > div:hover {
      padding-left: 64px;
    }
    color-swatch {
      color-scheme: only light;
      margin: 10px;
      border-radius: 4px;
      overflow: clip;
      color: #000;
      width: calc(100% - 20px);
      height: 64px;
      display: flex;
      box-shadow: 1px 1px 5px 0 #0004;
      >div {
        flex-grow: 1;
        padding: 4px;
        font-weight: 600;
        display: flex;
        justify-content: flex-end;
        align-items: flex-end;
        -webkit-user-select: none;
        user-select: none;
        transition: padding 0.4s, box-shadow 0.4s, scale 0.4s;
        cursor: grab;
        box-shadow: none;
        &:active {
          cursor: grabbing;
          /*padding-left: 32px;*/
          padding-left: 52px;
          box-shadow: 0 0 16px #0005;
          z-index: 10;
        }
        &:last-child {
          margin-right: -1px;
        }
      }
      &[success] {
        color: #FFF;
        >:nth-child(1) { background: var(--success); color: var(--success-contrast); }
        >:nth-child(2) { background: var(--danger); color: var(--danger-contrast); }
        >:nth-child(3) { background: var(--warning); color: var(--warning-contrast); }
        >:nth-child(4) { background: var(--info); color: var(--info-contrast); }
      }
      &[primary] {
        >:nth-child(1) { background: var(--primary); color: var(--primary-contrast); }
        >:nth-child(2) { background: var(--complimentary); color: var(--complimentary-contrast); }
        >:nth-child(3) { background: var(--secondary); color: var(--secondary-contrast); }
      }
      &[monochrome] {
        >:nth-child(-n+5) { color: #FFF; }
        >:nth-child(1) { background: var(--monochrome-100); }
        >:nth-child(2) { background: var(--monochrome-200); }
        >:nth-child(3) { background: var(--monochrome-300); }
        >:nth-child(4) { background: var(--monochrome-400); }
        >:nth-child(5) { background: var(--monochrome-500); }
        >:nth-child(6) { background: var(--monochrome-600); }
        >:nth-child(7) { background: var(--monochrome-700); }
        >:nth-child(8) { background: var(--monochrome-800); }
        >:nth-child(9) { background: var(--monochrome-900); }
      }
      &[analogous] {
        color: var(--primary-contrast);
        >:nth-child(1) { background: var(--analogous-a); }
        >:nth-child(2) { background: var(--analogous-b); }
        >:nth-child(3) { background: var(--primary); }
        >:nth-child(4) { background: var(--analogous-c); }
        >:nth-child(5) { background: var(--analogous-d); }
      }
    }
  }
}
</style>
</details>
<p style="width:fit-content;translate: 0 -12px;margin-right: 80px;"><em>(yes! the color picker above is written in just css)</em></p>
<p class="safari" style="color:red">Safari is currently broken when handling of cqw/cqh units, therefore the demo above may not work correctly. If this happens, try using Firefox or Chrome instead.</p>

There are so many cool new CSS features that make writing it just that little bit nicer. Things like letting you use `(width <= 768px)` instead of `(max-width: 768px)` in your [*@media* query](https://web.dev/articles/media-query-range-syntax), the [lh unit](https://developer.mozilla.org/en-US/docs/Web/CSS/length#lh) that matches the line-height, the [scrollbar-gutter](https://developer.mozilla.org/en-US/docs/Web/CSS/scrollbar-gutter) property that solves the little scrollbar-related layout shifts, or the ability to finally [center stuff vertically](https://web.dev/blog/align-content-block) without flex/grid.

<DIV><art-frame aria-label="Baseline logo" role="img" flex style='user-select:none;width: calc(100% - 64px);padding:32px;justify-content: center;align-items: center;font: 32px var(--inter-stack);line-height: 0;color-scheme:only light'>
<div style="border:8px solid #148936;width:32px;height:32px;border-top:0;border-left:0;rotate:45deg;box-shadow:-8px 0px 0 #FFF inset, 8px 8px 0 #B9D8BF inset;flex:none"></div>
<div style="margin:0 calc(min(5vw,25px)) 0 calc(1px * sqrt(40 * 40 * 2) - 40px - 1px * sqrt(8 * 8 * 2));border-left:8px solid #148936;width:32px;height:40px;rotate:45deg;box-shadow:-8px 8px 0 #B9D8BF inset, 8px 0px 0 #FFF inset, -8px -4px 0 #FFF, 0 -8px 0 #B9D8BF inset;flex:none"></div>Baseline</art-frame></DIV>

And all of this is brought together by the cherry on top that is [Baseline](https://web-platform-dx.github.io/web-features/). It's a guarantee that a specific feature works in every major browser[^baseline], and it also lets you know since when - **newly available** features work in all the latest browsers, and **widely available** ones work in browsers up to 2.5 years old. [Nesting](https://developer.mozilla.org/en-US/docs/Web/CSS/Nesting_selector), for example, has been fully supported in all browsers since December 2023, and thus will become *widely available* in June 2026. You can find the Baseline symbols in various places, such as the MDN docs[^mdnbaseline].

These are just a few examples of what makes modern CSS so much nicer to write than what we had even just 5 years ago. It almost feels like comparing ES3[^es3] to ECMAScript 2025 - and I wouldn't blame your grudge if the former is what you're used to.

## Why bother?

Okay, so CSS has more quality-of-life stuff than before. Still, why would one choose to use it over something else? Doesn't JavaScript already let us do everything just fine?

<DIV><art-frame aria-label="You need to disable JavaScript to run this app" role="img" center style="height: 200px;background:#EEE"><fake-frame style="width:50%;min-width:200px;height:90%;font:initial">You need to <noscript>enable<style>.noJs{display:none}</style></noscript><span class="noJs">disable</span> JavaScript to run this app.</fake-frame></art-frame></DIV>

I think my reasons for using CSS fall into two main categories - because some users don't want to use JavaScript, and because doing things in CSS can be genuinely better.

My blog, for example, focuses on infosec topics. Many security researchers (myself included) use a hardened browser configuration to protect themselves, which often means disabling JavaScript by default. I think it's nice that they can fully experience my blog without changing their security settings or running a separate, sandboxed browser.

The same goes for privacy-conscious users, and it makes sense! As an experiment, I opened up a local Estonian news site in a web browser with JavaScript enabled. Can you guess how many js files it fetched? *(answer in footnote[^newsanswer])* That's crazy! You do not want that running on your computer.

But surely, you are not *one of the evil devs* who loads a double-digit number of analytics scripts on your site - is there still any reason to reach for CSS?

Well, I think a lot of things are just plain nicer to make in HTML/CSS, both from the developer and end-user perspectives, be it for ease of use, accessibility, or performance.

Hover effects for your buttons? Toast animations? Input validation? All of these things *just work* in CSS, and you won't have to reinvent the wheel, or throw kilobytes of someone else's code at it. There will always be some cases where you do need that extra flexibility JavaScript often provides, but if you don't need that, and doing it in CSS is easier, then why not save yourself the trouble?

<DIV><art-frame aria-label="A fun pink button demo with shading, gradient, and shadows." role="figure" style="height: 200px" id="cool-anim">
<art-strs>
  <art-str style="--off:1;--bor:hsl(from #fcc1ff calc(h + 2) s calc(l + 2));top:20px;scale:0.9"></art-str>
  <art-str style="--off:3;--bor:hsl(from #fcc1ff calc(h - 5) s calc(l - 5));top:50px;scale:0.8"></art-str>
  <art-str style="--off:2;--bor:hsl(from #fcc1ff calc(h + 7) s calc(l + 7));top:80px;scale:1.0"></art-str>
  <art-str style="--off:5;--bor:hsl(from #fcc1ff calc(h - 3) s calc(l - 3));top:120px;scale:0.85"></art-str>
  <art-str style="--off:4;--bor:hsl(from #fcc1ff calc(h + 5) s calc(l + 5));top:150px;scale:1.1"></art-str>
  <art-str style="--off:6;--bor:hsl(from #fcc1ff calc(h - 2) s calc(l - 2));top:170px;scale:0.95"></art-str>
  <art-str style="--off:5.5;--bor:hsl(from #fcc1ff calc(h - 2) s calc(l + 2));top:40px;scale:0.95"></art-str>
  <art-str style="--off:3.5;--bor:hsl(from #fcc1ff calc(h + 5) s calc(l + 5));top:160px;scale:1.1"></art-str>
  <art-str style="--off:0.5;--bor:hsl(from #fcc1ff calc(h + 7) s calc(l - 7));top:130px;scale:0.9"></art-str>
  <art-str style="--off:4.5;--bor:hsl(from #fcc1ff calc(h - 3) s calc(l - 3));top:30px;scale:0.85"></art-str>
  <art-str style="--off:1.5;--bor:hsl(from #fcc1ff calc(h + 5) s calc(l + 5));top:140px;scale:1.0"></art-str>
  <art-str style="--off:2.5;--bor:hsl(from #fcc1ff calc(h - 2) s calc(l - 2));top:90px;scale:0.8"></art-str>
</art-strs>
<art-box class="pwWin" style="background:#FBC3FF;--transition-delay:0.1s,0.1s,0.0s,0.1s;left:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 50px);rotate:-3deg"></art-box>
<art-box class="pwWin" style="background:#EEC3FF;--transition-delay:0.2s,0.2s,0.02s,0.2s;left:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 100px);top:34px;rotate:-1deg"></art-box>
<art-box class="pwWin" style="background:#AAC3FF;--transition-delay:0.3s,0.3s,0.04s,0.3s;left:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 160px);rotate:2deg"></art-box>
<art-box class="pwWin" style="background:#BBC3FF;--transition-delay:0.4s,0.4s,0.06s,0.4s;right:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 55px);rotate:2deg;width:192px;"></art-box>
<art-box class="pwWin" style="background:#88C3FF;--transition-delay:0.5s,0.5s,0.08s,0.5s;right:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 65px);rotate:-3deg;width:192px;"></art-box>
<art-box class="pwWin" style="background:#66C3FF;--transition-delay:0.6s,0.6s,0.1s,0.6s;right:calc(50cqw - 384px + max(0px,76px - 10cqw) * 2 + 75px);rotate:-8deg;width:192px;"></art-box>
<art-style>
<style aria-hidden="true" type="text/css">
  @property --bg1 {
    syntax: '<color>';
    inherits: true;
    initial-value: #fbc2ff;
  }
  @property --bg2 {
    syntax: '<color>';
    inherits: true;
    initial-value: #ffe1fd;
  }
  @property --bg3 {
    syntax: '<color>';
    inherits: true;
    initial-value: #ffe1fd;
  }
  @property --bg4 {
    syntax: '<color>';
    inherits: true;
    initial-value: #fad1fb;
  }
  @keyframes tri {
  from {
    translate: 100px -10px;
    rotate: 0deg;
  }
  to {
    translate: -1000px -10px;
    rotate: 180deg;
  }
}
@keyframes art {
  from {
    translate: 100% 0;
    rotate: 20deg;
  }
  to {
    translate: -100% 0;
    rotate: -20deg;
  }
}
@keyframes stl {
  from {
    translate: 0 calc(-100% + 220px);
  }
  to {
    translate: 0 0%;
  }
}
  #cool-anim {
    touch-action: none;
    display: flex;
    justify-content: center;
    align-items: center;
    container-type: inline-size;
    button {
      --bg1: #fbc2ff;
      --bg2: #ffe1fd;
      --bg3: #ffe1fd;
      --bg4: #fad1fb;
      position: relative;
      font-family: var(--inter-stack);
      font-size: 150%;
      cursor: pointer;
      border: none;
      background-clip: border-box;
      background: linear-gradient(var(--bg1), var(--bg2));
      background-size: 110%;
      background-position: center;
      border-radius: 12px;
      outline: 1px solid #19015908;
      box-shadow: 0 2px #ca00ff22, 0 8px 12px #0001, 0 6px 24px 24px #FFF;
      /*
      color: #631980;
      text-shadow: 1px 1px #FFF8;
      */
      color: #FFF6;
      text-shadow: -1px -1px #C692CA; /*#c579cb*/
      z-index: 1;
      padding: 8px 16px;
      padding-right: 15px;
      will-change: transform;
      --ease1: cubic-bezier(0,0,0,1.2);
      --ease2: cubic-bezier(0,0,0,1);
      &:not(:active) {
        --ease1: cubic-bezier(0,0,0,2.5);
      }
      transition: translate 0.4s var(--ease1), box-shadow 0.4s var(--ease1),--bg1 0.3s var(--ease2),--bg2 0.2s var(--ease2),--bg3 0.3s var(--ease2),--bg4 0.2s var(--ease2);
      &::before {
        content: '';
        position: absolute;
        top: 0; right: 0; bottom: 0; left: 0;
        z-index: -1;
        margin: 3px;
        border-radius: 10px;
        background: linear-gradient(var(--bg3), var(--bg4)/*#fbc2ff*/);
        box-shadow: 0 -1px 2px inset #0400ff03;
      }
      &:hover, &:focus-visible {
        --bg1: hsl(from #fbc2ff h s calc(l + 2));
        --bg2: hsl(from #ffe1fd h s calc(l + 2));
        --bg3: hsl(from #ffe1fd h s calc(l + 1));
        --bg4: hsl(from #fad1fb h s calc(l + 1));
      }
      &::after {
        content: '';
        position: absolute;
        top: 0; right: 0; bottom: 0; left: 0;
        border-radius: 12px;
        translate: 0 0.75px;
        transition: translate 0.4s var(--ease1), opacity 0.1s var(--ease2);
        outline: 2px solid #ff62f688;
        outline-offset: 4px;
        opacity: 0;
      }
      &:focus-visible::after {
        opacity: 1;
      }
      &:active {
        &::after { translate: 0 -1.25px }
        translate: 0 2px;
        box-shadow: 0 0 #ca00ff22, 0 6px 12px #0001, 0 6px 24px 24px #FFF;
      }
    }
    &:has(button:active) art-box {
      transform: translateY(15px) scale(0.8) rotate(2deg);
      opacity: 0;
      filter: opacity(1);
      transition: transform 0s 0.15s, opacity 0.15s, filter 0s 0.15s, translate 0s 0.15s, visibility 0s allow-discrete;
    }
    &:has(button:active:not(:hover)):has(art-target:not(:hover)) art-box {
      transition: none;
    }
    art-box {
      position: absolute;
      display: block;
      background: #FBC3FF;
      width: 128px;
      height: 128px;
      border-radius: 8px;
      transform:  translateY(0) scale(1) rotate(0deg);
      opacity: 0.9;
      transition: transform 0.4s cubic-bezier(0,0,0,1.2), opacity 0.4s cubic-bezier(0,0,0,1), filter 2.6s cubic-bezier(0,0,0.5,0.5), translate 0.4s cubic-bezier(0,0,0,1), visibility 0s allow-discrete;
      translate: 0 0px;
      transition-delay: var(--transition-delay);
      filter: opacity(0);
    }
    &:has(button:active) art-target {
      display: block;
    }
    &:not(:has(button:active)) {
      &:has(art-target:hover) art-box {
        transform: translateY(15px) scale(0.8) rotate(2deg);
        opacity: 0;
        filter: opacity(1);
        transition: none!important;
      }
      art-target, art-target:hover {
        visibility: hidden;  
      }
    }
    art-target {
      cursor: pointer;
      &:hover {
        display: block;
      }
      display: none;
      width: 100px;
      height: 45px;
      border-radius: 12px;
      position: absolute;
      z-index:2;
    }
  }
#cool-anim {
  -webkit-user-select: none;
  user-select: none;
  &:not(:has(button:active)) {
    * { animation-play-state: paused; }
    art-str,style { opacity: 0; transition: opacity 0.2s; }
  }
  /*background: #001634;*/
/*  background: #F6EEFF;*/
  background: #FFF;
  position: relative;
  overflow: clip;
  art-str {
    display: block;
    width: 0;
    height: 0;
    border: 16px solid;
    --bor2: hsl(from var(--bor) h s calc(125 - l));
    border-color: var(--bor2) #0000 #0000 var(--bor2);
    position: absolute;
    right: 0;
    box-shadow: 1000px 0 0 var(--bor2);
    transform: scale(0.1) rotate(calc(var(--off) / 6 * 360deg)) scaleX(0.6) rotate(45deg);
    will-change: transform;
    animation: tri 6s ease-out calc(-6s / 6 * var(--off)) infinite;
    opacity: 1;
    transition: opacity 2s 0.5s;
  }
  art-strs {
    display: block;
    /*
    filter: drop-shadow(2px 0 #FFFA) drop-shadow(4px 0 #FFF8) drop-shadow(6px 0 #FFF6) drop-shadow(8px 0 #FFF4)  drop-shadow(10px 0 #FFF2);
    */
  }
  art-style {
    pointer-events: none;
    display: block;
    position: absolute;
    right: 0;
    animation: art 4s ease-out 0s infinite;
    transform-origin: 50% 50%;
    width: 100%;
    height: 100%;
  }
  style {
    text-align: center;
    opacity: 0.2;
    transition: opacity 2s 0.5s;
    display: block;
    font-family: var(--font-code);
/*    letter-spacing: 5px;*/
    /*white-space: pre-wrap;*/
    white-space: pre-line;
    line-height: 220px;
    translate: 0 -10%;
    animation: stl calc(4 * 48s) steps(48, end) -64s infinite;
  }
}</style>
</art-style>
<button>meow</button>
<art-target class="pwWin"></art-target>
</art-frame></DIV>

And the performance of CSS is so much better! Every JavaScript interaction has to go through an event loop that wastes CPU cycles, eats some battery, and adds that tiny bit of stutter to everything.

Sure, in the grand scale of things it isn't *that* bad, APIs like [requestAnimationFrame](https://developer.mozilla.org/en-US/docs/Web/API/Window/requestAnimationFrame) are really good at keeping things smooth. But CSS animations run in the separate compositor thread, and [aren't affected](https://web.dev/articles/animations-and-performance#css_vs_javascript_performance) by stutters and blocking in the event loop.

It makes quite a difference on low-end devices, but feels nice even on high-end ones. CSS animations on my 240hz monitor look amazing[^x3c] - JS can look pretty good too, but it has that tiny bit of stutter to it that keeps it from being perfect, especially if you plan on running other heavy code at the same time.

It also means you won't have to worry as much about optimization, as the browser takes care of a lot more of the rendering side of things, and often runs your stuff on the GPU if possible.

*Pro tip! Wanna trigger animations from JS anyways? Use the modern [Web Animations API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Animations_API/Using_the_Web_Animations_API) to easily play the smooth CSS animations from JS.*

## Transitioning

<!--Speaking of which, let's get to the first show & tell section of the post, where I show you something cool and tell you how it's made.-->
Speaking of which, I think it's time I start showing you practical examples, and a good place to *start* showing the *styles* is well, [*@starting-style*](https://developer.mozilla.org/en-US/docs/Web/CSS/@starting-style).

In the past it has been pretty annoying to add start animations (such as fade-ins) to elements. You've had to either set up an entire CSS animation with a separate *@keyframes* block to go with it, or do a transition using JavaScript where you first add an element to the page, then wait a frame, and then add a class to the element.

<DIV><code-compare aria-label="Demo: A toast message fading in from bottom" role="figure" id="starting-style-toast"><code-frame role=code style="height:150px">.<sx-y>toast</sx-y> {
  <sx-p>transition</sx-p>: <sx-a>opacity</sx-a> <sx-n>1s</sx-n>, <sx-a>translate</sx-a> <sx-n>1s</sx-n>;
  <sx-p>opacity</sx-p>: <sx-n>1</sx-n>;
  <sx-p>translate</sx-p>: <sx-n>0</sx-n> <sx-n>0</sx-n>;
  <sx-z>@starting-style</sx-z> {
    <sx-p>opacity</sx-p>: <sx-n>0</sx-n>;
    <sx-p>translate</sx-p>: <sx-n>0</sx-n> <sx-n>10px</sx-n>;
  }
}</code-frame>
<fake-frame style="height:150px"><span></span><div class="toast">Success!</div><button>replay</button></fake-frame></code-compare></DIV>
<style>
  #starting-style-toast {
    fake-frame {
      font-family: var(--inter-stack);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-direction: column;
    }
    /* make it look nice */
    .toast {
      width: fit-content;
      height: fit-content;
      border: 1px solid #0001;
      border-radius: 6px;
      padding: 6px 12px;
      background: hsl(100deg 100% 95%);
      color: hsl(100deg 100% 15%);
      box-shadow: 2px 2px 8px #00000005;
    }
    /* @starting-style */
    .toast {
      transition: opacity 1s, translate 1s;
      opacity: 1;
      translate: 0 0;
      @starting-style {
        opacity: 0;
        translate: 0 10px;
      }
    }
    /* replay button */
    button {
      font-family: inherit;
      cursor: pointer;
      border: 1px solid #0002;
      border-radius: 4px;
      margin-bottom: 4px;
      background: #F0F0F0;
      &:hover { background: hsl(from #F0F0F0 h s calc(l + 3)); }
      &:active { background: hsl(from #F0F0F0 h s calc(l - 3)); }
    }
    &:has(button:active) .toast {
      /* avoiding @starting-style here for tor browser compatibility */
      display: none;
      opacity: 0;
      translate: 0 10px;
      transition: none;
    }
  }
</style>

But this has all changed thanks to the new *@starting-style* at-rule!

Pretty much all you have to do is set your properties as usual, add the initial transition states to *@starting-style*, and add those properties to a transition. It's pretty simple and it kind of *just works* without having to trigger the animation in any way.

## Lunalover

Another good example of where CSS shines is theming. Many sites *need* separate light and dark modes, and modern CSS makes dealing with that pretty easy.

<DIV><code-compare aria-label="Demo: Various elements affected by theme setting" role="figure" class="uses-theme" id="dark-example-1"><code-frame role=code style="height:100px">:<sx-l>root</sx-l> {
  <sx-p>color-scheme</sx-p>: <sx-a>light</sx-a> <sx-a>dark</sx-a>;
  <sx-e>--text</sx-e>: <sx-k>light-dark</sx-k>(<sx-n>#000</sx-n>, <sx-n>#FFF</sx-n>);
  <sx-e>--bg</sx-e>: <sx-k>light-dark</sx-k>(<sx-n>#EEE</sx-n>, <sx-n>#242936</sx-n>);
}</code-frame>
<fake-frame style="height:100px"><p>hi there!</p><a href="https://karnaboy.bandcamp.com/track/lunalover" style="text-decoration:inherit;color:inherit;margin:8px;cursor:inherit" target="_blank"><button>mystery button</button></a><p>you are awesome!<br><label><input type="checkbox" id="awesome">i am!</label></p></fake-frame></code-compare></DIV>
<style>
  .uses-theme {
    color-scheme: light dark;
  }
  #dark-example-1 {
    --text: light-dark(#000, #FFF);
    --bg: light-dark(#EEE, #242936);
    fake-frame {
      background: var(--bg);
      color: var(--text);
      font-family: var(--inter-stack);
      display: flex;
      align-items: center;
      text-align: center;
      justify-content: space-between;
      flex-direction: column;
      label {
        font-size: 75%;
      }
    }
  }
</style>

By setting the [color-scheme](https://developer.mozilla.org/en-US/docs/Web/CSS/color-scheme) property to `light dark`, you are telling the browser to automatically pick the theme according to the user preference, and you can then make use of that by setting color values with the [light-dark()](https://developer.mozilla.org/en-US/docs/Web/CSS/color_value/light-dark) function.

Not only does it set your own colors, but also those of the native components, such as the default buttons, form elements, and scrollbars. It kind of just [makes stuff work](https://infosec.exchange/@rebane2001/115060623979682479) by default, and that's nice!

<DIV><code-compare aria-label="Demo: Buttons to change theme between auto, light, and dark" role="figure" class="uses-theme" id="dark-example-2"><code-frame role=code style="height:150px">:<sx-l>root</sx-l> {
  <sx-p>color-scheme</sx-p>: <sx-a>light</sx-a> <sx-a>dark</sx-a>;
  &amp;:<sx-l>has</sx-l>(#<sx-a>theme-light</sx-a>:<sx-l>checked</sx-l>) {
    <sx-p>color-scheme</sx-p>: <sx-a>light</sx-a>;
  }
  &amp;:<sx-l>has</sx-l>(#<sx-a>theme-dark</sx-a>:<sx-l>checked</sx-l>) {
    <sx-p>color-scheme</sx-p>: <sx-a>dark</sx-a>;
  }
}</code-frame>
<fake-frame style="height:150px"><theme-picker aria-label="Theme picker" role="radiogroup">
    <label><input type="radio" name="theme" id="theme-auto" checked>Auto</label>
    <label><input type="radio" name="theme" id="theme-light">Light</label>
    <label><input type="radio" name="theme" id="theme-dark">Dark</label>
  </theme-picker></fake-frame></code-compare></DIV>
<style>
  body:has(#theme-light:checked) .uses-theme {
    color-scheme: light;
  }
  body:has(#theme-dark:checked) .uses-theme {
    color-scheme: dark;
  }
  #dark-example-2 {
    --text: light-dark(#000, #FFF);
    --bg: light-dark(#EEE, #242936);
    fake-frame {
      background: var(--bg);
      color: var(--text);
      font-family: var(--inter-stack);
      display: flex;
      justify-content: center;
      align-items: center;
    }
    /* Minimal eye-candy */
    theme-picker {
      display: flex;
      padding: 20px;
      label {
        transition: background 0.08s;
        &:first-child { border-radius: 8px 0 0 8px; }
        &:last-child { border-radius: 0 8px 8px 0; }
        &:has(input:checked) { box-shadow: inset 0px 0px 8px 0px light-dark(#888, #000); }
        &:has(input:focus-visible) { outline: 2px solid light-dark(#000, #FFF); }
        &:hover { background: #0004; }
        &:active { background: #0006; }
        box-shadow: inset 0px 0px 1.2px 0px #000;
        background: #0002;
        padding: 10px;
        cursor: pointer;
        -webkit-user-select: none;
        user-select: none;
      }
      input {
        /* To allow screen reader to still access these. */
        opacity: 0;
        position: absolute;
        pointer-events: none;
      }
    }
  }
</style>

You can then add some way of overriding the *color-scheme* property to let the user pick a theme different from their system setting. Here I am using radio buttons to accomplish that.

*Pro tip! CSS can't save the theme preference, but you can still do progressive enhancement. Make the themes work CSS-only, and then add the saving/loading of preference as an optional extra in JavaScript or server-side code.*

## Lyres and accordions

*"But those don't look like radio buttons"* I hear you cry.

Input elements such as radio buttons and checkboxes are a great foundation to build other stuff on top of - the example above consists of labels for the buttons and invisible radio buttons that can be checked for with the *:checked* pseudo-class.

<DIV><code-compare aria-label="Demo: Making radio buttons look like normal buttons" role="figure" vertical id="radio-example"><code-frame role=code style="min-height:300px"><sx-t>&lt;radio-picker</sx-t> <sx-r>aria-label</sx-r><sx-t>=</sx-t><sx-v>"Radio buttons example"</sx-v> <sx-r>role</sx-r><sx-t>=</sx-t><sx-v>"radiogroup"</sx-v><sx-t>&gt;</sx-t>
  <sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"veni"</sx-v> <sx-r>checked</sx-r><sx-t>&gt;</sx-t>veni<sx-t>&lt;/label&gt;</sx-t>
  <sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"vidi"</sx-v><sx-t>&gt;</sx-t>vidi<sx-t>&lt;/label&gt;</sx-t>
  <sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"vici"</sx-v><sx-t>&gt;</sx-t>vici<sx-t>&lt;/label&gt;</sx-t>
<sx-t>&lt;/radio-picker&gt;</sx-t>
<sx-t>&lt;style&gt;</sx-t>
  <sx-t>radio-picker</sx-t> {
    <sx-p>display</sx-p>: <sx-a>flex</sx-a>;
    <sx-t>label</sx-t> {
      &amp;:<sx-l>has</sx-l>(<sx-t>input</sx-t>:<sx-l>checked</sx-l>) {
        <sx-p>box-shadow</sx-p>: <sx-a>inset</sx-a> <sx-n>0px</sx-n> <sx-n>0px</sx-n> <sx-n>8px</sx-n> <sx-n>0px</sx-n> <sx-n>#888</sx-n>;
      }
      &amp;:<sx-l>has</sx-l>(<sx-t>input</sx-t>:<sx-l>focus-visible</sx-l>) {
        <sx-p>outline</sx-p>: <sx-n>2px</sx-n> <sx-a>solid</sx-a> <sx-n>#000</sx-n>;
      }
      <sx-p>box-shadow</sx-p>: <sx-a>inset</sx-a> <sx-n>0px</sx-n> <sx-n>0px</sx-n> <sx-n>1.2px</sx-n> <sx-n>0px</sx-n> <sx-n>#000</sx-n>;
      <sx-p>padding</sx-p>: <sx-n>10px</sx-n>;
      <sx-p>cursor</sx-p>: <sx-a>pointer</sx-a>;
      <sx-p>background</sx-p>: <sx-n>#0002</sx-n>;
      &amp;:<sx-l>hover</sx-l> { <sx-p>background</sx-p>: <sx-n>#0004</sx-n>; }
      &amp;:<sx-l>active</sx-l> { <sx-p>background</sx-p>: <sx-n>#0006</sx-n>; }
    }
    <sx-t>input</sx-t> {
      <sx-c>/* To allow screen reader to still access these. */</sx-c>
      <sx-p>opacity</sx-p>: <sx-n>0</sx-n>;
      <sx-p>position</sx-p>: <sx-a>absolute</sx-a>;
      <sx-p>pointer-events</sx-p>: <sx-a>none</sx-a>;
    }
  }
<sx-t>&lt;/style&gt;</sx-t>
</code-frame>
<fake-frame style="min-height:150px"><radio-picker aria-label="Radio buttons example" role="radiogroup">
    <label><input type="radio" name="demo1" id="veni1" checked>veni</label>
    <label><input type="radio" name="demo1" id="vidi1">vidi</label>
    <label><input type="radio" name="demo1" id="vici1">vici</label>
  </radio-picker></fake-frame></code-compare></DIV>
<style>
  #radio-example, #tab-example {
    fake-frame {
      background: #EEE;
      color: #000;
      font-family: var(--inter-stack);
      display: flex;
      justify-content: center;
      align-items: center;
    }
    radio-picker {
      display: flex;
      label {
        &:has(input:checked) {
          box-shadow: inset 0px 0px 8px 0px #888;
        }
        &:has(input:focus-visible) {
          outline: 2px solid #000;
        }
        box-shadow: inset 0px 0px 1.2px 0px #000;
        padding: 10px;
        cursor: pointer;
        background: #0002;
        &:hover { background: #0004; }
        &:active { background: #0006; }
      }
      input {
        /* To allow screen reader to still access these. */
        opacity: 0.5;
        position: absolute;
        pointer-events: none;
      }
    }
  }
</style>

This is how I made the theme selector from the previous example. I've made the radio buttons half-visible in the demo for clarity, but with the `opacity: 0` they would not actually be visible.

There's a whole lot going on here, so let's break it down.

<pre class="sx-block"><code><sx-t>&lt;radio-picker</sx-t> <sx-r>aria-label</sx-r><sx-t>=</sx-t><sx-v>"Radio buttons example"</sx-v> <sx-r>role</sx-r><sx-t>=</sx-t><sx-v>"radiogroup"</sx-v><sx-t>&gt;</sx-t>
</code></pre>
We start off with the *radio-picker* element - I just made it up, you can use a div instead if you'd prefer. We give it an aria-label to give the group an accessible name, and the aria role of *radiogroup* to make it work as a group for the radio buttons.

You could also use the [*fieldset*](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/fieldset) element instead of doing the aria roles if that'd fit your use case better.

<pre class="sx-block"><code><sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"veni"</sx-v> <sx-r>checked</sx-r><sx-t>&gt;</sx-t>veni<sx-t>&lt;/label&gt;</sx-t>
<sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"vidi"</sx-v><sx-t>&gt;</sx-t>vidi<sx-t>&lt;/label&gt;</sx-t>
<sx-t>&lt;label&gt;&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"radio"</sx-v> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"demo"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"vici"</sx-v><sx-t>&gt;</sx-t>vici<sx-t>&lt;/label&gt;</sx-t>
</code></pre>
Next, we add the radio buttons with their respective labels - usually you'd have to use the *for* attribute on labels to define which element they're referring to, but since we have the *input* inside the *label* we don't have to do that.

All the `type="radio"` inputs should also have a *name* value set to the same thing so that they are grouped together (you still need[^fieldset] the radiogroup though). And then you can give them values or ids however you want.

<pre class="sx-block"><code><sx-t>label</sx-t> {
  &amp;:<sx-l>has</sx-l>(<sx-t>input</sx-t>:<sx-l>checked</sx-l>) {
    <sx-p>box-shadow</sx-p>: <sx-a>inset</sx-a> <sx-n>0px</sx-n> <sx-n>0px</sx-n> <sx-n>8px</sx-n> <sx-n>0px</sx-n> <sx-n>#888</sx-n>;
  }
  &amp;:<sx-l>has</sx-l>(<sx-t>input</sx-t>:<sx-l>focus-visible</sx-l>) {
    <sx-p>outline</sx-p>: <sx-n>2px</sx-n> <sx-a>solid</sx-a> <sx-n>#000</sx-n>;
  }
  <sx-p>box-shadow</sx-p>: <sx-a>inset</sx-a> <sx-n>0px</sx-n> <sx-n>0px</sx-n> <sx-n>1.2px</sx-n> <sx-n>0px</sx-n> <sx-n>#000</sx-n>;
  <sx-p>padding</sx-p>: <sx-n>10px</sx-n>;
  <sx-p>cursor</sx-p>: <sx-a>pointer</sx-a>;
  <sx-p>background</sx-p>: <sx-n>#0002</sx-n>;
  &amp;:<sx-l>hover</sx-l> { <sx-p>background</sx-p>: <sx-n>#0004</sx-n>; }
  &amp;:<sx-l>active</sx-l> { <sx-p>background</sx-p>: <sx-n>#0006</sx-n>; }
}
</code></pre>
We then style the labels as we wish - the *:hover* and *:active* pseudo-classes can be used to make the buttons more fun to click, the *:has(input:checked)* selector can be used to define the style of the selected button, and the *:has(input:focus-visible)* selector can be used to add an outline when someone tabs over to the button.

The difference between *:focus* and *:focus-visible* is that the former shows up even if you use your mouse, while the latter only shows up when you use keyboard navigation, so it's often visually more clean to use the latter.

<pre class="sx-block"><code><sx-t>input</sx-t> {
  <sx-p>opacity</sx-p>: <sx-n>0</sx-n>;
  <sx-p>position</sx-p>: <sx-a>absolute</sx-a>;
  <sx-p>pointer-events</sx-p>: <sx-a>none</sx-a>;
}
</code></pre>
And last, we make the radio button input *exist* while not being visible. This is a bit hacky, but it's how you can keep this control accessible to keyboard navigation and screen readers.

And that's how we get the cool-looking radio buttons!

<DIV><code-compare vertical id="tab-example"><code-frame role=code style="min-height:200px"><sx-t>&lt;radio-tabs&gt;</sx-t>
  <sx-t>&lt;div</sx-t> <sx-r>tabindex</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"tab-veni"</sx-v><sx-t>&gt;</sx-t>veni...<sx-t>&lt;/div&gt;</sx-t>
  <sx-t>&lt;div</sx-t> <sx-r>tabindex</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"tab-vidi"</sx-v><sx-t>&gt;</sx-t>vidi...<sx-t>&lt;/div&gt;</sx-t>
  <sx-t>&lt;div</sx-t> <sx-r>tabindex</sx-r><sx-t>=</sx-t><sx-v>0</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"tab-vici"</sx-v><sx-t>&gt;</sx-t>vici...<sx-t>&lt;/div&gt;</sx-t>
<sx-t>&lt;/radio-tabs&gt;</sx-t>
<sx-t>&lt;style&gt;</sx-t>
  <sx-t>body</sx-t>:<sx-l>has</sx-l>(#<sx-a>veni</sx-a>:<sx-l>not</sx-l>(:<sx-l>checked</sx-l>)) #<sx-a>tab-veni</sx-a>,
  <sx-t>body</sx-t>:<sx-l>has</sx-l>(#<sx-a>vidi</sx-a>:<sx-l>not</sx-l>(:<sx-l>checked</sx-l>)) #<sx-a>tab-vidi</sx-a>,
  <sx-t>body</sx-t>:<sx-l>has</sx-l>(#<sx-a>vici</sx-a>:<sx-l>not</sx-l>(:<sx-l>checked</sx-l>)) #<sx-a>tab-vici</sx-a> {
    <sx-p>display</sx-p>: <sx-a>none</sx-a>;
  }
<sx-t>&lt;/style&gt;</sx-t></code-frame>
<fake-frame style="min-height:150px"><div><radio-picker aria-label="Tabs example" role="radiogroup">
    <label><input type="radio" name="demo2" id="veni" checked>veni</label>
    <label><input type="radio" name="demo2" id="vidi">vidi</label>
    <label><input type="radio" name="demo2" id="vici">vici</label>
</radio-picker>
<radio-tabs>
  <div id="tab-veni" tabindex=0><strong>veni</strong><br><em>/ˈveɪni/</em><br>(intransitive) to come</div>
  <div id="tab-vidi" tabindex=0><strong>vidi</strong><br><em>/ˈviːdi/</em><br>(intransitive) to see</div>
  <div id="tab-vici" tabindex=0><strong>vici</strong><br><em>/ˈviːt͡ʃi/</em><br>(intransitive) to conquer</div>
</radio-tabs></div></fake-frame></code-compare></DIV>
<style>
  #tab-example {
    fake-frame {
      flex-direction: column;
      radio-picker input {
        opacity: 0;
      }
    }
  }
radio-tabs {
  display: flex;
  width: calc(240px - 16px);
  height: calc(80px - 16px);
  padding: 8px;
  box-shadow: inset 0px 0px 1.2px 0px #000;
  margin-top: -1px;
}
body:has(#veni:not(:checked)) #tab-veni,
body:has(#vidi:not(:checked)) #tab-vidi,
body:has(#vici:not(:checked)) #tab-vici {
  display: none;
}
</style>

We can now use them in the CSS however we want by just seeing if they're *:checked*. Here I made tabs with separate divs for the content by using a *:has* selector on a parent element to find out which radio button is currently selected.

The *:has* selector has to be on a parent element that contains both the radio button and the target element - you can simply use *html* or *body* if you want it to work across the entire page. You should **never** use something like <code style="color:#d30000">:has(...)</code> by itself as it'll run the selector for every element of the page, which can cause performance issues (<code style="color:#0e8d00">body:has(...)</code> is okay).

<DIV><code-compare aria-label="Demo: Details elements in an FAQ format" role="figure" id="details-example"><code-frame role=code style="height:520px"><sx-t>&lt;div&gt;</sx-t>
  <sx-t>&lt;details</sx-t> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"deets"</sx-v><sx-t>&gt;</sx-t>
    <sx-t>&lt;summary&gt;</sx-t>What's your name?<sx-t>&lt;/summary&gt;</sx-t>
    My name is Lyra Rebane.
  <sx-t>&lt;/details&gt;</sx-t>
  <sx-t>&lt;details</sx-t> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"deets"</sx-v><sx-t>&gt;</sx-t>
    ...
  <sx-t>&lt;/details&gt;</sx-t>
<sx-t>&lt;/div&gt;</sx-t>
<sx-t>&lt;style&gt;</sx-t>
  <sx-t>div</sx-t> {
    <sx-p>border</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-n>#AAA</sx-n>;
    <sx-p>border-radius</sx-p>: <sx-n>8px</sx-n>;
    <sx-c>/* based on the MDN example */</sx-c>
    <sx-t>summary</sx-t> {
      <sx-p>font-weight</sx-p>: <sx-a>bold</sx-a>;
      <sx-p>margin</sx-p>: <sx-n>-0.5em</sx-n> <sx-n>-0.5em</sx-n> <sx-n>0</sx-n>;
      <sx-p>padding</sx-p>: <sx-n>0.5em</sx-n>;
      <sx-p>cursor</sx-p>: <sx-a>pointer</sx-a>;
    }
    <sx-t>details</sx-t> {
      &amp;:<sx-l>last-child</sx-l> { <sx-p>border</sx-p>: <sx-a>none</sx-a> }
      <sx-p>border-bottom</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-n>#aaa</sx-n>;
      <sx-p>padding</sx-p>: <sx-n>0.5em</sx-n> <sx-n>0.5em</sx-n> <sx-n>0</sx-n>;
      &amp;[<sx-r>open</sx-r>] {
        <sx-p>padding</sx-p>: <sx-n>0.5em</sx-n>;
        <sx-t>summary</sx-t> {
          <sx-p>border-bottom</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-n>#aaa</sx-n>;
          <sx-p>margin-bottom</sx-p>: <sx-n>0.5em</sx-n>;
        }
      }
    }
  }
<sx-t>&lt;/style&gt;</sx-t></code-frame>
<fake-frame style="min-height:180px">
  <div>
    <!-- for some reason, the name thing doesn't work in tor browser -->
    <details name="deets"><summary>What's your name?</summary>My name is Lyra Rebane.</details>
    <details name="deets"><summary>Cool name!</summary>I know ^_^</details>
    <details name="deets"><summary>Where can I learn more?</summary>On my website, <a href="https://lyra.horse/">lyra.horse</a>!</details>
  </div>
</fake-frame></code-compare></DIV>
<style>
  #details-example {
fake-frame {
  display: flex;
  justify-content: center;
  align-items: flex-start;
}
fake-frame > div {
  display: flex;
  flex-direction:column;
  border: 1px solid #AAA;
  margin-top: 16px;
  border-radius: 8px;
  width: 300px;
  max-width: 90%;
}
/* based on the MDN example */
details {
  &:last-child { border: none }
  border-bottom: 1px solid #aaa;
  padding: 0.5em 0.5em 0;
}
summary {
  font-weight: bold;
  margin: -0.5em -0.5em 0;
  padding: 0.5em;
  cursor: pointer;
}
details[open] {
  padding: 0.5em;
}
details[open] summary {
  border-bottom: 1px solid #aaa;
  margin-bottom: 0.5em;
}
  }
</style>

Finally, before we move on, I want to give you a quick introduction to the [details](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/details) element. It's great for if you want an accordion-style menu, such as for a FAQ section. The details open and close independently of each other, but you can set their name attribute to the same value to have only one open at a time.

Using them is pretty easy, put your content and a *summary* tag inside a *details* tag, and put the title inside the *summary* tag. The example above is a bit more convoluted for the visual flair, but all you *really* need is the html part of it.

The details elements are pretty stylable! You can add animations depending on the *[open]* state, and you can also get rid of the arrow by setting `list-style: none` on the *summary*.

Also, ctrl+f works with it, which is a big win in my book!

## Validation

And lastly, I want to show you the power of input validation in HTML and CSS.

<DIV><code-compare aria-label="Demo: Input validation" role="figure" vertical id="validation-example-1"><code-frame role=code><sx-t>&lt;label</sx-t> <sx-r>for</sx-r><sx-t>=</sx-t><sx-v>"usrname"</sx-v><sx-t>&gt;</sx-t>Username<sx-t>&lt;/label&gt;</sx-t>
<sx-t>&lt;input</sx-t> <sx-r>type</sx-r><sx-t>=</sx-t><sx-v>"text"</sx-v> <sx-r>id</sx-r><sx-t>=</sx-t><sx-v>"usrname"</sx-v> <sx-r>pattern</sx-r><sx-t>=</sx-t><sx-v>"\w{3,16}"</sx-v> <sx-r>required</sx-r><sx-t>&gt;</sx-t>
<sx-t>&lt;small&gt;</sx-t>3-16 letters, only alphanum and _.<sx-t>&lt;/small&gt;</sx-t>
<sx-t>&lt;style&gt;</sx-t>
 <sx-t>input</sx-t>:<sx-l>valid</sx-l> {
   <sx-p>border</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-a>green</sx-a>;
 }
 <sx-t>input</sx-t>:<sx-l>invalid</sx-l> {
   <sx-p>border</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-a>red</sx-a>;
 }
<sx-t>&lt;/style&gt;</sx-t></code-frame>
<fake-frame style="min-height:128px">
  <div>
    <label for="usrname">Username</label>
    <input type="text" id="usrname" pattern="\w{3,16}" required>
    <small>3-16 letters, only alphanum and _.</small>
  </div>
</fake-frame></code-compare></DIV>
<style>
#validation-example-1 {
  fake-frame {
    display: flex;
    justify-content: center;
    align-items: center;
    & > div {
      display: flex;
      flex-direction: column;
    }
    input {
      outline-offset: 2px;
    }
    input:valid {
      border: 1px solid green;
    }
    input:invalid {
      border: 1px solid red;
    }
  }
}
</style>

This is a simple example of how you can validate an input field with a regex pattern. If you set a *pattern* attribute like above, a form that contains the input cannot be submitted unless the field matches the pattern. If you're submitting something like [an e-mail address](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input/email), [a phone number](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input/tel), or [a url](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/input/url), it might make sense to use the respective input types instead of writing your own regex.

Now, where CSS comes in is styling the input to show whether its value is valid. In the example above, I'm using *:valid* and *:invalid* to set a border color, but that comes with the downside of *always* having your input marked, even if the user hasn't entered anything yet.

<DIV><code-compare aria-label="Demo: Input validation" role="figure" id="validation-example-2"><code-frame role=code><sx-t>input</sx-t> {
  <sx-p>border</sx-p>: <sx-a>none</sx-a>;
  <sx-p>border-radius</sx-p>: <sx-n>2px</sx-n>;
  <sx-p>outline</sx-p>: <sx-n>1px</sx-n> <sx-a>solid</sx-a> <sx-n>#000</sx-n>;
  &amp;:<sx-l>focus</sx-l> { <sx-p>outline-width</sx-p>: <sx-n>2px</sx-n>; }
  &amp;:<sx-l>user-valid</sx-l> { <sx-p>outline-color</sx-p>: <sx-a>green</sx-a>; }
  &amp;:<sx-l>user-invalid</sx-l> { <sx-p>outline-color</sx-p>: <sx-a>red</sx-a>; }
}</code-frame>
<fake-frame style="min-height:128px">
  <div>
    <label for="usrname2">Username</label>
    <input type="text" id="usrname2" pattern="\w{3,16}" required>
    <small>3-16 letters, only alphanum and _.</small>
  </div>
</fake-frame></code-compare></DIV>
<style>
#validation-example-2 {
  fake-frame {
    display: flex;
    justify-content: center;
    align-items: center;
    & > div {
      display: flex;
      flex-direction: column;
    }
    input {
      border: none;
      border-radius: 2px;
      outline: 1px solid #000;
      &:focus { outline-width: 2px; }
      &:user-valid { outline-color: green; }
      &:user-invalid { outline-color: red; }
    }
  }
}
</style>

An easy win here is to instead use *:user-valid* and *:user-invalid* - these pseudo-classes only become active once you've interacted with input field. I also made this example use an outline instead of a border, which I think looks a lot nicer.

It may sometimes even make sense to use a combination of *:valid* and *:user-invalid*.

And of course, you can use the *:has* selector to style other elements depending on the input too!

<DIV><code-compare aria-label="Demo: Specific requirements password challenge for fun" role="figure" id="validation-example-3">
<fake-frame style="min-height:128px">
  <div>
    <label for="paswd">Password</label>
    <input type="password" id="paswd" data-disabled-maxlength="16" pattern="^(?=.*\p{Nl}).{8,15}\P{L}$" required="">
    <small>The password must:<br>
- be 8-16 characters<br>
- contain at least ⅰ roman numeral<br>
- not end with a letter<br>
</small>
  </div>
</fake-frame></code-compare></DIV>
<style>
#validation-example-3 {
  fake-frame {
    display: flex;
    justify-content: center;
    align-items: center;
    & > div {
      display: flex;
      flex-direction: column;
    }
    input {
      border: none;
      border-radius: 2px;
      outline: 1px solid #000;
      &:focus { outline-width: 2px; }
      &:valid { outline-color: green; }
      &:user-invalid { outline-color: red; }
    }
  }
}
body:not(:has(#validation-example-3 input:valid)) .pwWin { display:none; }
</style>

<p>This one's just for fun ^_-! <span class="pwWin" title="you've now unlocked a scrapped animation in the button thing!">you win! yay<a href="#cool-anim">!</a></span></p>

I do want to mention that for some stuff, such as date pickers <no-wrap>(<input name=date style=width:100px type=date>)</no-wrap> or datalists <no-wrap>(<input name=ponies list=ponies style=width:50px placeholder=pony>)</no-wrap>, there are built-in elements that do the job, but you may find them limited in one way or the other. If you're making an input like that with specific requirements, you may still need to dip your feet in a bit of JavaScript.

<datalist id="ponies">
  <option value="Twilight Sparkle"></option>
  <option value="Pinkie Pie"></option>
  <option value="Fluttershy"></option>
  <option value="Rainbow Dash"></option>
  <option value="Rarity"></option>
  <option value="Lyra Heartstrings"></option>
  <option value="Bonbon"></option>
  <option value="DJ Pon-3"></option>
  <option value="Octavia"></option>
  <option value="Colgate"></option>
  <option value="Carrot Top"></option>
  <option value="Berry Punch"></option>
  <option value="Derpy Hooves"></option>
  <option value="Dr. Hooves"></option>
  <option value="Jasmine Leaf"></option>
</datalist>

<!--
## Container queries
-->

## Do not the vw/vh

This section is kind of random but I wanted to include it here because I think a lot of people are messing this one up and I want more people to know how to do this stuff right.

So CSS has vw/vh units that correspond to 1% of the viewport width and height respectively, which makes perfect sense for desktop browsers.

<style>
/*
 * found a css issue in chrome while making this phone lol
 * https://issues.chromium.org/issues/440613173
 */
epic-phone {
  flex-shrink: 0;
  display: flex;
  width: 256px;
  height: 500px;
  background: #000;
  border-radius: 24px;
  border:4px inset #444;
  phone-screen {
    display: flex;
    flex-direction: column;
    border:2px inset #222;
    border-radius: 20px;
    min-width: 10px;
    min-height: 10px;
    background: #FFF;
    overscroll-behavior-y: none;
    overflow: clip;
    flex: 1;
    phone-navbar, phone-notifications {
      font-family: var(--inter-stack);
    }
    phone-navbar {
      color-scheme: only light;
      touch-action: none;
      cursor: row-resize;
      &:active { cursor: grabbing; }
      -webkit-user-select: none;
      user-select:none;
      font-weight: 600;
      font-size: 12px;
      font-size-adjust: ex-height 0.545;
      padding: 3px 10px 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
      height:26px;
      background:#121316;
      color:#FFF;
      span[data-battery] {
        background: #FFF;
        background: linear-gradient(90deg, #FFF 75%, #FFF9 75.01%);
        color: #121316;
        border-radius: 16px;
        padding: 0 4px;
      }
    }
    @media (pointer: coarse) {
      &:has(phone-navbar:hover, phone-navbar:active) phone-notifications {
        transition: 0.2s opacity;
        opacity: 1;
        display: flex;
        &>div {
          margin-top: 7px;
          opacity: 1;
          @starting-style {
            margin-top: -4px;
            opacity: 0;
          }
        }
        @starting-style {
         opacity: 0;
        }
      }
    }
    &:hover:has(phone-navbar:active:not(:hover)) phone-notifications {
      transition: 0.2s opacity;
      opacity: 1;
      display: flex;
      &>div {
        margin-top: 7px;
        opacity: 1;
        @starting-style {
          margin-top: -4px;
          opacity: 0;
        }
      }
      @starting-style {
       opacity: 0;
      }
    }
    phone-notifications {
      transition: 0s 0.2s display allow-discrete, 0.2s opacity;
      opacity: 0;
      -webkit-user-select: none;
      user-select: none;
      display: none;
      flex-direction: column;
      align-items: center;
      position: absolute;
      background: #0009;
      backdrop-filter: blur(4px);
      width: 100%;
      top: 29px;
      height: calc(100% - 29px);
      z-index: 10;
      color: #FFF;
      &>div {
        display: flex;
        align-items: center;
        --h: 0;
        &:nth-child(1) { --h: 0; }
        &:nth-child(2) { --h: 60; }
        &:nth-child(3) { --h: 120; }
        &:nth-child(4) { --h: 180; }
        &:nth-child(5) { --h: 240; }
        &:nth-child(6) { --h: 300; }
        &:nth-child(7) { --h: 340; }
        &>span {
          flex-shrink: 0;
          height: 32px;
          width: 32px;
          border-radius: 28px;
          margin: 8px;
          line-height: 32px;
          text-align: center;
          background: hsl(from #F6D2EC calc(h + var(--h)) s l);
          color: hsl(from #7B1C66 calc(h + var(--h)) s l);
        }
        &>div {
          &>div {
            font-size: 12px;
            font-weight: 500;
          }
          font-size: 10px;
          margin-top: -2px;
        }
        margin-top: -4px;
        background: #0009;
        width: 90%;
        height: 48px;
        border-radius: 40px;
        transition: 0.2s margin-top, 0.2s opacity;
        @starting-style {
          margin-top: -4px;
        }
      }
    }
    phone-content {
      display: block;
      flex: 1;
      overflow-y: auto;
      scrollbar-width: none;
      ul {
        margin: 0;
        padding: 0;
        li {
          display: inline;
          a {
            color: #4f4f63;
          }
        }
      }
    }
    phone-urlbar {
      color: #E3E2E6;
      position: relative;
      display: flex;
      height: 34px;
      width: calc(100% - 12px);
      padding: 6px;
      font-family: system-ui, sans-serif;
      transition: background 0.4s;
      background: #121316;
      font-size: 12px;
      align-items: center;
      gap: 8px;
      phone-urlbar-inner {
        height: 34px;
        border-radius: 17px;
        width: 100%;
        transition: background 0.2s, border-radius 0.2s, font-size 0.4s;
        display: flex;
        align-items: center;
        background: #313745;
        color: #C4C6D0;
        &:hover {
          background: #191C21;
          border-radius: 8px;
        }
        ::selection {
          color: #E3E2E6;
          background-color: #373E4D;
        }
        svg {
          width: 16px;
          height: 16px;
          fill: #E3E2E6;
          background: #0000;
          margin: 5px;
          padding: 4px;
          padding-left: 1px;
          position: absolute;
          display:block;
          border-radius: 24px;
        }
        & > span {
          text-overflow: ellipsis;
          overflow:hidden;
          white-space:nowrap;
          display:inline-block;
          margin-left:26px;
          & > span {
            color: #E3E2E6;
          }
        }
      }
    }
  }
}
clickbait-circle {
  display: block;
  position: absolute;
  width: 48px;
  height: 48px;
  border: 4px solid #cb6801;
  border-radius: 128px;
  z-index: 5;
  pointer-events: none;
}
smol-arrow {
  pointer-events: none;
  position: absolute;
  z-index: 5;
  width: 10px;
  height: 10px;
  display: block;
  border: 4px solid;
  border-width: 3px 3px 0 0;
  rotate: -45deg;
  translate: 4px 4px;
  &[down] {
    rotate: 135deg;
    translate: 4px -4px;
  }
  &[line] {
    border-width: 0 3px 0 0;
    translate: -1px 2px;
    rotate: 0deg;
  }
}
</style>

<div style="display:flex;flex-wrap: wrap;justify-content:center;gap:24px">
<epic-phone aria-label="A phone displaying a web page cut off from the top and bottom" role="figure"><phone-screen style="position:relative"><phone-navbar aria-hidden=true><span>•</span><span data-battery>75</span></phone-navbar>
<!--
<clickbait-circle style="top:46px;left:134px;scale:1.25 0.75"></clickbait-circle>
<clickbait-circle style="bottom:-3px;left:70px;scale:1.75 0.75"></clickbait-circle>
-->
<phone-notifications>
  <div><span>CB</span><div><div>Signal chat</div>Are you feeling encrypted?</div></div>
  <div><span>M</span><div><div>Marat</div>it smells of onions in here...</div></div>
  <div><span>bm</span><div><div>blackle mori</div>what's the scoop in yer smacker, horseberry?</div></div>
  <div><span>R</span><div><div>Rhynorater</div>CSS go BRRRRR</div></div>
  <div><span>P</span><div><div>PatTheHyruler</div>I just lost the game</div></div>
  <div><span>M</span><div><div>Malk</div>I can't wait to taste the sorbet!</div></div>
</phone-notifications>
<phone-content style="position:relative;background:hsl(from #8CFFDB h calc(s - 30) calc(l))">
<phone-urlbar aria-label="URL bar" role="figure" style="position:absolute;z-index: 1"><phone-urlbar-inner><div class="svgFallback" style="position:absolute;translate: 8px 0;">🔒</div><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"></path></svg><span><span>lyra.horse</span>/blog/</span></phone-urlbar-inner><!--<div style="border-radius:6px;border: 2px solid;width:15px;height:12px;font-size:9px;user-select:none;text-align: center;font-weight:600;line-height: 12px;">:D</div>--><a href="https://youtu.be/7zbNBCb_AOU
" style="rotate:90deg;user-select:none;margin:0 4px 0 2px;color:inherit" target=_blank>•••</a></phone-urlbar>
<div style="height:32px"></div>
<div style="font-family: Bahnschrift, 'DIN Alternate', 'Franklin Gothic Medium', 'Nimbus Sans Narrow', sans-serif-condensed, sans-serif;font-size: 20px;font-weight: bold;border-bottom: 1px solid #222"><ul><li><a href="/blog/" style="color:#007A1B" target=_blank>lyra's epic blog</a></li> <li><a href="/blog/posts/" target=_blank>posts</a></li> <li><a href="/blog/tags/" target=_blank>tags</a></li></ul></div>
<p style="font-family:var(--font-head);color:#04593b;margin:0;text-align:center;font-size:120%">You no longer need JavaScript</p>
<p style="font-size:75%;margin:0 16px">yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap yap</p>
</phone-content>
<div style="background:#FFF;height:32px"></div>
</phone-screen></epic-phone>
</div>

Where it becomes a bit more nuanced is on mobile devices. For example, mobile versions of both Firefox and Chrome will hide the URL bar when scrolling down on a page.

This causes the vw/vh units to be a bit ambigous - do they represent the *entire* available screen, only the area that's visible with the URL bar, or something in between?

If it's the first option, you might end up with buttons or links off-screen[^hr]! If it's the second, you may end up with a background div that doesn't cover the entire background.

<style>

  @property --minutes {
    syntax: '<integer>';
    inherits: true;
    initial-value: 0;
  }
  @keyframes minutes {
    from {
      --minutes: 0;
    }
    to {
      --minutes: 60;
    }
  }
  phone-navbar > :first-child {
    --minutes: 0;
    animation: 3600s steps(60, jump-end) infinite minutes;
    animation-fill-mode: forwards;
    animation-delay: -2222s;
    &::before {
      --d1: round(down, var(--minutes) / 10, 1);
      --d2: mod(var(--minutes),10);
      counter-reset: d1 var(--d1) d2 var(--d2);
      content: "13:" counter(d1) counter(d2) " ";
    }
  }
  phone-content {
    &:has(.scroll-up:active) {
      scroll-behavior: smooth;
      scroll-snap-type: y mandatory;
      phone-urlbar {
        scroll-snap-align: start;
      }
    }
    &:has(.scroll-down:active) {
      scroll-behavior: smooth;
      scroll-snap-type: y mandatory;
      .scroll-up {
        scroll-snap-align: end;
      }
    }
    .scroll-btn {
      display: none;
      border-radius: 16px;
      text-align: center;
      rotate: 90deg;
      line-height: 12px;
      width: 24px;
      height: 24px;
    }
    table {
      border-collapse: collapse;
      border: 2px solid #888;
      th,td {
        border: 1px solid #AAA;
        padding: 8px 10px;
      }
    }
  }
  unit-value {
    --vhi: tan(atan2(var(--vh), 1px));
    --lvhi: tan(atan2(var(--lvh), 1px));
    --dvhi: tan(atan2(var(--dvh), 1px));
    --svhi: tan(atan2(var(--svh), 1px));
    &[vh]::after {
      counter-reset: vhi var(--vhi);
      content: counter(vhi);
    }
    &[lvh]::after {
      counter-reset: lvhi var(--lvhi);
      content: counter(lvhi);
    }
    &[dvh]::after {
      counter-reset: dvhi var(--dvhi);
      content: counter(dvhi);
    }
    &[svh]::after {
      counter-reset: svhi var(--svhi);
      content: counter(svhi);
    }
  }
</style>


<div style="display:flex;flex-wrap: wrap;justify-content:center;gap:24px">
<epic-phone aria-label="A phone displaying the differences between the svh, dvh, and lvh units" role="figure" style="position:relative"><phone-screen style="position:relative"><phone-navbar aria-hidden=true><span>•</span><span data-battery>75</span></phone-navbar>
<phone-notifications>
  <div><span style="line-height: 28px">p</span><div><div>pingotux</div>css spec so good i transitioned</div></div>
  <div><span style="line-height: 30px">m</span><div><div>maya</div>hi wife!!</div></div>
  <div><span>Z</span><div><div>Zvit</div>lol. lmao, sogar.</div></div>
  <div><span>!!</span><div><div>!! HAND !!</div>yap yap yap</div></div>
  <div><span>J</span><div><div>Jones</div>Glory to KuK</div></div>
  <div><span>S</span><div><div>Spax</div>im goop</div></div>
  <div><span>e</span><div><div>enscribe</div>I need a job</div></div>
</phone-notifications>
<div style="pointer-events:none;user-select:none">
  <p style="position:absolute;z-index:3;translate:calc(100% + 2px) 0;right:24px;color:red;top:100px;">lvh</p>
  <p style="position:absolute;z-index:3;translate:calc(100% + 2px) 0;right:64px;color:orange;top:90px;">dvh</p>
  <p style="position:absolute;z-index:3;translate:calc(100% + 2px) 0;right:104px;color:green;top:80px;">svh</p>
</div>
<smol-arrow style="right:24px;color:red;top:28px;"></smol-arrow>
<smol-arrow style="right:24px;color:red;top:30px;height:460px" line></smol-arrow>
<smol-arrow style="right:24px;color:red;bottom:-1px" down></smol-arrow>
<smol-arrow style="right:64px;color:orange;z-index:1;top:28px;"></smol-arrow>
<smol-arrow style="right:64px;color:orange;z-index:1;top:30px;height:460px" line></smol-arrow>
<smol-arrow style="right:64px;color:orange;bottom:-1px" down></smol-arrow>
<smol-arrow style="right:104px;color:green;top:74px;"></smol-arrow>
<smol-arrow style="right:104px;color:green;top:76px;height:calc(460px - 46px)" line></smol-arrow>
<smol-arrow style="right:104px;color:green;bottom:-1px" down></smol-arrow>
<phone-content style="position:relative">
<phone-urlbar aria-label="URL bar" role="figure" style="position:absolute;z-index:2"><phone-urlbar-inner><div class="svgFallback" style="position:absolute;translate: 8px 0;">🔒</div><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"></path></svg><span><span>lyra.horse</span>/blog/</span></phone-urlbar-inner><a href="https://soundcloud.com/prodlightnex/anything-but-job" style="rotate:90deg;user-select:none;margin:0 4px 0 2px;color:inherit" target=_blank>•••</a></phone-urlbar>
<div style="height:46px"></div>
<smol-arrow style="right:64px;color:orange;z-index:1;top:45px;box-shadow: 5px -5px 0 4px #FFF"></smol-arrow>
<button class="scroll-btn scroll-down">➤ </button>
<div style="margin:6px;font-size:75%;line-height:1">
  <p>lvh</p>
  <p>svh</p>
  <p>dvh</p>
  <p>lvh</p>
  <p>svh</p>
  <p>dvh</p>
  <p>lvh</p>
  <p>svh</p>
  <p>dvh</p>
  <p>lvh</p>
  <p>svh</p>
  <p>dvh</p>
  <p>lvh</p>
  <p>svh</p>
  <p>dvh</p>
</div>
<p style="font-family:var(--font-head);color:#04593b;text-align:left;font-size:120%;margin: 4px">Your values</p>
<table style="margin: 4px">
  <thead>
    <tr>
      <th>Unit</th>
      <th>Value</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>vh</th>
      <td><unit-value vh></unit-value>px</td>
    </tr>
    <tr>
      <th>lvh</th>
      <td><unit-value lvh></unit-value>px</td>
    </tr>
    <tr>
      <th>dvh</th>
      <td><unit-value dvh></unit-value>px</td>
    </tr>
    <tr>
      <th>svh</th>
      <td><unit-value svh></unit-value>px</td>
    </tr>
  </tbody>
</table>
<p style="margin: 6px;font-size:75%;font-style: italic;color:#444;max-width:130px">Above is a table of values your browser reports - if you're on mobile, try scrolling the blogpost up and down so that the URL bar hides and see how the numbers change.</p>
<p style="margin: 6px;font-size:75%;font-style: italic;color:#444;max-width:130px">The values are multiplied by 100 (eg 100vh is used instead of 1vh).</p>
<button class="scroll-btn scroll-up" style="rotate:-90deg">➤ </button>
</phone-content>
</phone-screen></epic-phone>
</div>

The solution to this is to use the new responsive viewport units: **lvh**, **svh**, and **dvh**.

**lvh** stands for *largest* viewport height, and thus is useful for things like backgrounds that you'd want to cover the entire screen with, and wouldn't care about getting cut off.

**svh** stands for *smallest* viewport height, and should be used for things that must always fit on the screen, such as buttons and links.

And **dvh** stands for *dynamic* viewport height - this one will update to whatever the current viewport height is. It might seem like the obvious choice, but it should not be used for elements you don't want resizing or moving around as the user scrolls the page, as it could become quite annoying and possibly even laggy otherwise.

Of course, the respective **lvw**, **svw**, and **dvw** units exist too :).

### Keyboard cat

By default, the viewport units do not account for the keyboard overlaying the page.

There are two ways to deal with that: the *[interactive-widget](https://developer.mozilla.org/en-US/docs/Web/HTML/Guides/Viewport_meta_element#interactive-widget)* attribute, and the *[VirtualKeyboard](https://developer.mozilla.org/en-US/docs/Web/API/VirtualKeyboard_API)* API.

The former option is widely supported across browsers, works without JS, and goes in the meta viewport tag. It makes it so that opening the keyboard will change *all* of the viewport units.

<pre class="sx-block"><code><sx-t>&lt;meta</sx-t> <sx-r>name</sx-r><sx-t>=</sx-t><sx-v>"viewport"</sx-v> <sx-r>content</sx-r><sx-t>=</sx-t><sx-v>"width=device-width, interactive-widget=resizes-content"</sx-v><sx-t>&gt;</sx-t>
</code></pre>
The latter option is currently only supported in Chromium-based browsers, and requires a single line of JavaScript to use:

<pre class="sx-block"><code><sx-e>navigator</sx-e>.<sx-p>virtualKeyboard</sx-p>.<sx-p>overlaysContent</sx-p> = <sx-a>true</sx-a>;
</code></pre>
The advantage of the second option is that it allows you to use [environment variables](https://developer.mozilla.org/en-US/docs/Web/CSS/env) in CSS to get the position and size of the keyboard, which is pretty cool.

<pre class="sx-block"><code><sx-t>floating-button</sx-t> {
  <sx-p>margin-bottom</sx-p>: <sx-k>env</sx-k>(<sx-a>keyboard-inset-height</sx-a>, <sx-n>0px</sx-n>);
}
</code></pre>
But considering the fact that it doesn't work cross-browser, I'd avoid it.

## CSS wishlist

Alright, so this is a little different from the rest of the post, but I wanted to bring up some things that I wish were in CSS. I haven't fully fleshed out all of them, so some definitely wouldn't fit the spec as-is, but maybe they can inspire some other stuff at least.

They are just fun ideas, don't take them too seriously.

### Reusable blocks

I wish it was possible to put classes in other classes in CSS, so that you could write something like:

<pre class="sx-block"><code>.<sx-y>border</sx-y> {
  <sx-p>border</sx-p>: <sx-n>2px</sx-n> <sx-a>solid</sx-a>;
  <sx-p>border-radius</sx-p>: <sx-n>4px</sx-n>;
}

.<sx-y>button</sx-y> {
  <sx-z>@apply</sx-z> <sx-y>border</sx-y>;
}

.<sx-y>card</sx-y> {
  <sx-z>@apply</sx-z> <sx-y>border</sx-y>;
}
</code></pre>
This is something that [Tailwind already has](https://tailwindcss.com/docs/functions-and-directives#apply-directive), and that makes me jealous.

<!--
### Scoped variables

I wish we could scope variables, so that an inner element could set the value for an outer element.

<pre class="sx-block"><code><sx-t>foo</sx-t> {
  <sx-k>@property</sx-k> <sx-k>--color</sx-k> {
    <sx-p>syntax</sx-p>: <sx-s>'&lt;color&gt;'</sx-s>;
    <sx-p>initial-value</sx-p>: <sx-a>red</sx-a>;
    <sx-p>scoped</sx-p>: <sx-a>true</sx-a>;
  }
  <sx-t>bar</sx-t> {
    &amp;:<sx-l>hover</sx-l> {
      <sx-e>--color</sx-e>: <sx-a>blue</sx-a>;
    }
  }
  <sx-c>/* foo will be blue on bar hover */</sx-c>
  <sx-p>color</sx-p>: <sx-k>var</sx-k>(<sx-e>--color</sx-e>);
}
</code></pre>
This idea has a lot of problems in practice, from little things such as nested statements getting reordered, to bigger issues that'd require rewriting and rethinking big parts of CSS. I don't see this ever being added, but it would be fun to have.
-->

### Combined @media selectors

We can currently do nested *@media* queries, and also multiple selectors at the same time:

<pre class="sx-block"><code><sx-t>div</sx-t> {
  &amp;.<sx-y>foo</sx-y>, &amp;.<sx-y>bar</sx-y> {
    <sx-p>color</sx-p>: <sx-a>red</sx-a>;
    <sx-p>padding</sx-p>: <sx-n>8px</sx-n>;
    <sx-p>font-size</sx-p>: <sx-n>2em</sx-n>;
  }
  <sx-z>@media</sx-z> (<sx-p>width</sx-p> &lt; <sx-n>480px</sx-n>) {
    <sx-p>color</sx-p>: <sx-a>red</sx-a>;
    <sx-p>padding</sx-p>: <sx-n>8px</sx-n>;
    <sx-p>font-size</sx-p>: <sx-n>2em</sx-n>;
  }
}
</code></pre>
But we cannot combine the two into a single selector:

<pre class="sx-block"><code><sx-t>div</sx-t> {
  <sx-z>@media</sx-z> (<sx-p>width</sx-p> &lt; <sx-n>480px</sx-n>), &amp;.<sx-y>foo</sx-y> {
    <sx-p>color</sx-p>: <sx-a>red</sx-a>;
    <sx-p>padding</sx-p>: <sx-n>8px</sx-n>;
    <sx-p>font-size</sx-p>: <sx-n>2em</sx-n>;
  }
}
</code></pre>
Which means if you want to do that you'll inevitably have to repeat code or do some silly variable hacks, neither of which is ideal.

### n-th child variable

For many of the CSS crimes I like to commit, I often end up writing code like:

<pre class="sx-block"><code><sx-t>div</sx-t> {
  <sx-t>span</sx-t>:<sx-l>nth-child</sx-l>(<sx-n>1</sx-n>) { <sx-e>--nth</sx-e>: <sx-n>1</sx-n>; }
  <sx-t>span</sx-t>:<sx-l>nth-child</sx-l>(<sx-n>2</sx-n>) { <sx-e>--nth</sx-e>: <sx-n>2</sx-n>; }
  <sx-t>span</sx-t>:<sx-l>nth-child</sx-l>(<sx-n>3</sx-n>) { <sx-e>--nth</sx-e>: <sx-n>3</sx-n>; }
  <sx-t>span</sx-t>:<sx-l>nth-child</sx-l>(<sx-n>4</sx-n>) { <sx-e>--nth</sx-e>: <sx-n>4</sx-n>; }
  <sx-t>span</sx-t>:<sx-l>nth-child</sx-l>(<sx-n>5</sx-n>) { <sx-e>--nth</sx-e>: <sx-n>5</sx-n>; }
  ...
  <sx-y>span</sx-y> {
    <sx-p>top</sx-p>: <sx-k>calc</sx-k>(<sx-e>--nth</sx-e> * <sx-n>24px</sx-n>);
    <sx-p>color</sx-p>: <sx-k>hsl</sx-k>(<sx-k>calc</sx-k>(<sx-k>var</sx-k>(<sx-e>--nth</sx-e>) * <sx-n>90deg</sx-n>) <sx-n>100</sx-n> <sx-n>90</sx-n>);
  }
}
</code></pre>
And I think it would be a lot nicer if we could instead just do:

<pre class="sx-block"><code><sx-t>div</sx-t> {
  <sx-t>span</sx-t> {
    <sx-e>--nth</sx-e>: <sx-k>nth-child</sx-k>();
    <sx-p>top</sx-p>: <sx-k>calc</sx-k>(<sx-e>--nth</sx-e> * <sx-n>24px</sx-n>);
    <sx-p>color</sx-p>: <sx-k>hsl</sx-k>(<sx-k>calc</sx-k>(<sx-k>var</sx-k>(<sx-e>--nth</sx-e>) * <sx-n>90deg</sx-n>) <sx-n>100</sx-n> <sx-n>90</sx-n>);
  }
}
</code></pre>
### n-th letter targeting

CSS has the ability to style the [::first-letter](https://developer.mozilla.org/en-US/docs/Web/CSS/::first-letter) of text. It'd be cool if were was also a **::nth-letter(...)** selector, similar to [:nth-child](https://developer.mozilla.org/en-US/docs/Web/CSS/:nth-child). I suspect the reason this isn't a thing is because the *::first-letter* selector is a pseudo-element, which would be a bit tricky to implement with the nth-letter idea.

<DIV><code-compare aria-label="Demo: the letter i in hi there is made red" role="figure" id="nth-example"><code-frame role=code><sx-c>/* not a real feature */</sx-c>
<sx-t>p</sx-t>::<sx-l>nth-letter</sx-l>(2) {
  <sx-p>color</sx-p>: <sx-a>red</sx-a>;
}</code-frame>
<fake-frame style="min-height:64px">
<p>h<span style="color:red">i</span> there~</p>
</fake-frame></code-compare></DIV>
<style>
#nth-example {
  fake-frame {
    display: flex;
    justify-content: center;
    align-items: center;
    & > div {
      display: flex;
      flex-direction: column;
    }
    input {
      border: none;
      border-radius: 2px;
      outline: 1px solid #000;
      &:focus { outline-width: 2px; }
      &:user-valid { outline-color: green; }
      &:user-invalid { outline-color: red; }
    }
  }
}
</style>

[Blackle](https://www.blackle-mori.com/) suggested that combining the nth-child() variable with :nth-letter targeting would also be fun for certain effects, such as putting the value in the sin() function to create wavy text.

<DIV><code-compare aria-label="Demo: the text waves vertically, and has a trans-colored gradient going across it" role="figure" vertical id="wavey-example"><code-frame role=code><sx-t>div</sx-t> {
  <sx-c>/* not a real feature */</sx-c>
  <sx-e>--nth</sx-e>: <sx-k>nth-child</sx-k>(<sx-a>nth-letter</sx-a>);
  <sx-p>will-change</sx-p>: <sx-a>transform</sx-a>;
  <sx-p>translate</sx-p>: <sx-n>0</sx-n> <sx-k>calc</sx-k>(<sx-k>sin</sx-k>(<sx-k>var</sx-k>(<sx-e>--nth</sx-e>) * <sx-n>0.35</sx-n> - <sx-k>var</sx-k>(<sx-e>--wave</sx-e>) * <sx-n>3</sx-n>) * <sx-n>5px</sx-n>);
  <sx-p>color</sx-p>: <sx-k>color-mix</sx-k>(<sx-a>in</sx-a> <sx-a>oklch</sx-a>, <sx-n>#58C8F2</sx-n>, <sx-n>#EDA4B2</sx-n> <sx-k>calc</sx-k>(<sx-k>sin</sx-k>(<sx-k>var</sx-k>(<sx-e>--nth</sx-e>) * <sx-n>0.5</sx-n> - <sx-k>var</sx-k>(<sx-e>--wave</sx-e>)) * <sx-n>50%</sx-n> + <sx-n>50%</sx-n>));
}</code-frame>
<fake-frame style="min-height:128px; position: relative">
  <a href="https://blog.polly.computer/untuck_NOW_queen/" aria-label="untuck now queen" target="_blank">
    <div>u</div><div>n</div><div>t</div><div>u</div><div>c</div><div>k</div><div> </div><div>n</div><div>o</div><div>w</div><div> </div><div>q</div><div>u</div><div>e</div><div>e</div><div>n</div>
  </a>
  <p>(<span>tap</span><span>hover</span> to play animation)</p>
</fake-frame></code-compare></DIV>
<style>
@property --wavey {
  syntax: '<number>';
  inherits: true;
  initial-value: 0;
}
#wavey-example {
  fake-frame {
    &:not(:hover) {
      & > a {
        animation-play-state: paused
      }
      & > p {
        opacity: 0.5;
      }
    }
    display: flex;
    justify-content: center;
    align-items: center;
    & > p {
      position: absolute;
      opacity:0;
      transition: opacity 0.1s;
      bottom: 0;
      margin: 4px;
      pointer-events: none;
      /* note: we use (pointer: coarse) instead of
         (hover: hover) because the latter is broken
         on some android devices (mostly samsung) */
      @media not (pointer: coarse) {
        & > span:first-child {
          display: none;
        }
      }
      @media (pointer: coarse) {
        & > span:nth-child(2) {
          display: none;
        }
      }
    }
    & > a, & > a:visited, & > a:hover, & > a:active {
      --wavey: 0;
      animation: 3.5s linear infinite wavey;
      display: flex;
      font-weight: 600;
      font-size: 120%;
      white-space: pre;
      color: transparent;
      &>:nth-child(1)  { --nth:1  }
      &>:nth-child(2)  { --nth:2  }
      &>:nth-child(3)  { --nth:3  }
      &>:nth-child(4)  { --nth:4  }
      &>:nth-child(5)  { --nth:5  }
      &>:nth-child(6)  { --nth:6  }
      &>:nth-child(7)  { --nth:7  }
      &>:nth-child(8)  { --nth:8  }
      &>:nth-child(9)  { --nth:9  }
      &>:nth-child(10) { --nth:10 }
      &>:nth-child(11) { --nth:11 }
      &>:nth-child(12) { --nth:12 }
      &>:nth-child(13) { --nth:13 }
      &>:nth-child(14) { --nth:14 }
      &>:nth-child(15) { --nth:15 }
      &>:nth-child(16) { --nth:16 }
      &>div {
        will-change: transform;
        translate: 0 calc(sin(var(--nth) * 0.35 - var(--wavey) * 3) * 5px);
        /* This is commented out because: https://issues.chromium.org/issues/441442313 */
/*        color: color-mix(in oklch, #58C8F2, #EDA4B2 calc(sin(var(--nth) * 0.5 - var(--wavey)) * 50% + 50%))!important;*/
        --color: color-mix(in oklch, #58C8F2, #EDA4B2 calc(sin(var(--nth) * 0.5 - var(--wavey)) * 50% + 50%))!important;
        color: transparent;
        text-shadow: 0 0 0 var(--color);
      }
    }
  }
}
@keyframes wavey {
  from {
    --wavey: 0;
  }
  to {
    --wavey: calc(pi * 2);
  }
}
</style>

### Unit removal

I wish you could easily remove units from values, for example by dividing them.

<style>
  screen-size {
    --vwi: tan(atan2(var(--vw), 1px));
    &::after {
      counter-reset: vwi var(--vwi);
      content: counter(vwi);
    }
  }
</style>

<pre class="sx-block"><code><sx-t>div</sx-t> {
  <sx-c>/* Turns into: <screen-size></screen-size> (no unit) */</sx-c>
  <sx-e>--screen-width</sx-e>: <sx-k>calc</sx-k>(<sx-n>100vw</sx-n> / <sx-n>1px</sx-n>);
  <sx-p>color</sx-p>: <sx-k>hsl</sx-k>(<sx-k>var</sx-k>(<sx-e>--screen-width</sx-e>) <sx-n>100</sx-n>, <sx-n>50</sx-n>);
}</code></pre>

This would allow you to use the size of the viewport or container as a numeric variable for things other than length. For example, the [color picker](#color-picker) from earlier uses it to convert the location of the color picker dot to a number to be used in a color value instead.

Uh, but wait? Does that mean this feature already exists?

Yeah, lol! We already have the ability to get unitless values in CSS, but it involves doing hacky stuff such as `tan(atan2(var(--vw), 1px))` with a custom *@property*. It'd be nice to have this as just a division, for example.

Oh, and good news, this one we might actually be [getting soon](https://www.w3.org/TR/css-values-4/#calc-type-checking)!

*Also if you do something like `calc(1px + sqrt(1px * 1px))` your browser will crash[^sqrtcrash].*

### A better image function

The [**image()** function](https://developer.mozilla.org/en-US/docs/Web/CSS/image/image) exists, but no browsers implement it. It's similar to just using *url()*, but adds some really cool features such as a fallback color, and image fragments to crop a smaller section out of a bigger image (think spritesheets).

We can already do both fallbacks and spritesheets with the various background properties, but it'd be nice to have this pretty syntax. I'd honestly love this syntax even more for &lt;img&gt; tags than CSS.

### style tags in body

I make heavy use of &lt;style&gt; tags in &lt;body&gt; for my projects. On my blog, for example, I write the relevant CSS close to their graphics so that you can [start reading the blog](https://infosec.exchange/@rebane2001/114931064484832451) before the entire page (or the entire CSS) has finished loading[^smallsize]. And it works great!

But what's unfortunate is that despite browsers supporting this, and major sites using this, it's [not officially spec-compliant](https://github.com/whatwg/html/issues/1605). I suspect it's in the spec to avoid the [FOUC](https://en.wikipedia.org/wiki/Flash_of_unstyled_content) footgun, but there are so many reasons you would want/need style in body that I don't think it justifies it.

I think an HTML validator should warn for this, but not error.


## The art

I want to end this article by saying that to me, web development is an art, and thus, CSS is too. I often have a hard time relating to people who do webdev solely to earn money or build a startup - web development is very different when you're on a team and are given tasks from above instead of having free will over what you create for fun.

It's probably most apparent with things like AI[^ai], that for me take all the fun and creativity out of my work. But it also applies to build chain tooling such as linters and minifiers - the way I write my code is part of the art, and I don't want a tool to erase that. I don't even use an IDE[^sublime].

Among the practical reasons for sticking to CSS listed throughout this post, there's a secret extra reason I like to do everything in CSS, and that's expression and art. Art isn't always practical, and using CSS isn't either. But it's how I like to express myself, and it's why I do what I do.

I tried to keep this post approachable and practical for all web developers. But there is so much more to CSS that I'd like to talk about, so expect another post about the stuff that isn't practical, and is instead just cool as fuck. I think *CSS is a programming language*, and [I made a game to prove it](https://lyra.horse/css-clicker/).

But that's a topic for another time.

## afterword

it's been almost a year since my last post, but i hope it's been worth the wait ^_^

as usual, this post is a self-contained html file with no javascript, images, or other external resources - everything on the page is handwritten html/css, weighing in at around 49kB gzipped. it was really fun creating all the little interactive widgets and visuals this time around, i think i've improved in css a lot since the last time i posted.

this entire post turned out to be a bit of a fun mess (as did i!), it's almost like a chaotic gradient of tone throughout, i hope it was still interesting and enjoyable to read though.

i have a few new posts in the works: in addition to the second css one mentioned earlier, i also have one about a new web vulnerability subclass i discovered, and one about a trans topic. i'm not sure when these posts will come out, but we'll see! make sure to add me to your rss reader if that sounds fun.

i'll also be giving [a talk](https://pretalx.com/bsides-tallinn-2025/talk/S3V8UY/) at bsides tallinn in september! i'm hoping to also do css-related talks at the next ccc and disobey, but we'll have to see whether i get accepted and have the travel budget for those.

thank you so much for reading &lt;3
<p id="youAre">you're awesome!! (i can tell because you checked <a href="#awesome">that checkbox</a> from earlier)</p>
<style>body:not(:has(#awesome:checked)) #youAre { display: none; }</style>

**Discuss this post on:** twitter, mastodon, lobsters

<!--[^interactive]: They actually don't.-->
[^firefox-flex]: Chrome's DevTools come with the cool flexbox widget. Firefox's however don't seem to for some reason? I find that weird because Firefox does have really good tools for flexbox and grid development, so this seems like an odd omission.
[^tailwind]: While I think what I said is true, Tailwind does have more to its existence, the core of which can be found in [this post](https://adamwathan.me/css-utility-classes-and-separation-of-concerns/) by its creator.
[^compliant]: You are allowed to just make up elements <a target="_blank" href="https://html.spec.whatwg.org/multipage/custom-elements.html#valid-custom-element-name">as long as their names contain a hyphen</a>. Apart from the 8 existing tags listed at the link, no HTML tags contain a hyphen and none ever will. The spec even has `<math-α>` and `<emotion-😍>` as <a target="_blank" href="https://html.spec.whatwg.org/multipage/custom-elements.html#valid-custom-element-name:~:text=😍">examples of allowed names</a>. You are allowed to <a target="_blank" href="https://html.spec.whatwg.org/multipage/custom-elements.html#custom-elements-core-concepts:~:text=Any%20namespace%2Dless%20attribute">make up attributes</a> on an <a target="_blank" href="https://html.spec.whatwg.org/multipage/custom-elements.html#autonomous-custom-element">autonomous custom element</a>, but for other elements (built-in or extended) you should only make up `data-*` attributes. I make heavy use of this on my blog to make writing HTML and CSS nicer and avoid meaningless div-soup.<!-- links in this footnote are set to target="_blank" because otherwise the whatwg spec fragment links don't work on page load -->
[^bem]: Still not nice to read for you? I'm personally not a fan of [BEM](https://getbem.com/), but I'd definitely recommend reading up on it too if you just don't vibe with the way I'm writing my examples. Also, my example intentionally shows off a lot of the syntax at once, but in the real world it might make sense to structure things a little differently.
[^baseline]: Baseline browsers are Safari (macOS/iOS), Chrome (desktop/Android), Edge (desktop), and Firefox (desktop/Android).
[^es3]: ES3 (1999) is the last "classic" version of JavaScript. In 2009 we got the first major revision known as ES5, and a few years later we kicked off the yearly spec updates with ES2015. Also ES4 was abandoned which makes me feel sad :c.
[^hr]: A certain HR platform I have to use puts its action buttons at the very bottom of a 100vh container, leading to them not being visible/interactable on my phone - not a headache you want to go through when requesting sick days. It's a good example of how just using the wrong unit can cause a pretty bad real world accessibility problem.
[^sqrtcrash]: Well, probably not. This is [a bug](https://issues.chromium.org/issues/434187209) I found while writing this post that only affects Chrome, and it'll probably get fixed before it even manages to hit stable. *Update:* I took so long to get this blog post out that it has been fixed now. During the writing of this blog post I found [another bug](https://issues.chromium.org/issues/440613173) in Chrome though, which is pretty funny. *Update 2:* I found [yet another Chrome bug](https://issues.chromium.org/issues/441442313) while writing this post, this one is kinda weird, you should read it.
[^mdnbaseline]: The MDN docs of course also list detailed browser compatibility, but the Baseline symbols are nice for just getting a quick "yeah, we can use it and it'll work for everyone" type overview.
[^newsanswer]: 93 files!! Seems like they're 1/3 functionality, 1/3 ads, and 1/3 analytics.<!-- Funnily enough, after clicking on an article and dismissing its full-screen ad, 2/3rds of the page are covered in ads - you can't even read the full headline of the article you clicked on without scrolling down.--> The site works just fine with JavaScript disabled - only stuff like the comments section and ads won't load. It's no longer a laggy mess either for some reason.
[^x3c]: I think the [x3ctf challenges](https://x3c.tf/archive/2025/x3ctf.html#challenges) page looks really smooth on my computer - the marquee text animation and clicking on the challenges is buttery. And it also runs pretty well on the low-end hardware I have. Note that some browser performance recording tools can act a bit weird with CSS animations, so make sure your tools are working as expected before using them. Unrelated, but I made some other cool x3ctf web stuff too - check out [the archive](https://x3c.tf/archive/).
[^smallsize]: This matters for people on slow connections, such as bad mobile data, satellite internet, tor, or [iodine](https://code.kryo.se/iodine/). While my blog posts are very small in size, the CSS alone can take up [more than the first 14kB](https://endtimes.dev/why-your-website-should-be-under-14kb-in-size/) of a TCP round trip, so with blocking CSS in the head you might have to wait a few extra seconds (or minutes, in the case of iodine) just to start reading the first paragraph. Now, that 14kB number [isn't completely accurate in the modern world](https://www.tunetheweb.com/blog/critical-resources-and-the-first-14kb/), but testing on my own server (HTTP/2, TLS 1.3), around ~16kB of the compressed html reaches the browser in the first batch of http data.
[^ai]: By this I mean tools such as Copilot, Cursor, chatbots etc. I understand there is a huge difference between full-on *vibe coding* and just using the tab key, but I **do not** want to use or interact with any of those tools. Please respect that.
[^sublime]: I write all my code (and blogposts) in [Sublime Text](https://www.sublimetext.com/), which to me is just a glorified version of Notepad. The features over Notepad it gives me are syntax highlighting, multiple cursors, keyboard shortcuts, and a better visual design. It doesn't do that much, and yet, it's perfect. It's so good I paid for it.
[^fieldset]: There's [a bug](https://issues.chromium.org/issues/40923583) in Chrome that *requires* you to use a fieldset/radiogroup for the radio button index to work correctly in screenreaders. Eg if you have 3 radio buttons with the same *name*, selecting one of them should read *"radio button 1 of 3"*, which is what Firefox does, but in Chrome it will instead read it as *"radio button 4 of 9"* or whatever if you don't have a fieldset/radiogroup because it kind of just combines all the radio buttons on the page into a single index.