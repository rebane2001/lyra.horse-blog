+++
title = 'Using YouTube to steal your files'
date = 2024-09-19T07:30:00Z
draft = false
tags = ['infosec','bug bounty']
slug = "using-youtube-to-steal-your-files"
summary = "A writeup of my $4133.70 Google Drive vulnerability chain."
+++

In my security research I often come across weird quirks and behaviours that aren't particularly useful beyond a neat party trick. It's always a good idea to keep track of them though, perhaps one day they'll be just the missing piece you need.

<div class="slds">
    <div class="sldsH">
        <div class="sldsHicon"><div><div></div></div></div>
        <div class="sldsHlt">
            <span class="sldsHtitle" contenteditable="plaintext-only">Untitled presentation</span><br>
            <div class="sldsHlnks">
                <span>File</span><span>Edit</span><span>View</span><span>Insert</span><span>Format</span><span>Slide</span><span>Arrange</span><span>Tools</span><span>Extensions</span><span>Help</span>
            </div>
        </div>
        <div style="height: 40px; display:flex; padding: 2px; gap: 8px;margin-left:auto">
            <div class="sldsHbtn sldsHbtnWhite over640"><div>Slideshow</div><div style="display:flex"><div style="margin:auto" class="sldsDrop"></div></div></div>
            <div class="sldsHbtn sldsHbtnBlue over640"><div>Share</div><div style="display:flex"><div style="margin:auto" class="sldsDrop"></div></div></div>
            <div class="sldsHpfp over360"><div>L</div></div>
        </div>
    </div>
    <div class="sldsBody">
        <div class="sldsSideLeft over640">
            <div class="sldsFilmEntry">
                <div class="sldsFilmText">1</div>
                <div class="sldsFilmSlide">
                    <div style="text-align: center; filter: blur(0.4px)">
                        <div style="padding-top: 25px; font-size: 9px; color: #000D">Click to add title</div>
                        <div style="font-size: 5.3px;color: #595959">Click to steal your files</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="sldsMain">
            <div class="sldsSlide">
                <div class="sldsSlideTextbox sldsSlideTextboxBig" contenteditable="plaintext-only">Click to add title</div>
                <div class="sldsSlideTextbox sldsSlideTextboxSmall" contenteditable="plaintext-only">Click to steal your files<!--Click to add subtitle--></div>
            </div>
        </div>
    </div>
</div>

<style>
    /* You may notice me using the peculiar font-weight 501 in my CSS. That's because I intended to use 500, but for some reason Firefox renders fonts with just 400/600 at 500 as 400, not 600, so I'm using 501 so that it rounds to 600 if 500 is not available. */
    .sldsBody {
        display: flex;
        width: 100%;
        height: 360px;
    }
    .sldsSideLeft {
        width: 220px;
        height: 100%;
        user-select: none;
    }
    .sldsFilmEntry {
        display: flex;
        width: 213px;
        height: 100px;
    }
    .sldsFilmText {
        margin: 6px 4px 0 auto;
        font-size: 14px;
        font-weight: 501;
    }
    .sldsFilmSlide {
        width: 150px;
        height: 86px;
        border: 3px solid rgb(11, 87, 208);
        border-radius: 12px;
        margin: 4px 4px 4px 4px;
    }
    .sldsFilmSlide > div {
        background: #FFF;
        border-radius: 8px;
        width: calc(150px - 6px);
        height: calc(86px - 6px);
        margin: 3px;
    }
    .sldsMain {
        display: flex;
        height: 100%;
        flex-grow: 1;

    }
    .sldsSlide {
        display: flex;
        flex-direction: column;
        width: calc(100% - 32px);
        aspect-ratio: 16 / 9;
        background: #FFF;
        margin: auto;
        /* box-shadow: 0px 0px 4px 0px #0007; */
        border: 1px solid #C4C7C5;
        font-family: Arial, Helvetica, sans-serif;
    }
    .sldsSlideTextbox {
        border: 1px solid #C2C2C2;
        width: 90%;
        margin: auto;
        text-align: center;
    }
    .sldsSlideTextboxBig {
        margin-bottom: 2px;
        margin-top: 8%;
        padding-top: 10%;
        font-size: 35px;
        color: #000;
    }
    .sldsSlideTextboxSmall {
        margin-top: 2px;
        border: 1px solid #D7D7D7;
        height: 15%;
        font-size: 19px;
        color: #595959;
    }
</style>
<style>
    .slds {
        border-radius: 4px;
        width: 100%;
        height: fit-content;
        background: #f9fbfd;
        font-family: "Google Sans", "Open Sans", Roboto, sans-serif;
    }
    .sldsH {
        display: flex;
        flex-wrap: wrap;
        width: calc(100% - 28px);
        min-height: 48px;
        font-size: 14px;
        font-weight: 400;
        /* display: none; */
        padding: 8px 14px;
    }
    .sldsHlt {
        flex: 1 1 192px;
        overflow: hidden;
    }
    .sldsHlnks {
        width: 100%;
        height: 25px;
        display: flex;
        margin-top: 1px;
        flex-flow: row wrap;
        overflow: hidden;
    }
    .sldsHlnks > span {
        padding: 2px 7px;
        border: 1px solid transparent;
        border-radius: 4px;
        user-select: none;
        cursor: pointer;
    }
    .sldsHlnks > span:hover {
        background: #e8ebee;
    }
    .sldsHlnks > span:active {
        background: #e1e3e6;
    }
    .sldsHicon {
        display: flex;
        min-width: 40px;
        height: 52px;
    }
    .sldsHicon > div {
        display: flex;
        width: 26px;
        height: 34px;
        background: #FFBA00;
        margin: auto;
        border-radius: 4px 12px 4px 4px;
    }
    .sldsHicon > div > div {
        width: 14px;
        height: 8px;
        margin: auto;
        margin-bottom: 8px;
        border-radius: 2px;
        border: 2px solid #FFF;
    }
    .sldsHtitle {
        font-size: 18px;
        padding-left: 6px;
    }
    .sldsHbtn {
        display: flex;
        font-weight: 501;
        user-select: none;
    }
    .sldsHbtnWhite > div {
        border: 1px solid #747775;
        color: #444746;
    }
    .sldsHbtnWhite > div:hover {
        background: #e8ebee;
    }
    .sldsHbtnWhite > div:active {
        background: #e1e3e6;
    }
    .sldsHbtnBlue > div:first-child {
        border-right-color: #f9fbfd;
    }
    .sldsHbtnBlue > div {
        border: 1px solid #0000;
        color: #001d35;
        background: #c2e7ff;
    }
    .sldsHbtnBlue > div:hover {
        background: #B2D7EF;
    }
    .sldsHbtnBlue > div:active {
        background: #ABCFE7;
    }
    .sldsHbtnBlueDark > div:first-child {
        border-right-color: #1E1E1F;
    }
    .sldsHbtnBlueDark > div {
        border: 1px solid #0000;
        color: #C2E7FF;
        background: #004A77;
    }
    .sldsHbtnBlueDark > div:hover {
        background: #105782;
    }
    .sldsHbtnBlueDark > div:active {
        /* This color doesn't exist on the actual site,
         * but it feels horrible without it, so I decided
         * to add it anyways so you can click and stuff! */
        background: #145e8b;
    }
    .sldsHbtn > div:first-child {
        padding: 9px 17px 11px 18px;
        border-radius: 100px 0 0 100px;
        display: flex;
        justify-content: center;
        align-items: center;
    }
    .sldsHbtn > div:last-child {
        padding: 10px 14px 10px 12px;
        border-left: none;
        border-radius: 0 100px 100px 0;
        cursor: pointer;
    }
    .sldsHbtn > div:first-child:last-child {
        border-radius: 100px;
        padding: 9px 17px 11px 18px;
        border-right-color: #0000;
    }
    .sldsHpfp > div {
        width:100%;
        height: 100%;
        background: #7B1FA2;
        border-radius: 100px;
        color: #FFF;
        text-align: center;
        font-size: 20px;
        line-height: 32px;
        user-select: none;
    }
    .sldsHpfp {
        width: 32px;
        height: 32px;
        padding: 4px;
        border-radius: 100px;
        cursor: pointer;
    }
    .sldsHpfp:hover {
        background: #EAECEE;
    }
    .sldsHpfp:active {
        background: #D4D7D9;
    }
    .filePg .sldsHpfp:hover {
        background: #2E2E2F;
    }
    .filePg .sldsHpfp:active {
        background: #393939;
    }
    .sldsDrop {
        /* 
         * idk who thought to make a dropdown icon out of
         * css borders but it's pretty genius haha
         */
        border: solid 4px #0000;
        border-bottom: solid 0px currentcolor;
        border-top: solid 4px currentcolor;
    }
</style>
<br>

## Part 1: Cat videos

Who doesn't love cat videos?

Google Slides has this neat feature that lets you add YouTube videos to your presentations. Just open up the video picker, look for your favorite clip, and add it onto a slide.

What appears is an iframe that links to <span class="urlBox">www.youtube.com/embed/{VIDEOID}</span> with your cute cat video playing inside of it. Pretty neat! But can we do anything beyond just playing a video?

Looking at the network traffic, it seems like adding a video onto a slide will send Slides the videoid, which it then uses to construct the embed URL for the iframe. We can't control the full URL, just the videoid part. Can we still do something?

The obvious thing to try here is path traversal - if we change the videoid to **../**, the full url will be <span class="urlBox" style="white-space:nowrap">www.youtube.com/embed/../</span>, which should turn into just <span class="urlBox" style="white-space:nowrap">www.youtube.com/</span>, leading us straight to the YouTube home page. Let's try it!

> graphic - slides slide with an errored iframe in the middle (maybe devtools also)
<div class="genericContainer" style="background:#F9FBFD">
    <div class="sldsMain" style="margin:20px 10px">
            <div class="sldsSlide" style="aspect-ratio:unset;height:420px">
                <div style="width:94%;height:90%;margin:auto;overflow:hidden;border: 2px inset #EEE;background:#0E0E0E">
                </div>
            </div>
        </div>
</div>

To my surprise, it worked! We now have the YouTube homepage within this Slides iframe... or at least an error page representing it. YouTube, like most modern webapps, disallows framing most of its pages to prevent clickjacking attacks. Of course, the **/embed/** page is an exception because that page is intended to be embedded on other sites, but are there any other interesting **www\.youtube.com** pages we could frame?

I looked into it for a bit, and found a bunch of framable resources on **/s/**. We can have stuff like YouTube's emoji and css/js source code inside of a presentation! Unfortunately, it doesn't seem very useful for now, it's just a fun trick we can do.

> graphic - slides has youtube emoji embedded

## Part 2: Redirects

Open redirects are a genre of "vulnerabilities" that can redirect you to any other page. For example, visiting **[google.com/url?q=https://lyra.horse](https://www.google.com/url?q=https://lyra.horse)**[^goog] will take you to **[lyra.horse](https://lyra.horse)**. They are [rarely considered](https://bughunters.google.com/learn/invalid-reports/web-platform/navigation/6680364896223232/open-redirectors) to be real vulnerabilities because their impact is very limited - you'll just be redirected from one page to another.

Yet, as we're stuck in an iframe on **youtube.com**, an open redirect would be pretty lovely. Being able to navigate this Slides iframe to any website of our choice would let us do some very interesting stuff. So let's find one!

The first obvious place to look would be the external links around the site - such as the ones in video descriptions and comments. And indeed, clicking a link in the description of a video redirects us through a special **/redirect** endpoint:

<div class="urlBox"><a href="https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqbjdTaFRBeHRfSW95bkJDVmRGcl96VXV6MkNmd3xBQ3Jtc0tuOVg2b2ZsQVV6V3hpaUJfdXB0UWY2Z1A1bE1sUjlQeHZ4WlVYSzNVUXZBcUF0RFYzNHhLazVUUVFQM1Y5N3VGZEV4bmtCVWhmYXRwY05KWlEyY0w3ZHBBdDY5SEtBa1hpQXBkalpqT3liYzFqYVZxSQ&q=https%3A%2F%2Flyra.horse%2F&v=tbYxAFHnzG0">https://www.youtube.com/redirect?event=video_description&redir_token=<span style="color:#666">QUFFLUhqbjdTaFRBeHRfSW95bkJDVmRGcl96VXV6MkNmd3xBQ3Jtc0tuOVg2b2ZsQVV6V3hpaUJfdXB0UWY2Z1A1bE1sUjlQeHZ4WlVYSzNVUXZBcUF0RFYzNHhLazVUUVFQM1Y5N3VGZEV4bmtCVWhmYXRwY05KWlEyY0w3ZHBBdDY5SEtBa1hpQXBkalpqT3liYzFqYVZxSQ</span>&q=<span style="color:#FFF">https%3A%2F%2Flyra.horse%2F</span>&v=tbYxAFHnzG0</a></div>

The redirect works for now, but you'll notice it has a *redir_token* parameter - this parameter is some sort of a token for redirects that's unique to your session. If someone else opened the same link, they'd see this page instead:

<div class="genericContainer" style="background:#FFF;height:480px">
    <div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span class="urlBarDomain">youtube.com</span>/redirect?event=video_description&redir_token=QUFFLUhqbjdTaFRBeHRfSW95bkJDVmRGcl96VXV6MkNmd3xBQ3Jtc0tuOVg2b2ZsQVV6V3hpaUJfdXB0UWY2Z1A1bE1sUjlQeHZ4WlVYSzNVUXZBcUF0RFYzNHhLazVUUVFQM1Y5N3VGZEV4bmtCVWhmYXRwY05KWlEyY0w3ZHBBdDY5SEtBa1hpQXBkalpqT3liYzFqYVZxSQ&q=https%3A%2F%2Flyra.horse%2F&v=tbYxAFHnzG0</span></div></div>
    <div style="font-family: 'YouTube Noto', Roboto, 'Noto Sans', arial, sans-serif;font-size: 14px;display:flex;flex-direction:column;align-items:center;text-align:center;max-width:90%;margin:auto" class="defSelect">
        <!-- I admit, this YouTube logotype looks quite goofy with the fonts and CSS I used. -->
        <div style="padding-top:24px;filter:blur(0.3px);user-select:none"><a href="https://www.youtube.com/"><svg height="28px" style="display:inline-block" viewBox="0 0 68 48"><path d="M66.52,7.74c-0.78-2.93-2.49-5.41-5.42-6.19C55.79,.13,34,0,34,0S12.21,.13,6.9,1.55 C3.97,2.33,2.27,4.81,1.48,7.74C0.06,13.05,0,24,0,24s0.06,10.95,1.48,16.26c0.78,2.93,2.49,5.41,5.42,6.19 C12.21,47.87,34,48,34,48s21.79-0.13,27.1-1.55c2.93-0.78,4.64-3.26,5.42-6.19C67.94,34.95,68,24,68,24S67.94,13.05,66.52,7.74z" fill="#f00"></path><path d="M 45,24 27,14 27,34" fill="#fff"></path></svg><span style="display:inline-block;font-size:24px;color:#000;font-weight:900;transform:scaleX(0.93) translateY(1px) scaleY(1.2);vertical-align:super;line-height:0">YouTube</span></a></div>
        <div style="font-size:24px;color:#000;font-weight:bold;padding-top:90px">Are you sure you want to leave YouTube?</div>
        <div style="color:#888;padding-top:30px">The link is taking you to a site outside of YouTube (<b>lyra.horse</b>).</div>
        <div style="font-size: 12px;font-weight: 501;padding-top:42px"><a href="https://lyra.horse/"><span style="display:inline-block;padding:12px;color:#2793E6">GO TO SITE</span></a><a href="https://www.youtube.com/watch?v=tbYxAFHnzG0"><span style="display:inline-block;padding:12px;color:#FFF;background:#2793E6;border-radius: 2px">BACK TO YOUTUBE</span></a></div>
    </div>
</div>

It'd be difficult to convince someone to click through a page like that - and even so, we still wouldn't be able to use it inside of our cross-origin iframe due to it having the *x-frame-options* header set to *SAMEORIGIN*.

The next obvious place to look for open redirects is usually the authentication flow of a website - generally sites want to return you to the same page you were on before logging in. It's no different for YouTube, logging into a Google account takes you back to the page you were originally on. This is achieved through the **/signin** endpoint:

<div class="urlBox"><a href="https://www.youtube.com/signin?action_handle_signin=true&app=desktop&hl=en&next=https%3A%2F%2Fwww.youtube.com%2F&feature=passive&hl=en">https://www.youtube.com/signin?action_handle_signin=true&app=desktop&hl=en&next=<span style="color:#FFF">https%3A%2F%2Fwww.youtube.com%2F</span>&feature=passive&hl=en</a></div>

This endpoint does redirects without using a verification token! We can just specify an url of our choice in the *next* parameter and it'll work. Let's try it out with my website.

<div class="ytErr">
<!-- I'm reusing the CSS for the URL bar from my Telegram blog post, but this time I added a mobile theme for smaller screens to make it more cute! Also hover animations! -->
<div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span class="urlBarDomain">youtube.com</span>/signin?next=https://lyra.horse/</span></div></div>
<div class="ytAlert defSelect">
    <div class="ytAlertHeader">Sorry, we found some errors:</div>
    <div class="ytAlertContent">
        <ul>
            <li>Invalid url forwarding parameter</li>
            <li>Sorry, your login was incorrect.</li>
        </ul>
    </div>
</div>
<div class="ytOops">
<!-- I originally designed this part in pixels (566x375px), but I wanted it to be scalable and responsive so I wrote a script to find the most optimal relevant size (625x375px) for the nicest percentage point roundings and then converted everything to nice percentages. While some of these values do have repeating floating point, they're all pretty good cases (eg x.33333 and x.66666) so on a 1x scaled monitor at the original size it matches pixel-perfect to the old px values version. Also the corner radii for the screens are wrong on smaller screens because they don't get scaled but I think I'm okay with that, phones are more round anyways :P. -->
<div class=ytOopsTvRect style="left:8.8%;top:90.4%;width:83.2%;height:1.6%; filter: blur(8px);"></div>
<div class=ytOopsTv style="left:36%;top:5.87%;width:14.24%;height:18.67%"></div>
<div class=ytOopsTv style="left:50.4%;top:-0%;width:4%;height:12%"></div>
<div class=ytOopsTv style="left:51.2%;top:12.53%;width:9.44%;height:12.27%"></div>
<div class=ytOopsTv style="left:35.52%;top:26.13%;width:25.44%;height:27.2%"></div>
<div class=ytOopsTv style="left:23.04%;top:22.93%;width:11.52%;height:13.07%"></div>
<div class=ytOopsTv style="left:62.08%;top:23.2%;width:11.52%;height:13.87%"></div>
<div class=ytOopsTv style="left:63.68%;top:38.4%;width:18.08%;height:20%"></div>
<div class=ytOopsTv style="left:15.68%;top:38.13%;width:18.72%;height:24.8%"></div>
<div class=ytOopsTv style="left:9.28%;top:64.27%;width:24.16%;height:26.67%"></div>
<div class=ytOopsTv style="left:35.52%;top:54.93%;width:27.68%;height:36%"></div>
<div class=ytOopsTv style="left:64.8%;top:59.73%;width:26.72%;height:31.73%"></div>
<div class=ytOopsTvScr style="left:50.88%;top:0.8%;width:3.2%;height:4%;border-radius:2px"></div>
<div class=ytOopsTvScr style="left:37.28%;top:7.2%;width:11.68%;height:13.87%;border-radius:3px"></div>
<div class=ytOopsTvScr style="left:51.84%;top:13.07%;width:8.16%;height:10.4%;border-radius:3px"></div>
<div class=ytOopsTvScr style="left:63.84%;top:24.8%;width:9.28%;height:10.93%;border-radius:5px"></div>
<div class=ytOopsTvScr style="left:38.56%;top:29.07%;width:19.04%;height:22.4%;border-radius:6px"></div>
<div class=ytOopsTvScr style="left:64.8%;top:39.73%;width:14.56%;height:17.33%;border-radius:10px"></div>
<div class=ytOopsTvScr style="left:66.08%;top:62.93%;width:21.28%;height:25.07%;border-radius:10px"></div>
<div class=ytOopsTvScr style="left:10.72%;top:66.13%;width:19.52%;height:22.93%;border-radius:14px"></div>
<div class=ytOopsTvScr style="left:17.28%;top:39.73%;width:15.52%;height:18.4%;border-radius:4px"></div>
<div class=ytOopsTvScr style="left:37.76%;top:56.27%;width:23.36%;height:30.13%;border-radius:6px"></div>
<div class=ytOopsTvScr style="left:25.28%;top:24.53%;width:8.16%;height:10.4%;border-radius:5px"></div>
<div class=ytOopsTvRect style="left:41.28%;top:21.87%;width:5.76%;height:1.6%"></div>
<div class=ytOopsTvRect style="left:58.72%;top:28.53%;width:1.28%;height:10.67%"></div>
<div class=ytOopsTvRect style="left:80.16%;top:39.47%;width:1.12%;height:2.93%"></div>
<div class=ytOopsTvRect style="left:80.16%;top:43.73%;width:1.12%;height:2.93%"></div>
<div class=ytOopsTvRect style="left:31.2%;top:65.87%;width:1.44%;height:9.87%"></div>
<div class=ytOopsTvRect style="left:30.08%;top:65.87%;width:0.48%;height:1.33%"></div>
<div class=ytOopsTvRect style="left:20%;top:59.47%;width:7.68%;height:2.13%"></div>
<div class=ytOopsTvLines style="left:58.56%;top:41.33%;width:1.6%;height:9.87%"></div>
<div class=ytOopsTvLines style="left:51.04%;top:7.47%;width:2.88%;height:3.47%"></div>
<div class=ytOopsTvLines style="left:30.88%;top:77.87%;width:2.08%;height:9.07%"></div>
<div class=ytOopsTvLines style="left:23.68%;top:32.8%;width:0.8%;height:1.33%"></div>
<div class=ytOopsTvLines style="left:79.84%;top:48.53%;width:1.6%;height:6.93%"></div>
<div class="ytOopsTvBtn" style="left:23.68%;top:24.13%;width:0.8%;height:1.33%"></div>
<div class="ytOopsTvBtn" style="left:23.68%;top:26.4%;width:0.8%;height:1.33%"></div>
<div class="ytOopsTvBtn" style="left:23.68%;top:28.27%;width:0.8%;height:1.33%"></div>
<div class="ytOopsTvBtn" style="left:23.68%;top:30.67%;width:0.8%;height:1.33%"></div>
<div class="ytOopsTvBtn" style="left:51.2%;top:5.33%;width:0.64%;height:1.07%"></div>
<div class="ytOopsTvBtn" style="left:53.12%;top:5.33%;width:0.64%;height:1.07%"></div>
<div class="ytOopsTvBtn" style="left:59.36%;top:23.73%;width:0.48%;height:0.8%"></div>
<div class="ytOopsTvBtn" style="left:52.32%;top:23.73%;width:0.48%;height:0.8%"></div>
<div class="ytOopsTvBtn" style="left:47.68%;top:21.6%;width:1.28%;height:2.13%"></div>
<div class="ytOopsTvBtn" style="left:62.56%;top:30.67%;width:1.12%;height:1.87%"></div>
<div class="ytOopsTvBtn" style="left:62.56%;top:28%;width:1.12%;height:1.87%"></div>
<div class="ytOopsTvBtn" style="left:62.56%;top:25.33%;width:1.12%;height:1.87%"></div>
<div class="ytOopsTvBtn" style="left:36.16%;top:29.6%;width:1.76%;height:2.93%"></div>
<div class="ytOopsTvBtn" style="left:36.16%;top:33.33%;width:1.76%;height:2.93%"></div>
<div class="ytOopsTvBtn" style="left:36.16%;top:37.07%;width:1.76%;height:2.93%"></div>
<div class="ytOopsTvBtn" style="left:17.28%;top:59.2%;width:1.76%;height:2.93%"></div>
<div class="ytOopsTvBtn" style="left:88%;top:64.53%;width:2.72%;height:4.53%"></div>
<div class="ytOopsTvBtn" style="left:88%;top:70.67%;width:2.72%;height:4.53%"></div>
<div class="ytOopsTvBtn" style="left:88%;top:76.53%;width:2.72%;height:4.53%"></div>
<div class="ytOopsTvBtn" style="left:88.48%;top:84%;width:0.96%;height:1.6%"></div>
<div class="ytOopsTvBtn" style="left:89.44%;top:84%;width:0.96%;height:1.6%"></div>
<div class="ytOopsTvBtn" style="left:90.4%;top:84%;width:0.96%;height:1.6%"></div>
<div class="ytOopsTvBtn" style="left:59.36%;top:88%;width:1.28%;height:2.13%"></div>
<div class="ytOopsTvBtn" style="left:38.88%;top:88%;width:1.28%;height:2.13%"></div>
<div class="ytOopsTvBtn" style="left:62.24%;top:33.87%;width:0.32%;height:0.53%"></div>
<div class="ytOopsTvBtn" style="left:62.72%;top:33.87%;width:0.32%;height:0.53%"></div>
<div class="ytOopsTvBtn" style="left:63.2%;top:33.87%;width:0.32%;height:0.53%"></div>
<!-- <3 https://stackoverflow.com/a/75054687/2251833 -->
<svg width='0' height='0'>
  <filter id='grainy' x='0' y='0' width='100%' height='100%'>
    <feTurbulence type='fractalNoise' baseFrequency='.737'/>
    <feColorMatrix type='saturate' values='0'/>
    <feBlend in='SourceGraphic' mode='overlay'/>
  </filter>
</svg>
</div>
</div>
<style>
    .ytErr {
        display: flex;
        flex-direction: column;
        align-items: center;
        width: 100%;
        border-radius: 4px;
        background: #f1f1f1;
        overflow: hidden;
    }
    /* These are the default selections colors, at least on Chrome+Windows. The background color I guessed, because it has both the base color and transparency, and I found that #0041C6CC seems to match perfectly with how the default selection looks. */
    .defSelect *::selection {
        color: #FFF;
        background: #0041C6CC;
    }
    .ytAlert {
        border: 2px #b91f1f solid;
        font-family: "YouTube Noto", Roboto, arial, sans-serif;
        font-size: 13px;
        font-weight: 700;
        text-align: center;
        vertical-align: middle;
        line-height: 15.6px;
        background: #FFF;
        width: 90%;
        margin: 16px 0;
    }
    .ytAlertHeader {
        width: 100%;
        background: #B91F1F;
        color: #FFF;
        padding: 11px 0 11px;
    }
    .ytOops {
        margin-top: 5.21%;
        max-width: 625px;
        width: 100%;
        aspect-ratio: 5 / 3;
        position: relative;
        filter: blur(0.3px);
    }
    .ytOopsTv {
        position: absolute;
        /*background: repeating-linear-gradient(#945424 2.2px, #0000 3.98px);*/
        background: repeating-linear-gradient(90deg, #9E5E2E 0px, #905020 2.1px, #8B4B1B 4.3px, #915122 8.5px, #965626 12px),
         repeating-linear-gradient(90deg, #9E5E2E 0px, #90502000 1.21px, #8B4B1B 2.43px, #91512200 3.85px, #965626 4.2px),
         repeating-linear-gradient(-15deg, #9E5E2ECC , #905020CC 10.21px, #8B4B1BCC 20.43px, #915122CC 30.85px, #965626CC 40.2px, #9E5E2ECC 51.2px);
        background-blend-mode:lighten;
    }
    .ytOopsTvScr {
        position: absolute;
        overflow: hidden;
        filter: none;
        transition: filter 0.2s;
    }
    .ytOopsTvScr:hover {
        filter: brightness(1.1);
    }
    .ytOopsTvScr::after {
        position: absolute;
        width: 100%;
        height: 100%;
        background: radial-gradient(circle, #CCC 75%, #BBB 90%, #AAA);
        transition: all 0.5s;
        filter: url(#grainy) blur(0.5px);
        content: "";
    }
    .ytOopsTvRect {
        position: absolute;
        background: #47260E;
    }
    .ytOopsTvLines {
        position: absolute;
        background: repeating-linear-gradient(#47260E, #47260E 0.9px, #0000 1.1px, #0000 2px);
    }
    .ytOopsTvBtn {
        position: absolute;
        background: #47260E;
        border-radius: 100%;
    }
</style>
<style>
    .urlBar {
        background: #3C3C3C;
        height: 34px;
        width: calc(100% - 12px);
        padding: 6px;
        /*border-radius: 4px;*/
        font-family: system-ui, sans-serif;
        font-size: 14px;
        transition: background 0.4s;
    }
    .urlBarInner *::selection {
        color: #000;
        background-color: #A8C7FA;
    }
    .urlBarInner {
        background: #282828;
        color: #C7C7C7;
        height: 34px;
        border-radius: 17px;
        width: 100%;
        transition: background 0.2s, border-radius 0.2s, font-size 0.4s;
        display: flex;
        align-items: center;
    }
    .urlBarInner:hover {
        background: #4A4A4A;
    }
    .urlBarText {
        text-overflow: ellipsis;
        overflow:hidden;
        white-space:nowrap;
        display:inline-block;
        margin-left:37px;
        width: calc(100% - 36px - 16px);
    }
    .urlBarIcon {
        width: 16px;
        height: 16px;
        margin: 5px;
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
    .urlBarDomain {
        color: #E3E3E3;
    }
    @media (width < 480px) {
        .urlBar {
            background: #121316;
            font-size: 12px;
        }
        .urlBarInner {
            background: #313745;
            color: #C4C6D0;
        }
        .urlBarInner:hover {
            background: #191C21;
            border-radius: 8px;
        }
        .urlBarInner *::selection {
            color: #E3E2E6;
            background-color: #373E4D;
        }
        .urlBarText {
            margin-left:26px;
            width: calc(100% - 25px - 16px);
        }
        .urlBarIcon {
            fill: #E3E2E6;
            background: #0000;
            padding-left: 1px;
        }
        .urlBarDomain {
            color: #E3E2E6;
        }
    }
</style>

Oh, seems like it doesn't let us do an open redirect after all. Next I tried **google.com** - still the same error. I tried **youtube.com**... and once again, the same error?

I then realized that I had fogotten the subdomain - **www\.youtube.com** does in-fact work with the redirect. And soon enough I discovered the redirects to work with any YouTube subdomain - **music\.youtube.com** and **admin\.youtube.com** both worked! We're still stuck on YouTube's domains, but at least we now have a bit more attack surface to work with.

## Part 3: Re-redirects

That **/signin** redirect wasn't the only one I found though - there was another one present on a different YouTube subdomain:

<div class="urlBox"><a href="https://accounts.youtube.com/accounts/SetSID?ssdc=1&sidt=&continue=https%3A%2F%2Fwww.google.com&tcc=1&dbus=EE">https://<span style="color:#FFF">accounts.youtube.com</span>/accounts/SetSID?ssdc=1&sidt=&continue=<span style="color:#FFF">https%3A%2F%2Fwww.google.com</span>&tcc=1&dbus=EE</a></div>

This one seems to be for Google account logins. For example, if you log in on **google.ee**, you'd get redirected through **accounts.google.com** and **accounts.youtube.com** to update the cookies on both of those domains. I played around with it a little and found that while it once again wasn't a full open redirect, it did allow a variety of Google's own domains in the *continue* parameter, including services such as Docs.

If we could redirect our iframe to **docs.google.com** it'd open up a lot of possibilities. Google Docs is built in a way where most of its pages set the *x-frame-options* header to *SAMEORIGIN*, meaning that we're not supposed to be able to frame those pages on other websites. However, with such a redirect in place, we'd end up with a same-origin iframe within Slides, allowing us to frame pages we're not supposed to, and do cool stuff to them!

Let's try chaining our previous path-traversed **/signin** redirect to the new **accounts.youtube.com** one and see if we can make it embed Docs pages within itself.

> graphics - docs inside docs

And meow - Docs inside Docs!! So epic!

## Part 4: Okay but what now?

So we have Docs inside of Docs, which is incredibly fun for a few minutes, but can we actually do anything useful with this? The document pages themselves already have clickjacking protections in place, and the only interesting interaction on the Docs homepage is deleting a document. We'll need to find something more impactful on the Docs domain.

You might think that the document editing pages themselves would be useful, but those pages already have protections in place because they're already (intentionally) framable on any website. If a page detects that it is within an iframe, it'll disable a lot of the dangerous functionality, such as the sharing options of the document.

> graphic - can't share framed document

This part here is what actually took me the longest to figure out. I spent a while looking for anything interesting on the **docs.google.com** domain to frame and clickjack. Looking through the Wayback Machine[^2] and trying various Google dorks[^1], I kept finding a bunch of old endpoints that would've been useful in the past, but now just redirect to Google Drive, which we cannot frame.

Going through link after link, I eventually stumbled upon this url: <span class="urlBox" style="white-space:nowrap">docs.google.com/file/d/{ID}/edit</span>. This page lets us preview and perform actions (such as sharing) on Google Drive files, and unlike the other links I found earlier, it stays on the **docs.google.com** domain instead of redirecting to Drive. And not only does it work with Drive files, it also works with folders and other such entities (such as Google Sites pages). You could even open up your Drive's "Root" folder[^root] with it!

<div class="genericContainer">
    <div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span class="urlBarDomain">docs.google.com</span>/file/d/0ALK4w9WgXcQUUk9PVA/edit</span></div></div>
    <div class="filePg defSelect">
        <div class="filePgH">
            <div class="filePgName"><span class="folderIcon" style="margin: 0 11px"><div></div><div></div></span>Root</div>
            <div class="filePgOpenW over640">Open with</div>
            <div style="height: 40px; display:flex; padding: 2px; gap: 8px;margin-left:auto;margin-right:2px">
                <div class="iconButton over480"><div class="dotsIcon"><div></div><div></div><div></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark over480"><div>Share</div><div style="display:flex"><div style="margin:auto" class="sldsDrop"></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark under480"><div>Share</div></div>
                <div class="sldsHpfp"><div>L</div></div>
            </div>
        </div>
        <div class="filePgNoPrev">No preview available</div>
        <div style="height:64px"></div>
    </div>
</div>
<style>
    .filePg {
        background: #1E1E1F;
        width: 100%;
        height: 480px;
        font-family: "Google Sans Text", "Google Sans", "Open Sans", Roboto, Arial, sans-serif;
        font-size: 16px;
        display: flex;
        flex-direction: column;
        position: relative;
    }
    .filePgH {
        display: flex;
        height: 64px;
        width: calc(100% - 24px);
        font-size: 14px;
        align-items: center;
        margin: 0px 12px;
    }
    .filePgName {
        font-size: 16px;
        font-weight: 501;
        color: #C4C7C5;
    }
    .folderIcon {
        display: inline-block;
        width: 18px;
        height: 15px;
    }
    .folderIcon > div:first-child {
        width: 8px;
        height: 0px;
        border-bottom: 3px solid #8F8F8F;
        border-left: none;
        border-top: none;
        border-right: 3px solid #0000;
        border-top-left-radius: 2px;
    }
    .folderIcon > div:last-child {
        width: 18px;
        height: 12px;
        background: #8F8F8F;
        border-radius: 0 0.75px 0.75px 0.75px;
    }
    .dotsIcon {
        height: 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        margin: auto;
    }
    .dotsIcon div {
        background: #C4C7C5;
        width: 4px;
        height: 4px;
        border-radius: 2px;
    }
    .iconButton {
        display: flex;
        width: 40px;
        height: 40px;
        border-radius: 20px;
        cursor: pointer;
        transition: background 0.1s;
    }
    .iconButton:hover {
        background: #2B2C2B;
    }
    .iconButton:active {
        background: #323232;
    }
    .iconButtonLight:hover {
        background: #F0F1F1;
    }
    .iconButtonLight:active {
        background: #DEDFDF;
    }
    .filePgOpenW {
        background: #131314;
        height: 18px;
        border-radius: 18px;
        border: 1px solid #8E918F;
        color: #C4C7C5;
        font-weight: 501;
        padding: 8px 16px;
        cursor: pointer;
        user-select: none;
        margin: auto;
        position: absolute;
        left: 0;
        right: 0;
        width: fit-content;
    }
    .filePgOpenW:hover {
        background: #212221;
    }
    .filePgOpenW:active {
        background: #29292A;
    }
    .filePgNoPrev {
        width: min(300px, 90%);
        height: 68px;
        background: #4C494C;
        border-radius: 12px;
        color: #FFF;
        font-size: 19px;
        margin: auto;
        text-align: center;
        display: flex;
        justify-content: center;
        align-items: center;
        box-shadow: 0px 10px 12px 5px #0002;
    }
</style>

The page has a share button that stays enabled even within an iframe. If we can trick someone into clicking the Share button, typing in our e-mail, and changing the permissions on some important folder, we'll gain access to it.

## Part 5: But can we?

But let's do a reality check - can we *really* trick someone into performing all those actions? Maybe, if we try hard enough, but even with all our iframing and clickjacking abilities it's going to take a lot to convince someone to do all that. I don't think the VRP panel[^3] would be very impressed with this much reliance on social engineering. We must find a way to make it more convincing - ideally condensing it down to just a single click.

Thinking of ways to improve the attack, I remembered the feature in Drive that lets you request access to other people's documents. Doing so sends out an e-mail with a cool little button to immediately manage the permissions.

<style>
    .gmailTable {
        position:absolute;
        background:#FFF;
        color: #222;
        max-width:420px;
        padding: 16px;
        border: 1px solid #CCC;
        box-shadow: 0 2px 4px #0002;
        top: 84px;
        left: max(0px, min(104px, calc(100% - 456px)));
        z-index: 1;
    }
    .gmailTable td:first-child {
        color:#999;
        white-space:nowrap;
        text-align:right;
        vertical-align: top;
        padding-right: 12px;
    }
</style>
<div class="genericContainer defSelect" style="position:relative;background:#FFF;font-family:'Google Sans',Roboto,Arial,Helvetica,sans-serif;font-size:14px;color:#3C4043">
    <input type="checkbox" style="display:none" id="gmailInfoCheck" checked />
    <div class="gmailTable" id="gmailTable1">
        <label for="gmailInfoCheck"><div style="text-align:right;cursor:pointer" class="under480">×</div></label>
        <table>
            <tr><td>from:</td><td style="color:#5E5E5E"><b style="color:#1F1F1F">Lyra Rebane (via Google Drive)</b> &lt;drive-shares-dm-noreply@google.com&gt;</td></tr>
            <tr><td>reply-to:</td><td>Lyra Rebane &lt;lyra.horse<wbr>@gmail.com&gt;</td></tr>
            <tr><td>to:</td><td>lyra.horse<wbr>@gmail.com</td></tr>
            <tr><td>date:</td><td>Sep 19, 2024, 10:30 AM</td></tr>
            <tr><td>subject:</td><td>Share request for "Secret Folder"</td></tr>
            <tr><td>mailed-by:</td><td>doclist.bounces.<wbr>google.com</td></tr>
            <tr><td>signed-by:</td><td>google.com</td></tr>
            <tr><td>security:</td><td>🔒 Standard encryption (TLS) <a href="https://blog.aegrel.ee/" style="color:inherit;text-decoration:underline">Learn more</a></td></tr>
        </table>
    </div>
    <div style="display:flex;align-items:center;margin:12px 8px 12px 70px"><input type="checkbox" style="display:none" id="gmailInboxCheck" /><div style="font-size:22px;color:#1F1F1F">Share request for "Secret Folder"</div><div style="border-radius:4px 0 0 4px;padding-right:2px;margin-left:10px" class="inboxBtn over560" id="inboxBtn1">Inbox</div><label id="inboxBtn2" for="gmailInboxCheck"><div style="border-radius:0 4px 4px 0;padding-left:2px" class="inboxBtn over560">×</div></label></div>
    <div style="color:#5E5E5E;font-size:12px;display:flex;margin-right:12px">
        <div style="flex-shrink:0;width:40px;height:40px;background:#A0C3FF;border-radius:40px;margin:-2px 16px;overflow:hidden"><div style="background:#4374E0;width:15px;height:15px;border-radius:30px;margin:9px auto 2px;"></div><div style="background:#4374E0;width:27px;height:30px;border-radius:30px;margin:auto"></div></div>
        <div style="overflow:hidden;white-space:nowrap">
            <div style="text-overflow:ellipsis;overflow:hidden"><b style="color:#1F1F1F">Lyra Rebane (via Google Drive)</b> &lt;drive-shares-dm-noreply@google.com&gt;</div>
            <div style="display:flex;width:fit-content">to me <label for="gmailInfoCheck"><div class="dropBtnWrapper"><div class="sldsDrop"></div></div></label></div>
        </div>
        <div style="margin-left:auto;flex-shrink:0"><span class="over560">Sep 19th, 2024, </span>10:30 AM</div>
        <div class="iconButton iconButtonLight over480" style="flex-shrink:0;transform:scale(0.6); margin: -11px -4px"><div class="dotsIcon" style="filter:brightness(0.6)"><div></div><div></div><div></div></div></div>
    </div>
    <div style="border-radius:8px;border:1px solid #dadce0;width:75%;margin:24px auto;padding:4.5%">
        <div style="margin-bottom:32px;font-size:28px">Share a folder?</div>
        <div style="display:flex">
        <div class="shareDlgCircle" style="width:50px;height:50px"><div style="width:100%;height:100%;background:#7B1FA2;color:#FFF;text-align:center;font-size:30px;line-height:50px;user-select:none;border-radius:50px">L</div></div>
        <div style="margin-left:12px">
        <div style="color:#202124;font-size:16px">Lyra Rebane (lyra.horse<wbr>@gmail.com) is <b>requesting access</b> to the following folder:</div>
        <div style="margin:24px 0 28px;color:#5f6368;font-size:16px">hi pls give access kthxbye</div>
        </div>
        </div>
        <div style="cursor:pointer;width:fit-content;padding:8px 5px 7px;border:1px solid #DADCE0;border-radius:32px;display:flex;font-weight:501;margin-bottom:36px"><span class="folderIcon" style="margin: 0 8px;transform:scale(0.9);filter:brightness(0.615)"><div style="transform:translate(-0.05px,0.4px) scaleY(1.1)"></div><div></div></span><div style="padding-right:6px;letter-spacing:.25px">Secret Folder</div></div>
        <a href="https://docs.google.com/file/d/1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL/edit?usp=sharing_esp&userstoinvite=lyra.horse@gmail.com&sharingaction=manageaccess&role=writer&ts=66e724ba" style="display:inline-block"><div style="cursor:pointer;width:fit-content;padding:9px 24px 10px;background:#1A73E8;color:#FFF;border-radius:32px;display:flex;font-weight:501;letter-spacing:.25px">Manage sharing</div></a>
    </div>
</div>

The button in that e-mail links to <span class="urlBox">https://drive.google.com/drive/folders/{ID}?usp=sharing_esp&userstoinvite=lyra.horse@gmail.com&sharingaction=manageaccess&role=writer&ts=66e724ba
</span>, which when opened, pops up the Share dialog with a notification of the request. Of course, that's a Drive link, not a Docs one, but I tried copying all of the query parameters over to our Docs link and to my surprise, it worked!

<div class="genericContainer">
    <div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span class="urlBarDomain">docs.google.com</span>/file/d/1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL/edit?usp=sharing_esp&userstoinvite=lyra.horse@gmail.com&sharingaction=manageaccess&role=writer&ts=66e724ba</span></div></div>
    <div class="filePg defSelect" style="height:512px">
        <div class="filePgH">
            <div class="filePgName"><span class="folderIcon" style="margin: 0 11px"><div></div><div></div></span>Secret Folder</div>
            <div class="filePgOpenW over640">Open with</div>
            <div style="height: 40px; display:flex; padding: 2px; gap: 8px;margin-left:auto;margin-right:2px">
                <div class="iconButton over480"><div class="dotsIcon"><div></div><div></div><div></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark over480"><div>Share</div><div style="display:flex"><div style="margin:auto" class="sldsDrop"></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark under480"><div>Share</div></div>
                <div class="sldsHpfp"><div>L</div></div>
            </div>
        </div>
        <div class="filePgO">
            <div class="shareDlg">
                <input type="checkbox" style="display:none" id="reviewDialog"  />
                <div id="shareDlgReview1">
                <a href="https://www.youtube.com/watch?v=yD2FSwTy2lw" title="no one's around to help"><div class="over360 iconButton iconButtonLight" style="position:absolute;right:6px;top:10px"><div class="helpIcon">?</div></div></a>
                <div class="shareDlgTitle">Share "Secret Folder"</div>
                <div class="shareDlgBanner">Lyra Rebane asked to be an editor<span style="padding-left:0"><label for="reviewDialog" style="cursor:inherit">Review</label></span><span class="over480">✖</span></div>
                <input class="shareDlgTbox shareDlgBbox" placeholder="Add people, groups, and calendar events"></input>
                <div class="shareDlgSubtitle">People with access</div>
                <div class="shareDlgEntry shareDlgEntryH"><div class="shareDlgCircle"><div style="width:100%;height:100%;background:#7B1FA2;color:#FFF;text-align:center;font-size:20px;line-height:32px;user-select:none;border-radius:20px">L</div></div><div style="margin-left:10px"><div style="font-weight:501;margin-left:4px">Lyra Rebane (you)</div><div style="color:#444746;font-size:12px;letter-spacing:0.1px;margin-left:4px">lyra.horse@gmail.com</div></div><div style="margin-left:auto;color:#AAA;letter-spacing:0.15px;user-select:none" class="over480">Owner</div></div>
                <div class="shareDlgSubtitle">General access</div>
                <div class="shareDlgEntry shareDlgEntryH"><div class="shareDlgCircle"><svg width="20" height="20" viewBox="0 0 24 24" style="margin:auto"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"></path></svg></div><div style="margin-left:10px"><div class="shareDlgDrop over360">Restricted<div class="sldsDrop" style="margin: 0 2px 0 12px"></div></div><div style="color:#444746;font-size:12px;letter-spacing:0.1px;margin-left:4px">Only people with access can open with the link</div></div></div>
                <div style="display:flex;margin: 16px 0;justify-content: space-between"><div class="over360 shareDlgBtn shareDlgBtnWhite">Copy link</div><div class="shareDlgBtn shareDlgBtnBlue">Done</div></div>
                </div>
                <div id="shareDlgReview2">
                    <label for="reviewDialog" style="cursor:inherit"><div class="iconButton iconButtonLight" style="position:absolute;left:16px;top:12px"><svg width="24" height="24" viewBox="0 0 24 24" style="margin:auto"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"></path></svg></div></label>
                    <div class="shareDlgTitle" style="margin-left: 42px">Request for access</div>
                    <div class="shareDlgEntry"><div class="shareDlgCircle"><div style="width:100%;height:100%;background:#7B1FA2;color:#FFF;text-align:center;font-size:20px;line-height:32px;user-select:none;border-radius:20px">L</div></div><div style="margin-left:10px"><div style="font-weight:501;margin-left:4px">Lyra Rebane asked to be an editor</div><div style="color:#444746;font-size:12px;letter-spacing:0.1px;margin-left:4px">lyra.horse@gmail.com</div></div></div>
                    <div style="margin-left:46px">
                        <div style="background:#D3E3FD;border-radius:4px 16px 16px;width:fit-content;padding:8px;margin-bottom:24px">hi pls give access kthxbye</div>
                        <div class="shareDlgBbox" style="padding:10px 18px;width:fit-content;user-select:none;cursor:default;display:flex;align-items:center">Editor<div class="sldsDrop" style="margin-left:12px"></div></div>
                        <div style="display:flex;align-items:center;margin-top:30px;margin-bottom:15px"><input id="notifyChk" type="checkbox" style="width:18px;height:18px;filter: brightness(0.8) contrast(1.5);margin:1px;margin-right:16px" checked><label for="notifyChk">Notify</label><div title="This checkbox does nothing because this is just a static blogpost with cool CSS." class="helpIcon" style="margin:0 0 0 8px">?</div></div>
                        <input class="shareDlgTbox shareDlgBbox" style="padding:8px 16px;font-size: 14px;" placeholder="Message"></input>
                        <div style="display:flex;margin: 28px 0;justify-content: flex-end"><div class="shareDlgBtn shareDlgBtnWhite">Decline</div><div class="shareDlgBtn shareDlgBtnBlue" style="margin-left:8px">Share</div></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<style>
    .inboxBtn {
        background:#DDD;
        color:#666;
        font-size: 12px;
        padding:0 4px;
        cursor: pointer;
    }
    .inboxBtn:hover {
        background:#666;
        color:#DDD;
    }
    .dropBtnWrapper {
        margin: auto 1px;
        padding: 5px 3px;
        border-radius: 4px;
        transition: background 0.1s;
        cursor: pointer;
    }
    .dropBtnWrapper:hover {
        background: #F2F2F2;
    }
    .dropBtnWrapper:active {
        background: #E4E4E4;
    }
    input#reviewDialog[type="checkbox"]:checked ~ #shareDlgReview1 {
        display:none;
    }
    input#gmailInfoCheck[type="checkbox"]:checked ~ #gmailTable1 {
        display:none;
    }
    input#gmailInboxCheck[type="checkbox"]:checked ~ #inboxBtn1,
    input#gmailInboxCheck[type="checkbox"]:checked ~ #inboxBtn2 {
        display:none;
    }
    input#reviewDialog[type="checkbox"]:not(:checked) ~ #shareDlgReview2 {
        display:none;
    }
    .filePgO {
        width: 100%;
        height: 100%;
        z-index: 1;
        position: absolute;
        background: #0008;
        display: flex;
    }
    .shareDlg {
        position: relative;
        width: calc(min(512px, 90%) - 48px);
        height: fit-content;
        background: white;
        border-radius: 8px;
        margin: auto;
        padding: 16px 24px;
        font-size: 14px;
        color: #1F1F1F;
    }
    .shareDlgTitle {
        font-size: 22px;
    }
    .shareDlgBanner {
        background: #D3E3FD;
        padding: 13px;
        border-radius: 8px;
        color: #0F264D;
        display: flex;
        align-items: center;
        margin: 16px 0;
    }
    .shareDlgBanner span:first-child {
        margin-left: auto;
    }
    /* Apologizes,  I was too lazy to make actual buttons here :P */
    .shareDlgBanner span {
        color: #0842A0;
        font-weight: 501;
        cursor: pointer;
        padding-left: min(26px, max(12px, 5%));
        user-select: none;
    }
    .shareDlgBanner span:hover {
        color: #1E64D4;
    }
    .shareDlgBanner span:active {
        color: #3574D8;
    }
    .shareDlgBbox {
        border: 1px solid #747775;
        border-radius: 4px;
        outline: 2px solid #0000;
        outline-offset: -2px;
        transition: outline 0.2s;
    }
    .shareDlgTbox {
        display: block;
        height: calc(48px - 32px);
        width: calc(100% - 2px - 32px);
        padding: 16px;
    }
    .shareDlgBbox:focus {
        outline: 2px solid #0B57D0;
    }
    .shareDlgBbox:active {
        outline: 2px solid #0B57D0;
    }
    .shareDlgSubtitle {
        font-size: 16px;
        margin: 16px 0 0;
        font-weight: 501;
    }
    .helpIcon {
        width: 12px;
        height: 12px;
        color: #444746;
        border: 2px solid #444746;
        border-radius: 13px;
        font-weight: bold;
        font-size: 13px;
        line-height: 13px;
        text-align: center;
        margin: auto;
        user-select: none;
    }
    .shareDlgBtn {
        display: flex;
        font-weight: 501;
        user-select: none;
        font-size: 14px;
        height: 38px;
        padding: 0 24px;
        align-items: center;
        border-radius: 40px;
        cursor: pointer;
        transition: background 0.15s, box-shadow 0.15s;
    }
    .shareDlgBtnWhite {
        border: 1px solid #747775;
        background: #FFF;
        color: #0B57D0;
    }
    .shareDlgBtnWhite:hover {
        background: #ECF2FC;
    }
    .shareDlgBtnWhite:active {
        background: #D5E1F7;
    }
    .shareDlgBtnBlue {
        border: 1px solid #0B57D0;
        background: #0B57D0;
        color: #FFF;
        box-shadow: 0px 1px 3px 1px #0000;
    }
    .shareDlgBtnBlue:hover {
        background: #1E64D4;
        box-shadow: 0px 1px 3px 1px #0003;
    }
    .shareDlgBtnBlue:active {
        background: #3574D8;
        box-shadow: 0px 1px 3px 1px #0000;
    }
    .shareDlgCircle {
        display: flex;
        width: 32px;
        height: 32px;
        flex-shrink: 0;
        background: #E3E3E3;
        border-radius: 32px;
    }
    .shareDlgEntry {
        display: flex;
        align-items: center;
        padding: 8px 0;
        height: 46px;
    }
    .shareDlgEntryH:hover {
        background: #EEE;
        box-shadow: -24px 0 0 #EEE, 24px 0 0 #EEE;
    }
    .shareDlgDrop {
        width: fit-content;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 14px;
        font-weight: 501;
        transition: background 0.1s;
        user-select: none;
        cursor: pointer;
        display: flex;
        align-items: center;
    }
    .shareDlgDrop:hover {
        background: #DFDFDF;
    }
    .shareDlgDrop:active {
        background: #CECECE;
    }
    .shareDlgBubble {
        border: 1px solid #747775;
        padding:4px 12px;
        border-radius: 32px;
        font-weight: 501;
        background: #F8FAFD;
        cursor: pointer;
        display: flex;
        align-items: center;
        text-align: center;
        transition: background 0.1s, border 0.1s;
    }
    .shareDlgBubble:hover {
        background: #F0F3F6;
    }
    .shareDlgBubble:active {
        background: #B1D3E8;
        border: 1px solid #0B57D0;
    }
</style>

<!--<div style="width:100%;text-align:center;margin-top:4px"><i>Try <span class="fineText">clicking</span><span class="coarseText">tapping</span> "<span style="color:#0842A0;font-weight:bold"><label style="cursor:pointer" for="reviewDialog">Review</label></span>" above to see the second screen!</i></div>-->

In its current state, this page requires us to make two clicks to complete the attack - first a click on the "Review" label, and then a click on the "Share" button (try <span class="fineText">clicking</span><span class="coarseText">tapping</span> "<span style="color:#0842A0;font-weight:bold"><label style="cursor:pointer" for="reviewDialog">Review</label></span>" above). That's already quite good, but I still *really* wanted to get the entire attack down to just one click.

I pulled out my DevTools and began digging through the JavaScript of the page to see how the query parameters are handled. As a simple test, I started off with just the *userstoinvite* query parameter.

<div class="genericContainer">
    <div class="urlBar"><div class="urlBarInner"><div class="urlBarIcon"><svg xmlns="http://www.w3.org/2000/svg"><path d="M11.55 13.52a2.27 2.27 0 0 1 -1.68 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68a2.27 2.27 0 0 1 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.45c0.25 0 0.47 -0.09 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.27 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.26 0.64c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.4 0.27 0.65 0.27Zm-9.47 -0.1v-1.63H7.98v1.63Zm2.37 -4.75a2.27 2.27 0 0 1 -1.67 -0.69a2.29 2.29 0 0 1 -0.69 -1.68c0 -0.66 0.23 -1.22 0.7 -1.68a2.3 2.3 0 0 1 1.68 -0.69c0.66 0 1.22 0.23 1.68 0.69c0.46 0.46 0.69 1.02 0.69 1.68c0 0.66 -0.23 1.22 -0.69 1.68c-0.46 0.46 -1.02 0.69 -1.68 0.69Zm0 -1.46a0.88 0.88 0 0 0 0.65 -0.27a0.88 0.88 0 0 0 0.27 -0.64a0.89 0.89 0 0 0 -0.26 -0.65a0.88 0.88 0 0 0 -0.65 -0.27a0.88 0.88 0 0 0 -0.65 0.27a0.88 0.88 0 0 0 -0.27 0.65c0 0.25 0.09 0.47 0.27 0.65c0.18 0.18 0.39 0.27 0.65 0.27Zm3.57 -0.1V4.03h5.9v1.63Zm0 0Z"/></svg></div><span class="urlBarText"><span class="urlBarDomain">docs.google.com</span>/file/d/<span class="over720">1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL</span><span class="under720">...</span>/edit?userstoinvite=lyra.horse@gmail.com</span></div></div>
    <div class="filePg defSelect" style="height:512px">
        <div class="filePgH">
            <div class="filePgName"><span class="folderIcon" style="margin: 0 11px"><div></div><div></div></span>Secret Folder</div>
            <div class="filePgOpenW over640">Open with</div>
            <div style="height: 40px; display:flex; padding: 2px; gap: 8px;margin-left:auto;margin-right:2px">
                <div class="iconButton over480"><div class="dotsIcon"><div></div><div></div><div></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark over480"><div>Share</div><div style="display:flex"><div style="margin:auto" class="sldsDrop"></div></div></div>
                <div class="sldsHbtn sldsHbtnBlueDark under480"><div>Share</div></div>
                <div class="sldsHpfp"><div>L</div></div>
            </div>
        </div>
        <div class="filePgO">
            <div class="shareDlg">
                    <a href="https://www.youtube.com/watch?v=6XFX8hL6YdI" title="there's no one in moominvalley to help"><div class="over360 iconButton iconButtonLight" style="position:absolute;right:6px;top:10px"><div class="helpIcon">?</div></div></a>
                    <div class="iconButton iconButtonLight" style="position:absolute;left:16px;top:12px"><svg width="24" height="24" viewBox="0 0 24 24" style="margin:auto"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"></path></svg></div>
                    <div class="shareDlgTitle" style="margin-left: 42px">Share "Secret Folder"</div>
                    <div style="display:flex;margin-top:20px"><div class="shareDlgBbox" style="padding:10px 18px;flex-grow:1;user-select:none;cursor:default;display:flex;align-items:center;margin-right:10px"><div class="shareDlgBubble"><div style="background:#7B1FA2;height:17px;width:17px;border-radius:17px;transform:translate(-4px,0);color:#FFF;line-height:17px;font-weight:400;font-size:12px" class="over480">L</div>Lyra Rebane<span style="margin-left:10px" class="over360">✖</span></div></div><div class="shareDlgBbox" style="padding:14px 18px;width:fit-content;user-select:none;cursor:default;display:flex;align-items:center">Editor<div class="sldsDrop over360" style="margin-left:12px"></div></div></div>
                    <div style="display:flex;align-items:center;margin-top:16px;margin-bottom:14px"><input id="notifyChk2" type="checkbox" style="width:18px;height:18px;filter: brightness(0.8) contrast(1.5);margin:1px;margin-right:16px" checked><label for="notifyChk2">Notify people</label></div>
                        <textarea class="shareDlgTbox shareDlgBbox" style="padding:8px 16px;font-size: 14px;height:96px;font-family:inherit;resize: none" placeholder="Message"></textarea>
                        <div style="display:flex;margin: 28px 0 8px;justify-content: flex-end"><div class="shareDlgBtn shareDlgBtnWhite">Cancel</div><div class="shareDlgBtn shareDlgBtnBlue" style="margin-left:8px">Send</div></div>
            </div>
        </div>
    </div>
</div>

And wow!? I had accidentally stumbled upon the perfect share dialog URL. For some reason, leaving out all the other query parameters makes the share dialog just auto-fill the e-mail field from the query parameter, defaulting to giving out *Editor* permissions.

Pretty much all we need to do here is convince someone to do a single click on the ambiguously labeled "Send" button, and we're set!

## Part 6: Re-re-redirects

I began putting the attack together, combining all the cool tricks we've come up with so far.

<!-- todo: replace with real urls ; add line breaks and color the various parts of the urls -->

<ol style="word-break: break-all">
<li>We first take cool little docs invite url.<br>
<span class="urlBox">https://docs.google.com/file/d/1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL/edit?userstoinvite=lyra.horse@gmail.com</span></li>
<li>Then we put it inside the <b>accounts.youtube.com</b> redirect.<br>
<span class="urlBox">https://accounts.youtube.com/accounts/SetSID?continue=<span style="color:#999; font-weight: normal; filter: blur(1px)">https%3A%2F%2Fdocs.google.com%2Ffile%2Fd%2F1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL%2Fedit%3Fuserstoinvite%3Dlyra.horse%40gmail.com</span></span></li>
<li>Then we put <i>that</i> into the <b>youtube.com/signin</b> redirect.<br>
<span class="urlBox">https://www.youtube.com/signin?next=<span style="color:#999; font-weight: normal; filter: blur(1px)">https%3A%2F%2Faccounts.youtube.com%2Faccounts%2FSetSID%3Fcontinue%3D<span style="color:#666">https%3A%2F%2Fdocs.google.com%252Ffile%252Fd%252F1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL%252Fedit%253Fuserstoinvite%253Dlyra.horse%2540gmail.com</span></span></span></li>
<li>And finally, we turn it into a path traversed "videoid" we can embed in our slides.<br>
<span class="urlBox">../signin?next=https%3A%2F%2Faccounts.youtube.com%2Faccounts%2FSetSID%3Fcontinue%3Dhttps%3A%2F%2Fdocs.google.com%252Fa%252Fa%252Ffile%252Fd%252F1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL%252Fedit%253Fuserstoinvite%253Dlyra.horse%2540gmail.com</span></li>
</ol>

And there we go! I threw it in my slides and...

<div class="genericContainer" style="background:#F9FBFD">
    <div class="sldsMain" style="margin:20px 10px">
            <div class="sldsSlide" style="aspect-ratio:unset;height:fit-content;">
                <div style="width:94%;height:90%;margin:12px auto;overflow:hidden;border: 2px inset #EEE;background:#0E0E0E">
<div class="needAccess">
    <div>
        <div class="needAccessLogo"><span style="font-weight:501;filter: blur(0.4px)"><span style="color:#4285F4">G</span><span style="color:#EA4335">o</span><span style="color:#FBBC05">o</span><span style="color:#4285F4">g</span><span style="color:#34A853">l</span><span style="color:#EA4335">e</span></span> Drive</div>
        <div style="font-size:32px;color:#202124;width: 100%;margin: 8px 0;">You need access</div>
        <div class="needAccessText"><a href="https://docs.google.com/presentation/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit">Open the document directly</a> to see if requesting access is possible, or switch to an account with access. <a href="https://www.youtube.com/watch?v=Hh9iFc5Sdso">Learn more</a></div>
        <div class="needAccessSignedAs">
            You are signed in as
            <div style="display:flex"><div class="over360" style="width:20px;height:20px;background:#4285F4;border-radius:100px;vertical-align: text-top"><div style="width:14px;height:14px;margin:3px;overflow:hidden;border-radius:10px"><div style="width:6px;height:5.5px;margin:2px auto 1.5px;background:#FFF;border-radius:10px"></div><div style="width:12px;height:14px;margin:auto;background:#FFF;border-radius:10px"></div></div></div><span style="margin: 0 7px">lyra.horse@gmail.com</span></div>
        </div>
    </div>
</div>
                </div>
            </div>
        </div>
</div>

<style>
    .needAccess {
        font-family: "Google Sans", "Open Sans", Roboto, sans-serif;
        display: flex;
        width: 100%;
        min-height: 400px;
        height: fit-content;
        background: #FFF;
        font-size: 14px;
    }
    .needAccess > div {
        display: flex;
        flex-direction: column;
        margin: auto;
        padding: 50px 0;
        align-items: center;
        width: 90%;
        max-width: 378px;
    }
    .needAccessLogo {
        font-size: 32px;
        font-family: "Product Sans", Arial, Helvetica, sans-serif;
        color: #0008;
        width: 100%;
        margin-bottom: 16px;
    }
    .needAccessSignedAs {
        display: flex;
        align-items: center;
        flex-direction: column;
        text-align: center;
        width: fit-content;
        font-size: 13px;
        margin-top: 32px;
    }
    .needAccessSignedAs > div {
        font-weight: 501;
        border: 1px solid #DADCE0;
        width: fit-content;
        font-size: 14px;
        border-radius: 100px;
        padding: 5px 7px;
        margin-top: 9px;
        color: #202124;
    }
    .needAccessText {
        width: 100%;
        color: #5F6368;
        letter-spacing: 0.2px;
        line-height: 20px;
    }
    .needAccessText a {
        color: #1a73e8;
    }
</style>

...it didn't work, why?

It seems like Docs has some sort of a mitigation in place that prevents me from using a cross-site redirect for the file page within an iframe. More precisely, it checks for the *Sec-Fetch-Dest* and and *Sec-Fetch-Site* headers, and if they're both set to *iframe* and *cross-site* respectively, we get a 403 back. Pretty weird.

I got the opportunity to chat with a couple security people from Google, so I asked about this behavior, and it seems like this is some sort of a mitigation to prevent cross-origin framing on the server-side. I'm still not entirely sure as to what threat scenario it'd be useful in, but the idea is that an iframe can tell whether it's on a same-origin page or not from just the *Sec-Fetch-Site* header. On a cross-origin page, the header will *always* be set to *cross-site*, even if the redirect within the iframe is same-origin.

Of course, that could be detected more reliably on the client-side with JavaScript and whatnot, but the headers are the only way for a server to tell *before* sending out a response. A side-effect of the server-side detection is that even though both our frames are same-origin, a cross-origin redirect within the iframe will still end up with the *cross-site* header. To bypass *that*, we need to perform a same-origin redirect inside of the iframe.

To put it simply, we're currently doing:

<span class="urlBox" style="white-space:nowrap">accounts.youtube.com</span> <span style="color:#F00;font-weight:bold">(cross-site)</span> → <span class="urlBox" style="white-space:nowrap">docs.google.com/file/d/.../edit</span> <span style="color:#F00;font-weight:bold">(403)</span>

so to bypass that, we want to chain a redirect like this:

<span class="urlBox" style="white-space:nowrap">accounts.youtube.com</span> <span style="color:#F00;font-weight:bold">(cross-site)</span> → <span class="urlBox" style="white-space:nowrap">docs.google.com/???</span> <span style="color:green;font-weight:bold">(same-origin)</span> → <span class="urlBox" style="white-space:nowrap">docs.google.com/file/d/.../edit</span> <span style="color:green;font-weight:bold">(200)</span>

and it should work! But we have to find something that'd work for that part in the middle. And lucky for us, I had already spotted something like that in my googling earlier.

It seems like there's an old legacy GSuite URL format of **docs.google.com/a/&lt;domain&gt;/...**, which probably did something useful years ago, but these days just disappears when you open an URL. If you're logged out, you must find some working donor URL to use, such as **/a/wyo.gov/**[^wyo], but logged in you can even do **/a/a/** and it'll just work.

Here are a couple of example URLs to try out.

This one should work regardless of your login state:

<div class="urlBox" style="margin-top:-12px"><a href="https://docs.google.com/a/wyo.gov/file/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit">https://docs.google.com<span style="color:#FFF">/a/wyo.gov/</span>file/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit</a></div>

And this one requires that you be logged into any Google account:

<div class="urlBox" style="margin-top:-12px"><a href="https://docs.google.com/a/a/file/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit">https://docs.google.com<span style="color:#FFF">/a/a/</span>file/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit</a></div>

Both will end up redirecting to <span class="urlBox">https://docs.google.com/file/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit</span>.

With that figured out, let's throw the **/a/a/** thing into our "videoid" from earlier:
<span class="urlBox">../signin?next=https%3A%2F%2Faccounts.youtube.com%2Faccounts%2FSetSID%3Fcontinue%3Dhttps%3A%2F%2Fdocs.google.com%252Ffile%252Fd%252F1sHy3aQXsIlnOCj-mBFxQ0ZXm4TzjjfFL%252Fedit%253Fuserstoinvite%253Dlyra.horse%2540gmail.com</span>

<div class="genericContainer" style="background:#F9FBFD">
    <div class="sldsMain" style="margin:20px 10px">
            <div class="sldsSlide" style="aspect-ratio:unset;height:420px">
                <div style="width:94%;height:90%;margin:auto;overflow:hidden;border: 2px inset #EEE;background:#0E0E0E"><div style="transform:scale(0.8);width:125%;height:125%;margin:-6.75% 0 0 -12.5%">
    <div class="filePg defSelect" style="width:100%;height:100%">
        <div class="filePgO">
            <div class="shareDlg">
                    <div class="iconButton iconButtonLight" style="position:absolute;left:16px;top:12px"><svg width="24" height="24" viewBox="0 0 24 24" style="margin:auto"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"></path></svg></div>
                    <div class="shareDlgTitle" style="margin-left: 42px">Share "Secret Folder"</div>
                    <div style="display:flex;margin-top:20px"><div class="shareDlgBbox" style="padding:10px 18px;flex-grow:1;user-select:none;cursor:default;display:flex;align-items:center;margin-right:10px"><div class="shareDlgBubble"><div style="background:#7B1FA2;height:17px;width:17px;border-radius:17px;transform:translate(-4px,0);color:#FFF;line-height:17px;font-weight:400;font-size:12px" class="over480">L</div>Lyra Rebane<span style="margin-left:10px" class="over360">✖</span></div></div><div class="shareDlgBbox" style="padding:14px 18px;width:fit-content;user-select:none;cursor:default;display:flex;align-items:center">Editor<div class="sldsDrop over360" style="margin-left:12px"></div></div></div>
                    <div style="display:flex;align-items:center;margin-top:16px;margin-bottom:14px"><input id="notifyChk2" type="checkbox" style="width:18px;height:18px;filter: brightness(0.8) contrast(1.5);margin:1px;margin-right:16px" checked><label for="notifyChk2">Notify people</label></div>
                        <textarea class="shareDlgTbox shareDlgBbox over480" style="padding:8px 16px;font-size: 14px;height:96px;font-family:inherit;resize: none" placeholder="Message"></textarea>
                        <div style="display:flex;margin: 28px 0 8px;justify-content: flex-end"><div class="shareDlgBtn shareDlgBtnWhite">Cancel</div><div class="shareDlgBtn shareDlgBtnBlue" style="margin-left:8px">Send</div></div>
            </div>
        </div>
    </div>
                </div> </div>
            </div>
        </div>
</div>

And it works!

<!--
I wanted to throw a fun Sheets-style table here, but ended up scrapping the idea.
Feel free to uncomment to see what it looked like in its WIP state :).
<div class="sheetsTbl">
<table>
  <thead>
    <tr>
      <th scope="col"></th>
      <th scope="col">A</th>
      <th scope="col">B</th>
      <th scope="col">C</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">1</th>
      <td>Sec-Fetch-Dest/Site</td>
      <td>document</td>
      <td>iframe</td>
    </tr>
    <tr>
      <th scope="row">2</th>
      <td>same-origin</td>
      <td>✅</td>
      <td>✅</td>
    </tr>
    <tr>
      <th scope="row">3</th>
      <td>cross-site</td>
      <td>✅</td>
      <td>❌</td>
    </tr>
  </tbody>
</table>
</div>
<style>
    .sheetsTbl {
        width: 100%;
        overflow: hidden;
    }
    .sheetsTbl table {
        background: #FFF;
        color: #000;
        font-family: "Google Sans", Roboto, RobotoDraft, Helvetica, Arial, sans-serif;
        border-collapse: collapse;
    }
    .sheetsTbl th, .sheetsTbl td, .sheetsTbl tr {
        border: solid 1px #E1E1E1;
    }
    .sheetsTbl th {
        max-width: 100px;
        width: calc(min(20vw, 100px));
    }
    .sheetsTbl th:first-child {
        min-width: 45px;
        width: 45px;
        background: #F00;
    }
    .sheetsTbl .sheetsTblFiller {
        min-width: 100px;
        max-width: 100px;
    }
</style>
-->

## Part 7: Finishing touches

With our share dialog inside a presentation, all we need to do now is cover it up with other stuff to make it look presentable. Since all we need to do here is get someone to click the "Send" button, I decided to make my demo look like Google Forms.

<div class="genericContainer" style="background:#F9FBFD">
    <div class="sldsMain" style="margin:20px 10px">
            <div class="sldsSlide" style="aspect-ratio:unset;height:420px">
                <div id="formContainer" style="position:relative;width:94%;height:90%;margin:auto;overflow:hidden;border: 2px inset #EEE;background:#F0EBF8">
                    <div style="position:absolute;background:#FFF;border-radius:4px;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;display:flex;margin:auto;left:0;right:0;padding:8px">
                        <div style="display:flex;margin: 28px 0 8px;justify-content: flex-end">
                            <div class="shareDlgBtn shareDlgBtnWhite">Cancel</div>
                        <div class="shareDlgBtn shareDlgBtnBlue" style="margin-left:8px">Send</div></div>
                    </div>
                    <div id="formOverlay">
                    <div class="formColorOverlay" style="background:#F0EBF8;pointer-events:none;position:absolute;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;left:0;right:0;display:flex;margin:auto;padding:8px;transform:translateX(-100px);"></div>
                    <div class="formColorOverlay" style="background:#F0EBF8;pointer-events:none;position:absolute;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;left:0;right:0;display:flex;margin:auto;padding:8px;transform:translateY(-64px);"></div>
                    <div class="formColorOverlay" style="background:#F0EBF8;pointer-events:none;position:absolute;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;left:0;right:0;display:flex;margin:auto;padding:8px;transform:translateY(264px);"></div>
                    <div class="formColorOverlay" style="background:#F0EBF8;pointer-events:none;position:absolute;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;left:0;right:0;display:flex;margin:auto;padding:8px;transform:translateX(408px);"></div>
                    <div style="pointer-events:none;position:absolute;border-radius:4px;width:min(400px,100%);height:256px;flex-direction:column;justify-content:flex-end;left:0;right:0;display:flex;margin:auto;padding:8px">
                        <div style="width:calc(100% - 36px);background:#FFF;border:1px solid #DADCE0;border-radius:8px;margin: 0 auto 12px;overflow:hidden;pointer-events:all;padding:18px">
                            <div style="color:#202124;font-size:16px;padding-bottom:8px">Who are the coolest horses?</div>
                            <label class="formRadio" style="display:flex;align-items:center"><input name="ponyVote" type="radio"><div></div>Ponies</label>
                            <label class="formRadio" style="display:flex;align-items:center"><input name="ponyVote" type="radio"><div></div>Unicorns</label>
                            <label class="formRadio" style="display:flex;align-items:center"><input name="ponyVote" type="radio"><div></div>Pegasi</label>
                        </div>
                        <div style="width:100%;background:#0000;border:1px solid #DADCE0;border-radius:8px;margin: 0 auto;display:flex;overflow:hidden">
                            <div style="pointer-events:all;background:#FFF;color:#202124;font-size:16px;padding:18px;flex-grow:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">Never submit passwords</div>
                            <div style="width:88px;background:#0000;    flex-shrink: 0"></div>
                        </div>
                    </div>
                </div>
                <div style="pointer-events:none;position:absolute;top:calc(256px + 16px);text-align:center;width:100%;font-size:12px">This content is neither created nor endorsed by Google.</div>
                </div>
                <div style="display:none;pointer-events:none;position:absolute;top:calc(256px + 16px);text-align:center;width:100%;font-size:12px">Hover over the form to see behind it.</div>
                </div>
            </div>
        </div>
</div>

<style>
    #formOverlay:hover {
        filter:drop-shadow(1px 1px 6px #0009);
        opacity:0.75;
    }
    #formOverlay, #formOverlay .formColorOverlay {
        transition: filter 0.5s, opacity 0.5s;
    }
    #formOverlay:hover .formColorOverlay {
        filter:drop-shadow(1px 1px 6px #000F);
        opacity:0.9;
    }
    #formOverlay {
        /**/
    }
    .formRadio div {
        width:16px;
        height:16px;
        border-radius:16px;
        border:2px solid #61656A;
        margin: 8px;
        transition: border 0.2s;
    }
    .formRadio input:checked ~ div {
        border:2px solid #673AB7;
    }
    .formRadio div:after {
        content: "";
        width: 10px;
        height: 10px;
        margin: 3px;
        border-radius: 10px;
        background: #0000;
        display: block;
        transition: background 0.2s;
    }
    .formRadio input:checked ~ div:after {
        background: #673AB7;
    }
    .formRadio input {
        display: none;
    }
</style>

And we're done! It looks like a Google Forms page, but it has a "cutout" for the "Send" button in the Share dialog below. If clicked, it'll immediately share *Editor* permissions for the targeted file/folder with whatever e-mail we specified. To send this attack to someone we can replace the **/edit** with **/present** in the Slides url to have it open and "play" the slide direcly.

And there we go, a one-click clickjacking attack that chains a Google Slides YouTube embed path traversal to three separate redirects to gain editor access on a Drive file/folder!

I reported this vulnerability chain to Google on the 1st of July 2024, and got it triaged & confirmed on the same day! 10 days later, on the 11th of July, the VRP panel awarded me with a reward of <span style="font-weight:900;color:green">$3133.70</span> + <span style="font-weight:900;color:green">$1000</span> bonus, totalling <span style="font-weight:900;color:green">$4133.70</span>. Sweet!

## afterword

thank you for reading, you're awesome!!

<!-- https://tallinn.bsides.ee/2024/ -->
i tried to keep this writeup condensed because i'm also presenting my research with additional story elements at [bsides tallinn 2024](https://tallinn.bsides.ee/) the same day this blogpost goes out. i hope it goes well! i'm not sure when the bsides talk recordings will be released (keep an eye on [this channel](https://www.youtube.com/@bsidestallinn427/videos)), but for now you can check out [the slides](https://docs.google.com/presentation/d/10LlimFowOJ_noDrJsv4CnRgU8XoUKRAa6YjTeJFrs70/edit)!

as with my previous posts, everything on the page is just html/css crafted with love. no images, javascript, or other external resources, and just 1337kB (TBD) gzipped! it takes a lot of time and effort compared to just throwing screenshots on the page, but i think it's really fun to have a blogpost come to life like that, with interactivity and all. and it's responsive!

i hope this writeup is conherent and interesting to read, the attack chain involves quite a few elements so the article is all over the place at times, you can always feel free to ask me any questions if anything's unclear ^^

love you all &lt;3!

**Discuss this post on:** [twitter](https://twitter.com/rebane2001/), [mastodon](https://infosec.exchange/@rebane2001/), [lobsters](https://lobste.rs/s/)

[^goog]: This specific example will probably display a warning - but let's just pretend it doesn't.
[^1]: Google dorks are blabla
[^2]: The [Internet Archive](https://web.archive.org/) allows listing all archived URLs for a domain, quite handy for recon.
[^3]: The [VRP](https://bughunters.google.com/about/rules/google-friends/6625378258649088/google-and-alphabet-vulnerability-reward-program-vrp-rules) is Google's bug bounty program, and its panel is a group of people who decide how much $$$ you'll get for a bug.
[^root]: Every Google Drive file and folder has an ID associated with it, and your entire drive's Root folder is no exception! Want to find yours? Open Drive's page with DevTools open, and then search for `9PVA` in the network requests.
[^wyo]: I'm using this domain as an example because it's short and came up a lot in my Google searches, but there isn't anything special about it, you can use other gsuite domains too. In case anyone from the [Wyoming goverment](https://ets.wyo.gov/cybersecurity) happens across this post - no, this isn't touching your IT systems in any way, it's only affecting Google's systems and they're already aware of and working on the topics discussed in this blog post.

<style>
.urlBox {
    word-break: break-all;
    background: #2B2B2B;
    border-radius:4px;
    padding: 2px 5px;
    color: #C7C7C7;
    font-size: 12px;
    font-family: system-ui, sans-serif;
    width: fit-content;
}
.urlBox a {
    color: #C7C7C7;
}
.urlBox::selection, .urlBox *::selection {
    background: #FFF;
    color: #000;
}
.genericContainer {
    width: 100%;
    border-radius: 4px;
    overflow: hidden;
}
.coarseText {
    display: none;
}
.fineText {
    display: inline;
}
@media (pointer: coarse) {
    .coarseText {
        display: inline;
    }
    .fineText {
        display: none;
    }
}
@media (width >= 720px) {
    .under720 {
        display: none;
    }
}
@media (width < 720px) {
    .over720 {
        display: none;
    }
}
@media (width >= 640px) {
    .under640 {
        display: none;
    }
}
@media (width < 640px) {
    .over640 {
        display: none;
    }
}
@media (width >= 560px) {
    .under560 {
        display: none;
    }
}
@media (width < 560px) {
    .over560 {
        display: none;
    }
}
@media (width >= 480px) {
    .under480 {
        display: none;
    }
}
@media (width < 480px) {
    .over480 {
        display: none;
    }
    .sldsBody {
        height: fit-content;
        padding-bottom: 16px;
    }
    .sldsSlideTextboxBig {
        font-size: 30px;
    }
    .sldsSlideTextboxSmall {
        font-size: 16px;
    }
}
@media (width >= 360px) {
    .under360 {
        display: none;
    }
}
@media (width < 360px) {
    .over360 {
        display: none;
    }
    .sldsSlideTextboxBig {
        font-size: 24px;
    }
    .sldsSlideTextboxSmall {
        font-size: 13px;
    }
}
</style>