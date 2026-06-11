/**
 * agaporni-cursor.js — Lovebird cursor & touch effects.
 *
 * Desktop : sitting bird (idle) ↔ flying bird (moving) with direction tracking.
 * Touch   : peck on tap · flying bird on scroll.
 * Skips everything when prefers-reduced-motion is active.
 */
(function () {
  'use strict';

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  /* ── SVG: Sitting agaporni ──────────────────────────────────────────────
     36 × 40 px.  Cursor hotspot → feet at bottom-centre (18, 39).
     CSS offset:  left: -18px;  top: -39px
  ────────────────────────────────────────────────────────────────────────── */

  var SVG_SITTING =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 36 40" width="36" height="40">' +
    '<defs>' +
      '<linearGradient id="ag-sb" x1=".3" y1="0" x2=".7" y2="1">' +
        '<stop offset="0%" stop-color="#81C784"/>' +
        '<stop offset="55%" stop-color="#43A047"/>' +
        '<stop offset="100%" stop-color="#1B5E20"/>' +
      '</linearGradient>' +
      '<radialGradient id="ag-sh" cx="52%" cy="38%" r="62%">' +
        '<stop offset="0%" stop-color="#FFAB40"/>' +
        '<stop offset="45%" stop-color="#F4511E"/>' +
        '<stop offset="100%" stop-color="#B71C1C"/>' +
      '</radialGradient>' +
      '<linearGradient id="ag-sw" x1="0" y1="0" x2="1" y2="1">' +
        '<stop offset="0%" stop-color="#2E7D32"/>' +
        '<stop offset="100%" stop-color="#1B5E20"/>' +
      '</linearGradient>' +
      '<linearGradient id="ag-st" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#1565C0"/>' +
        '<stop offset="100%" stop-color="#0D47A1"/>' +
      '</linearGradient>' +
      '<linearGradient id="ag-sc" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#FFEE58"/>' +
        '<stop offset="100%" stop-color="#FB8C00"/>' +
      '</linearGradient>' +
    '</defs>' +

    /* tail feathers */
    '<path d="M7,25C4,30 1,35 3,39C6,35 10,30 12,27Z" fill="url(#ag-st)"/>' +
    '<path d="M5,28C2,33 0,38 2,40C5,36 9,31 11,29Z" fill="#1565C0" opacity=".75"/>' +
    '<path d="M9,25C7,30 6,34 8,37C10,33 12,29 13,26Z" fill="#1976D2" opacity=".55"/>' +

    /* closed wing */
    '<ellipse cx="13" cy="25" rx="9" ry="9" fill="url(#ag-sw)" transform="rotate(-15 13 25)"/>' +
    '<path d="M7,22C8,28 9,33 8,36C11,31 13,27 12,21Z" fill="#1B5E20" opacity=".65"/>' +
    '<path d="M10,21C12,27 13,32 12,36C14,30 15,26 14,20Z" fill="#388E3C" opacity=".45"/>' +

    /* body */
    '<ellipse cx="16" cy="25" rx="11" ry="12" fill="url(#ag-sb)"/>' +
    '<ellipse cx="14" cy="21" rx="5" ry="5" fill="#C8E6C9" opacity=".2" transform="rotate(-20 14 21)"/>' +

    /* yellow collar */
    '<ellipse cx="21" cy="17" rx="5.5" ry="2.8" fill="url(#ag-sc)"/>' +

    /* head */
    '<circle cx="24" cy="11" r="9" fill="url(#ag-sh)"/>' +
    '<path d="M17,8C15,13 17,17 22,17C19,13 17,10 17,8Z" fill="#00897B" opacity=".28"/>' +
    '<ellipse cx="22" cy="8" rx="4" ry="3" fill="#FFCC80" opacity=".18"/>' +

    /* eye */
    '<circle cx="28" cy="10" r="2.6" fill="#3E2723" opacity=".85"/>' +
    '<circle cx="28" cy="10" r="2" fill="#FFCC80" opacity=".6"/>' +
    '<circle cx="28" cy="10" r="1.3" fill="#1A1A1A"/>' +
    '<circle cx="28.8" cy="9.4" r=".45" fill="white"/>' +

    /* beak — hooked parrot */
    '<path d="M30,8C33,7.5 35,9.5 34,12C32.5,11.5 30,11 30,8Z" fill="#BF360C"/>' +
    '<path d="M30,8C32,7.5 33,9 32.5,10C31.5,9.5 30.5,9 30,8Z" fill="#E64A19" opacity=".55"/>' +
    '<path d="M30,11C32,12.5 33,14.5 31,15.5C29.5,14 29.5,12.5 30,11Z" fill="#8D1A0F"/>' +

    /* legs */
    '<line x1="13" y1="34" x2="13" y2="38" stroke="#5D4037" stroke-width="1.3" stroke-linecap="round"/>' +
    '<line x1="17" y1="35" x2="17" y2="38" stroke="#5D4037" stroke-width="1.3" stroke-linecap="round"/>' +

    /* toes */
    '<path d="M13,38C11,39.5 9.5,40 9,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '<path d="M13,38C12.5,39.5 12.5,40 12.5,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '<path d="M13,38C14,39.5 14.5,40 15,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '<path d="M17,38C15.5,39.5 15,40 14.5,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '<path d="M17,38C17,39.5 17,40 17,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '<path d="M17,38C18.5,39.5 19,40 19.5,40" stroke="#5D4037" stroke-width="1.1" stroke-linecap="round" fill="none"/>' +
    '</svg>';


  /* ── SVG: Flying agaporni ───────────────────────────────────────────────
     44 × 36 px.  Centered on cursor wrapper at (-22, -18).
     Wing groups (.ag-wg-up / .ag-wg-lo) animated by CSS when flying.
  ────────────────────────────────────────────────────────────────────────── */

  var SVG_FLYING =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 44 36" width="44" height="36">' +
    '<defs>' +
      '<linearGradient id="ag-fb" x1=".3" y1="0" x2=".7" y2="1">' +
        '<stop offset="0%" stop-color="#81C784"/>' +
        '<stop offset="55%" stop-color="#43A047"/>' +
        '<stop offset="100%" stop-color="#1B5E20"/>' +
      '</linearGradient>' +
      '<radialGradient id="ag-fh" cx="52%" cy="38%" r="62%">' +
        '<stop offset="0%" stop-color="#FFAB40"/>' +
        '<stop offset="45%" stop-color="#F4511E"/>' +
        '<stop offset="100%" stop-color="#B71C1C"/>' +
      '</radialGradient>' +
      '<linearGradient id="ag-fwu" x1=".5" y1="1" x2="0" y2="0">' +
        '<stop offset="0%" stop-color="#4CAF50"/>' +
        '<stop offset="100%" stop-color="#1B5E20"/>' +
      '</linearGradient>' +
      '<linearGradient id="ag-fwl" x1=".5" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#4CAF50"/>' +
        '<stop offset="100%" stop-color="#1B5E20"/>' +
      '</linearGradient>' +
      '<linearGradient id="ag-ft" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#1565C0"/>' +
        '<stop offset="100%" stop-color="#0D47A1"/>' +
      '</linearGradient>' +
      '<linearGradient id="ag-fc" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#FFEE58"/>' +
        '<stop offset="100%" stop-color="#FB8C00"/>' +
      '</linearGradient>' +
    '</defs>' +

    /* lower wing group — behind body */
    '<g class="ag-wg-lo">' +
      '<path d="M22,18C18,22 12,28 5,26C10,22 16,20 22,18Z" fill="url(#ag-fwl)"/>' +
      '<path d="M22,19C17,24 10,31 3,29C8,25 15,22 22,19Z" fill="#1B5E20" opacity=".65"/>' +
      '<path d="M21,20C17,26 10,33 2,31C7,27 14,24 21,20Z" fill="#2E7D32" opacity=".35"/>' +
    '</g>' +

    /* blue tail */
    '<path d="M6,16C1,14 0,18 2,20C4,19 5,17 6,16Z" fill="url(#ag-ft)"/>' +
    '<path d="M6,19C1,19 0,23 2,25C4,22 5,21 6,19Z" fill="#1565C0" opacity=".65"/>' +

    /* body */
    '<ellipse cx="22" cy="18" rx="15" ry="7" fill="url(#ag-fb)"/>' +
    '<ellipse cx="19" cy="16" rx="8" ry="4" fill="#C8E6C9" opacity=".18" transform="rotate(-5 19 16)"/>' +

    /* upper wing group — in front of body */
    '<g class="ag-wg-up">' +
      '<path d="M22,18C18,12 12,6 5,8C10,12 16,15 22,18Z" fill="url(#ag-fwu)"/>' +
      '<path d="M22,17C17,10 10,3 3,5C8,9 15,13 22,17Z" fill="#43A047" opacity=".65"/>' +
      '<path d="M21,17C17,9 10,2 2,3C7,7 14,12 21,17Z" fill="#66BB6A" opacity=".3"/>' +
    '</g>' +

    /* yellow collar */
    '<ellipse cx="31" cy="16" rx="5.5" ry="3" fill="url(#ag-fc)" transform="rotate(-8 31 16)"/>' +

    /* head */
    '<circle cx="36" cy="13" r="7" fill="url(#ag-fh)"/>' +
    '<path d="M30,10C29,13 31,17 35,17C33,13 31,11 30,10Z" fill="#00897B" opacity=".25"/>' +
    '<ellipse cx="34" cy="10" rx="3.5" ry="2.5" fill="#FFCC80" opacity=".18"/>' +

    /* eye */
    '<circle cx="39" cy="12" r="2.6" fill="#3E2723" opacity=".85"/>' +
    '<circle cx="39" cy="12" r="2" fill="#FFCC80" opacity=".6"/>' +
    '<circle cx="39" cy="12" r="1.3" fill="#1A1A1A"/>' +
    '<circle cx="39.8" cy="11.4" r=".45" fill="white"/>' +

    /* beak */
    '<path d="M41,10.5C44,10 44.5,12 44,14C42.5,13.5 41,13 41,10.5Z" fill="#BF360C"/>' +
    '<path d="M41,10.5C43,10 43.5,11.5 43,12C42,11.5 41.5,11 41,10.5Z" fill="#E64A19" opacity=".55"/>' +
    '<path d="M41,13C43,14 43.5,16 42,17C40.5,15.5 40.5,14 41,13Z" fill="#8D1A0F"/>' +
    '</svg>';


  /* ── SVG: Flying (small) — scroll effect ───────────────────────────────
     Same paths as above, rendered at 28 × 22 px.
  ────────────────────────────────────────────────────────────────────────── */

  var SVG_FLYING_SMALL =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 44 36" width="28" height="22">' +
    '<defs>' +
      '<linearGradient id="ag-ssb" x1=".3" y1="0" x2=".7" y2="1"><stop offset="0%" stop-color="#81C784"/><stop offset="55%" stop-color="#43A047"/><stop offset="100%" stop-color="#1B5E20"/></linearGradient>' +
      '<radialGradient id="ag-ssh" cx="52%" cy="38%" r="62%"><stop offset="0%" stop-color="#FFAB40"/><stop offset="45%" stop-color="#F4511E"/><stop offset="100%" stop-color="#B71C1C"/></radialGradient>' +
      '<linearGradient id="ag-sswu" x1=".5" y1="1" x2="0" y2="0"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#1B5E20"/></linearGradient>' +
      '<linearGradient id="ag-sswl" x1=".5" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#1B5E20"/></linearGradient>' +
      '<linearGradient id="ag-sst" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1565C0"/><stop offset="100%" stop-color="#0D47A1"/></linearGradient>' +
      '<linearGradient id="ag-ssc" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#FFEE58"/><stop offset="100%" stop-color="#FB8C00"/></linearGradient>' +
    '</defs>' +
    '<g class="ag-wg-lo"><path d="M22,18C18,22 12,28 5,26C10,22 16,20 22,18Z" fill="url(#ag-sswl)"/><path d="M22,19C17,24 10,31 3,29C8,25 15,22 22,19Z" fill="#1B5E20" opacity=".65"/></g>' +
    '<path d="M6,16C1,14 0,18 2,20C4,19 5,17 6,16Z" fill="url(#ag-sst)"/>' +
    '<ellipse cx="22" cy="18" rx="15" ry="7" fill="url(#ag-ssb)"/>' +
    '<g class="ag-wg-up"><path d="M22,18C18,12 12,6 5,8C10,12 16,15 22,18Z" fill="url(#ag-sswu)"/><path d="M22,17C17,10 10,3 3,5C8,9 15,13 22,17Z" fill="#43A047" opacity=".65"/></g>' +
    '<ellipse cx="31" cy="16" rx="5.5" ry="3" fill="url(#ag-ssc)" transform="rotate(-8 31 16)"/>' +
    '<circle cx="36" cy="13" r="7" fill="url(#ag-ssh)"/>' +
    '<circle cx="39" cy="12" r="2.6" fill="#3E2723" opacity=".85"/><circle cx="39" cy="12" r="2" fill="#FFCC80" opacity=".6"/><circle cx="39" cy="12" r="1.3" fill="#1A1A1A"/><circle cx="39.8" cy="11.4" r=".45" fill="white"/>' +
    '<path d="M41,10.5C44,10 44.5,12 44,14C42.5,13.5 41,13 41,10.5Z" fill="#BF360C"/>' +
    '<path d="M41,13C43,14 43.5,16 42,17C40.5,15.5 40.5,14 41,13Z" fill="#8D1A0F"/>' +
    '</svg>';


  /* ── SVG: Peck head — touch tap ──────────────────────────────────────── */

  var SVG_PECK =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 26 26" width="26" height="26">' +
    '<defs>' +
      '<radialGradient id="ag-ph" cx="50%" cy="40%" r="60%">' +
        '<stop offset="0%" stop-color="#FFAB40"/>' +
        '<stop offset="45%" stop-color="#F4511E"/>' +
        '<stop offset="100%" stop-color="#B71C1C"/>' +
      '</radialGradient>' +
    '</defs>' +
    '<circle cx="13" cy="12" r="10" fill="url(#ag-ph)"/>' +
    '<ellipse cx="13" cy="8" rx="6.5" ry="5.5" fill="#FFCC80" opacity=".18"/>' +
    '<circle cx="17" cy="11" r="2.6" fill="#3E2723" opacity=".85"/>' +
    '<circle cx="17" cy="11" r="2" fill="#FFCC80" opacity=".6"/>' +
    '<circle cx="17" cy="11" r="1.3" fill="#1A1A1A"/>' +
    '<circle cx="17.8" cy="10.4" r=".45" fill="white"/>' +
    /* beak pointing down */
    '<path d="M10,21C13,27 16,21 13,19C12,20 11,20.5 10,21Z" fill="#BF360C"/>' +
    '<path d="M11,21C13,25.5 15,21 13,19.5C12.5,20.5 11.5,21 11,21Z" fill="#E64A19" opacity=".55"/>' +
    '</svg>';


  /* ── CSS ─────────────────────────────────────────────────────────────── */

  var STYLES = [
    /* Hide native cursor */
    'body.ag-active,body.ag-active *{cursor:none!important}',

    /* Cursor wrapper: zero-size point positioned at (mouseX, mouseY) */
    '.ag-cursor{position:fixed;top:0;left:0;pointer-events:none;z-index:2147483647;',
    'user-select:none;will-change:transform}',

    /* Bob wrapper — sits between cursor and both bird states */
    '.ag-cursor__bob{position:absolute;top:0;left:0}',

    /* Sitting bird: hotspot at feet */
    '.ag-cursor__sitting{position:absolute;left:-18px;top:-39px;',
    'transition:opacity .22s ease;opacity:1}',

    /* Flying rotation wrapper: centered on cursor */
    '.ag-cursor__flying-rot{position:absolute;left:-22px;top:-18px;',
    'transition:opacity .22s ease;opacity:0}',

    /* Visibility swap */
    '.ag-cursor--flying .ag-cursor__sitting{opacity:0}',
    '.ag-cursor--flying .ag-cursor__flying-rot{opacity:1}',

    /* Hidden (cursor left window) */
    '.ag-cursor--hidden{opacity:0!important}',

    /* Idle bob — sitting only */
    '@keyframes ag-bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-2px)}}',
    '.ag-cursor:not(.ag-cursor--flying):not(.ag-cursor--hidden) .ag-cursor__sitting{',
    'animation:ag-bob 2.2s ease-in-out infinite}',

    /* Body oscillation synced with wingbeat — applied to the bob wrapper */
    '@keyframes ag-fly-bob{',
    '0%  {transform:translateY(0)}',
    '36% {transform:translateY(-1.8px)}',  /* peaks at downstroke apex */
    '100%{transform:translateY(0)}}',
    '.ag-cursor--flying .ag-cursor__bob{animation:ag-fly-bob .3s linear infinite}',

    /* Wing-beat — pivot near wing-root (right edge of fill-box) */
    '.ag-wg-up,.ag-wg-lo{transform-box:fill-box}',
    '.ag-wg-up{transform-origin:72% 90%}',
    '.ag-wg-lo{transform-origin:72% 10%}',

    /* Asymmetric wingbeat: fast power-stroke down, slower recovery up.
       Per-keyframe timing overrides the animation's own timing-function,
       so the animation itself is declared linear.                        */
    '@keyframes ag-wu{',
    '0%  {transform:rotate(-19deg);animation-timing-function:cubic-bezier(.1,0,.25,1)}',
    '36% {transform:rotate(14deg); animation-timing-function:cubic-bezier(.75,0,1,1)}',
    '100%{transform:rotate(-19deg)}}',

    '@keyframes ag-wl{',
    '0%  {transform:rotate(17deg); animation-timing-function:cubic-bezier(.1,0,.25,1)}',
    '36% {transform:rotate(-12deg);animation-timing-function:cubic-bezier(.75,0,1,1)}',
    '100%{transform:rotate(17deg)}}',

    '.ag-cursor--flying .ag-wg-up{animation:ag-wu .3s linear infinite}',
    '.ag-cursor--flying .ag-wg-lo{animation:ag-wl .3s linear infinite;animation-delay:-.05s}',

    /* Scroll bird wings */
    '.ag-scroll-bird .ag-wg-up{animation:ag-wu .3s linear infinite}',
    '.ag-scroll-bird .ag-wg-lo{animation:ag-wl .3s linear infinite;animation-delay:-.05s}',

    /* Peck */
    '.ag-peck{position:fixed;pointer-events:none;z-index:2147483647;user-select:none;',
    'animation:ag-peck .65s ease forwards}',
    '@keyframes ag-peck{',
    '0%  {transform:translate(-50%,-130%) scale(.25);opacity:0}',
    '15% {transform:translate(-50%,-108%) scale(1.1);opacity:1}',
    '42% {transform:translate(-50%,-58%)  scale(1);  opacity:1}',
    '68% {transform:translate(-50%,-98%)  scale(.95);opacity:.9}',
    '100%{transform:translate(-50%,-165%) scale(.45);opacity:0}}',

    /* Scroll bird */
    '.ag-scroll-bird{position:fixed;right:20px;pointer-events:none;',
    'z-index:2147483647;user-select:none}',
    '.ag-scroll-bird--up{bottom:30%;animation:ag-scr-up 1.3s cubic-bezier(.25,.46,.45,.94) forwards}',
    '.ag-scroll-bird--down{top:30%;animation:ag-scr-dn 1.3s cubic-bezier(.25,.46,.45,.94) forwards}',
    '@keyframes ag-scr-up{',
    '0%  {opacity:0;transform:translateY(0) scale(.55)}',
    '15% {opacity:1;transform:translateY(-14px) scale(1)}',
    '80% {opacity:.8;transform:translateY(-85px) scale(1)}',
    '100%{opacity:0;transform:translateY(-110px) scale(.65)}}',
    '@keyframes ag-scr-dn{',
    '0%  {opacity:0;transform:translateY(0) scale(.55)}',
    '15% {opacity:1;transform:translateY(14px) scale(1)}',
    '80% {opacity:.8;transform:translateY(85px) scale(1)}',
    '100%{opacity:0;transform:translateY(110px) scale(.65)}}'
  ].join('');


  /* ── Utilities ───────────────────────────────────────────────────────── */

  var _stylesInjected = false;
  function injectStyles() {
    if (_stylesInjected) return;
    _stylesInjected = true;
    var el = document.createElement('style');
    el.id = 'agaporni-cursor-styles';
    el.textContent = STYLES;
    document.head.appendChild(el);
  }

  /** Lerp angles via shortest arc. */
  function lerpAngle(a, b, t) {
    var diff = b - a;
    while (diff > 180)  diff -= 360;
    while (diff < -180) diff += 360;
    return a + diff * t;
  }

  /**
   * Build the CSS transform for the flying rotation wrapper.
   *
   * The bird SVG faces RIGHT.  We rotate it to face `angle` (degrees, atan2).
   * Hysteresis avoids rapid flip-flop near ±90°:
   *   – flips  when |angle| crosses 95°
   *   – unflips when |angle| drops below 80°
   *
   * When flipped (scaleX(-1)):
   *   angle > 0 → drawAngle = angle − 180
   *   angle < 0 → drawAngle = −(180 + angle)
   */
  var _flipped = false;

  function buildFlyTransform(angle) {
    if (!_flipped && Math.abs(angle) > 95) _flipped = true;
    if (_flipped  && Math.abs(angle) < 80) _flipped = false;

    if (!_flipped) {
      return 'rotate(' + angle.toFixed(2) + 'deg)';
    }
    var draw = angle > 0 ? angle - 180 : -(180 + angle);
    return 'scaleX(-1) rotate(' + draw.toFixed(2) + 'deg)';
  }


  /* ── Desktop cursor ──────────────────────────────────────────────────── */

  function initDesktopCursor() {
    injectStyles();

    /* Build DOM:
         .ag-cursor          ← positioned at (mouseX, mouseY) by JS
           .ag-cursor__bob   ← body-bob CSS animation when flying
             .ag-cursor__sitting    (sitting SVG)
             .ag-cursor__flying-rot (direction rotation by JS)
               [flying SVG]                                        */
    var cursor = document.createElement('div');
    cursor.className = 'ag-cursor';
    cursor.setAttribute('aria-hidden', 'true');

    var bobEl = document.createElement('div');
    bobEl.className = 'ag-cursor__bob';

    var sittingEl = document.createElement('div');
    sittingEl.className = 'ag-cursor__sitting';
    sittingEl.innerHTML = SVG_SITTING;

    var rotEl = document.createElement('div');
    rotEl.className = 'ag-cursor__flying-rot';
    rotEl.innerHTML = SVG_FLYING;

    bobEl.appendChild(sittingEl);
    bobEl.appendChild(rotEl);
    cursor.appendChild(bobEl);
    document.body.appendChild(cursor);
    document.body.classList.add('ag-active');

    cursor.style.transform = 'translate(-300px,-300px)';

    /* ── Direction tracking ─────────────────────────────────────────── */
    var smoothAngle = 0;
    var targetAngle = 0;
    var prevX = null;
    var prevY = null;
    var idleTimer = null;
    var isFlying = false;
    var rafId = null;

    function tick() {
      /* Lerp factor 0.14 → responsive but not twitchy */
      smoothAngle = lerpAngle(smoothAngle, targetAngle, 0.14);
      rotEl.style.transform = buildFlyTransform(smoothAngle);
      rafId = requestAnimationFrame(tick);
    }

    function startFlying() {
      if (!isFlying) {
        isFlying = true;
        cursor.classList.add('ag-cursor--flying');
        if (!rafId) rafId = requestAnimationFrame(tick);
      }
    }

    function stopFlying() {
      isFlying = false;
      cursor.classList.remove('ag-cursor--flying');
      /* Keep rAF alive so direction stays current for next movement */
    }

    document.addEventListener('mousemove', function (e) {
      cursor.style.transform = 'translate(' + e.clientX + 'px,' + e.clientY + 'px)';
      cursor.classList.remove('ag-cursor--hidden');

      /* Update direction only when movement is intentional (> 3 px) */
      if (prevX !== null) {
        var dx = e.clientX - prevX;
        var dy = e.clientY - prevY;
        if (dx * dx + dy * dy > 9) {
          targetAngle = Math.atan2(dy, dx) * (180 / Math.PI);
        }
      }
      prevX = e.clientX;
      prevY = e.clientY;

      startFlying();
      clearTimeout(idleTimer);
      idleTimer = setTimeout(stopFlying, 520);
    });

    document.addEventListener('mouseleave', function () {
      cursor.classList.add('ag-cursor--hidden');
    });
    document.addEventListener('mouseenter', function () {
      cursor.classList.remove('ag-cursor--hidden');
    });

    rafId = requestAnimationFrame(tick);
  }


  /* ── Touch effects ───────────────────────────────────────────────────── */

  function spawnPeck(x, y) {
    var el = document.createElement('div');
    el.className = 'ag-peck';
    el.setAttribute('aria-hidden', 'true');
    el.innerHTML = SVG_PECK;
    el.style.left = x + 'px';
    el.style.top  = y + 'px';
    document.body.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 700);
  }

  function spawnScrollBird(dir) {
    var el = document.createElement('div');
    el.className = 'ag-scroll-bird ag-scroll-bird--' + dir;
    el.setAttribute('aria-hidden', 'true');
    el.innerHTML = SVG_FLYING_SMALL;
    document.body.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 1400);
  }

  function initTouchEffects() {
    injectStyles();

    document.addEventListener('touchstart', function (e) {
      var t = e.changedTouches[0];
      spawnPeck(t.clientX, t.clientY);
    }, { passive: true });

    var lastScrollY = window.scrollY;
    var scrollLock  = false;

    window.addEventListener('scroll', function () {
      var dir = window.scrollY >= lastScrollY ? 'down' : 'up';
      lastScrollY = window.scrollY;
      if (!scrollLock) {
        scrollLock = true;
        spawnScrollBird(dir);
        setTimeout(function () { scrollLock = false; }, 1100);
      }
    }, { passive: true });
  }


  /* ── Init ────────────────────────────────────────────────────────────── */

  function init() {
    if (window.matchMedia('(any-pointer: fine)').matches) {
      initDesktopCursor();
    }

    var hasTouch =
      ('ontouchstart' in window) ||
      (navigator.maxTouchPoints > 0) ||
      window.matchMedia('(any-pointer: coarse)').matches;

    if (hasTouch) {
      initTouchEffects();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
