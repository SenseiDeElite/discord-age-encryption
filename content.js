// content.js — Discord Age Encryption
//
// Wire format : [age]:<session_id>:<base64disc_payload>:<base64url_ed25519_sig>
// Crypto      : age-encryption (X25519 + ChaCha20-Poly1305) + Ed25519 signatures, lib/age.js
// Compression : deflate-raw applied to plaintext before encryption

(() => {
  'use strict';

  const PREFIX = '[age]';

  // Keyed on stable li.id so React DOM reconciliation (which replaces element
  // nodes) can re-render instantly from cache without a second decrypt call.
  const _processedIds   = new Set();
  const _decryptedCache = new Map();

  let _identity    = null;  // full two-line blob (age key + ed25519 priv)
  let _signingKey  = null;  // CryptoKey (Ed25519 private), imported on unlock
  let _contacts    = {};
  let _globalOn    = true;
  let _msgObserver = null;
  let _banner      = null;
  let _bannerTimer = null;

  const sleep    = ms => new Promise(r => setTimeout(r, ms));
  const localGet = keys => new Promise(r => chrome.storage.local.get(keys, r));

  // ─── DOM helpers ─────────────────────────────────────────────────────────────

  function getTextbox()     { return document.querySelector('[data-slate-editor="true"]'); }
  function getMessageList() { return document.querySelector('ol[data-list-id="chat-messages"]'); }

  function getCurrentChannelId() {
    const m = location.pathname.match(/\/channels\/[^/]+\/(\d+)/);
    return m ? m[1] : null;
  }

  function getContact() {
    const id = getCurrentChannelId();
    return id ? (_contacts[id] ?? null) : null;
  }

  // ─── Enter key interception ───────────────────────────────────────────────────

  function isEncryptionActive() {
    return !!(_identity && getContact()?.enabled && _globalOn);
  }

  function attachEnterHook() {
    const tb = getTextbox();
    if (!tb || tb._ageKeyHandler) return;
    tb._ageKeyHandler = (e) => {
      if (e.key !== 'Enter' || e.shiftKey || e.altKey) return;
      if (document.querySelector('[role="listbox"]')) return;
      const raw = tb.innerText?.trim() ?? '';
      if (!raw) return;
      if (raw.startsWith(PREFIX)) return;
      if (!isEncryptionActive()) return;
      e.preventDefault();
      e.stopPropagation();
      handleEncryptClick();
    };
    tb.addEventListener('keydown', tb._ageKeyHandler, { capture: true });
  }

  function detachEnterHook() {
    const tb = getTextbox();
    if (tb?._ageKeyHandler) {
      tb.removeEventListener('keydown', tb._ageKeyHandler, { capture: true });
      delete tb._ageKeyHandler;
    }
  }

  // ─── Crypto ──────────────────────────────────────────────────────────────────

  async function importSigningKey(identityBlob) {
    const line = identityBlob.split('\n')[1] ?? '';
    if (!line.startsWith('ed25519priv:')) throw new Error('No Ed25519 private key in identity blob');
    const pkcs8 = base64UrlToBytes(line.slice('ed25519priv:'.length));
    return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  }

  async function importVerifyKey(contactKeyString) {
    const m = contactKeyString.match(/;ed25519:([A-Za-z0-9_-]+)$/);
    if (!m) return null;
    const raw = base64UrlToBytes(m[1]);
    return crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  }

  async function encryptMessage(plaintext, contact) {
    const enc = new age.Encrypter();
    enc.addRecipient(contact.ageRecipient.split(';')[0]);
    const self = await localGet(['ageRecipient']);
    if (self.ageRecipient) enc.addRecipient(self.ageRecipient.split(';')[0]);
    return bytesToBase64Disc(await enc.encrypt(await compress(plaintext)));
  }

  async function decryptMessage(encoded) {
    const dec = new age.Decrypter();
    dec.addIdentity(_identity.split('\n')[0]);
    return decompress(await dec.decrypt(base64DiscToBytes(encoded), 'uint8array'));
  }

  // ─── Compression ─────────────────────────────────────────────────────────────

  async function streamTransform(stream, bytes) {
    const writer = stream.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const chunks = [];
    const reader = stream.readable.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
  }

  const compress   = str   => streamTransform(new CompressionStream('deflate-raw'),   new TextEncoder().encode(str));
  const decompress = bytes => streamTransform(new DecompressionStream('deflate-raw'), bytes).then(b => new TextDecoder().decode(b));

  // ─── Base64 (Discord-safe) ───────────────────────────────────────────────────
  // Replace + → - and / → . (not _) because Discord renders __ as underline
  // markup and strips the underscores from the DOM, corrupting the payload.
  // Dot never appears in standard base64 and triggers no Discord markdown.

  function bytesToBase64Url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64UrlToBytes(str) {
    let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToBase64Disc(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '.').replace(/=/g, '');
  }

  function base64DiscToBytes(str) {
    let b64 = str.replace(/-/g, '+').replace(/\./g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ─── Send ────────────────────────────────────────────────────────────────────
  // Plaintext is inserted via synthetic ClipboardEvent — Slate serialises from its
  // internal model, not the DOM, so execCommand('insertText') would send the wrong text.

  async function pasteIntoEditor(text) {
    const tb = getTextbox();
    if (!tb) return;
    tb.focus();
    await sleep(20);
    document.execCommand('selectAll', false);
    await sleep(20);
    const dt = new DataTransfer();
    dt.setData('text/plain', text);
    tb.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    await sleep(120);
  }

  let _sending = false;
  const _outgoingCache = new Map();

  async function handleEncryptClick() {
    if (_sending) return;
    if (!isEncryptionActive()) return;
    const contact = getContact();
    const plain   = getTextbox()?.innerText?.trim();
    if (!plain || !contact) return;
    _sending = true;
    try {
      const sid    = Math.random().toString(36).slice(2, 6).toUpperCase();
      const cipher = await encryptMessage(plain, contact);

      const sigInput = new TextEncoder().encode(`${sid}:${cipher}`);
      const sigBytes = await crypto.subtle.sign('Ed25519', _signingKey, sigInput);
      // Clamp to 64 bytes — some Chromium builds return 65 bytes from Ed25519 sign.
      const sig      = bytesToBase64Url(new Uint8Array(sigBytes).slice(0, 64));

      _outgoingCache.set(sid, plain);
      await pasteIntoEditor(`${PREFIX}:${sid}:${cipher}:${sig}`);
      setTimeout(() => _outgoingCache.delete(sid), 8000);
    } catch (err) {
      console.error('[age] encrypt error:', err);
      showBanner('Encryption failed — ' + err.message, 'error');
    } finally {
      _sending = false;
    }
  }

  // ─── Receive ─────────────────────────────────────────────────────────────────

  function waitForMessageList(onReady) {
    const list = getMessageList();
    if (list) { attachMsgObserver(list); scanExisting(); onReady?.(); return; }
    const iv = setInterval(() => {
      const list = getMessageList();
      if (list) { clearInterval(iv); attachMsgObserver(list); scanExisting(); onReady?.(); }
    }, 400);
  }

  function attachMsgObserver(list) {
    _msgObserver?.disconnect();
    _msgObserver = new MutationObserver(mutations => {
      let dirty = false;
      for (const { addedNodes } of mutations) {
        for (const node of addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (node.matches?.('li[id^="chat-messages-"]')) {
            processMessageNode(node); dirty = true;
          } else {
            node.querySelectorAll?.('li[id^="chat-messages-"]').forEach(li => { processMessageNode(li); dirty = true; });
            if (node.matches?.('[id^="message-content-"]')) {
              const li = node.closest('li');
              if (li) { processMessageNode(li); dirty = true; }
            }
            node.querySelectorAll?.('[id^="message-content-"]').forEach(el => {
              const li = el.closest('li');
              if (li) { processMessageNode(li); dirty = true; }
            });
          }
        }
      }
      if (dirty) sanitizeReplyPreviews();
    });
    _msgObserver.observe(list, { childList: true, subtree: true });
  }

  function scanExisting() {
    document.querySelectorAll('li[id^="chat-messages-"]').forEach(processMessageNode);
    sanitizeReplyPreviews();
  }

  function sanitizeReplyPreviews() {
    document.querySelectorAll('[class*="repliedText"] [id^="message-content-"]').forEach(el => {
      if (el.dataset.agePreviewMasked || !el.textContent.includes(PREFIX)) return;
      el.textContent = '🔒 Encrypted message';
      el.style.opacity = '0.6';
      el.dataset.agePreviewMasked = '1';
    });
  }

  function rescanPending() {
    document.querySelectorAll('[id^="message-content-"][data-age-raw]').forEach(el => {
      if (el.closest('[class*="repliedText"]') || el.closest('[class*="replyPreview"]')) return;
      if (el.dataset.ageState === 'ok') return;
      const li = el.closest('li[id^="chat-messages-"]');
      if (li) processMessageNode(li);
    });
  }

  function processMessageNode(li) {
    const el = [...li.querySelectorAll('[id^="message-content-"]')].find(e =>
      !e.closest('[class*="repliedText"]') &&
      !e.closest('[class*="replyPreview"]')
    );
    if (!el) return;

    const msgId = li.id;

    if (_processedIds.has(msgId)) {
      const cached = _decryptedCache.get(msgId);
      if (cached && el.dataset.ageState !== 'ok') renderDecrypted(el, cached);
      return;
    }

    const text = el.dataset.ageRaw ?? directTextContent(el).trim();
    if (!text.startsWith(PREFIX)) return;

    const m = text.match(/^\[age\]:([A-Z0-9]+):([A-Za-z0-9\-.]+):([A-Za-z0-9_-]+)$/);
    if (!m) return;

    el.dataset.ageRaw = text;

    if (!_identity || !_globalOn) {
      markMessage(el, !_identity ? '🔒 Unlock extension to decrypt.' : '🔒 Decryption disabled.', 'pending');
      return;
    }

    const outgoingPlain = _outgoingCache.get(m[1]);
    if (outgoingPlain !== undefined) {
      _processedIds.add(msgId);
      _decryptedCache.set(msgId, outgoingPlain);
      renderDecrypted(el, outgoingPlain);
      return;
    }

    markMessage(el, '🔒 Decrypting…', 'pending');

    (async () => {
      const contact     = getContact();
      const sigInput    = new TextEncoder().encode(`${m[1]}:${m[2]}`);
      // Clamp to 64 bytes — some Chromium builds produce a 65-byte sign output.
      const sigBytes    = base64UrlToBytes(m[3]).slice(0, 64);

      const contactKey  = contact ? await importVerifyKey(contact.ageRecipient).catch(() => null) : null;
      const contactValid = contactKey
        ? await crypto.subtle.verify('Ed25519', contactKey, sigBytes, sigInput)
        : false;

      if (!contactValid) {
        const self        = await localGet(['ageRecipient']);
        const selfKey     = self.ageRecipient
          ? await importVerifyKey(self.ageRecipient).catch(() => null)
          : null;
        const selfValid   = selfKey
          ? await crypto.subtle.verify('Ed25519', selfKey, sigBytes, sigInput)
          : false;

        if (!selfValid) {
          console.error('[age] signature invalid', { msgId });
          markMessage(el, '🔴 Signature invalid — possible tampering.', 'error');
          return;
        }
      }
      try {
        const plain = await decryptMessage(m[2]);
        _processedIds.add(msgId);
        _decryptedCache.set(msgId, plain);
        renderDecrypted(el, plain);
      } catch (err) {
        console.error('[age] decrypt failed', { msgId, err });
        markMessage(el, '🔓 Could not decrypt.', 'error');
      }
    })();
  }

  function directTextContent(el) {
    let text = '';
    for (const node of el.childNodes) {
      if (node.nodeType === Node.TEXT_NODE) {
        text += node.textContent;
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        const cls  = node.className ?? '';
        const skip = node.getAttribute('data-type') === 'reply'
          || /reply|embed|accessory/i.test(cls)
          || node.tagName === 'BLOCKQUOTE'
          || node.tagName === 'ARTICLE';
        if (!skip) text += node.textContent;
      }
    }
    return text.trim();
  }

  setInterval(() => {
    if (_identity) attachEnterHook();
    sanitizeReplyPreviews();
  }, 1500);

  // ─── Render ──────────────────────────────────────────────────────────────────

  function renderDecrypted(el, plaintext) {
    el.dataset.ageState = 'ok';
    el.textContent = '';
    const badge = Object.assign(document.createElement('span'), { textContent: '🔒 ' });
    badge.style.userSelect = 'none';
    el.appendChild(badge);
    plaintext.split('\n').forEach((line, i, arr) => {
      el.appendChild(renderMarkdownLine(line));
      if (i < arr.length - 1) el.appendChild(document.createElement('br'));
    });
  }

  function renderMarkdownLine(text) {
    const wrap = document.createElement('span');
    wrap.style.color = '#889ce6';
    if (/^> /.test(text)) {
      wrap.style.cssText = 'color:#889ce6;border-left:3px solid #5c6aaa;padding-left:8px;display:inline-block;margin:2px 0';
      applyInlineMarkdown(wrap, text.slice(2));
    } else {
      applyInlineMarkdown(wrap, text);
    }
    return wrap;
  }

  function applyInlineMarkdown(container, text) {
    const tokens = [
      { re: /\*\*(.+?)\*\*/s,  tag: 'strong'  },
      { re: /\*(.+?)\*/s,      tag: 'em'      },
      { re: /__(.+?)__/s,      tag: 'u'       },
      { re: /~~(.+?)~~/s,      tag: 's'       },
      { re: /`([^`]+)`/,       tag: 'code'    },
      { re: /\|\|(.+?)\|\|/s,  tag: 'spoiler' },
    ];

    let remaining = text;
    while (remaining.length > 0) {
      let earliest = null;
      for (const { re, tag } of tokens) {
        const m = re.exec(remaining);
        if (m && (!earliest || m.index < earliest.index))
          earliest = { index: m.index, match: m[0], inner: m[1], tag };
      }

      if (!earliest) { renderWithEmoji(container, remaining); break; }
      if (earliest.index > 0) renderWithEmoji(container, remaining.slice(0, earliest.index));

      if (earliest.tag === 'code') {
        const code = document.createElement('code');
        Object.assign(code.style, {
          background: '#2b2d31', color: '#e3e5e8',
          borderRadius: '3px', padding: '0 4px',
          fontFamily: 'monospace', fontSize: '0.875em',
        });
        code.textContent = earliest.inner;
        container.appendChild(code);
      } else if (earliest.tag === 'spoiler') {
        const sp = document.createElement('span');
        Object.assign(sp.style, {
          background: '#889ce6', color: '#889ce6',
          borderRadius: '3px', padding: '0 2px',
          cursor: 'pointer', userSelect: 'none',
        });
        sp.title = 'Click to reveal';
        applyInlineMarkdown(sp, earliest.inner);
        sp.addEventListener('click', () => { sp.style.color = '#889ce6'; sp.style.background = 'transparent'; });
        container.appendChild(sp);
      } else {
        const el = document.createElement(earliest.tag);
        if (earliest.tag === 'strong') el.style.color = '#889ce6';
        applyInlineMarkdown(el, earliest.inner);
        container.appendChild(el);
      }

      remaining = remaining.slice(earliest.index + earliest.match.length);
    }
  }

  const EMOJI_MAP = {
    // laughing / crying
    rofl:'🤣', joy:'😂', laughing:'😆', sweat_smile:'😅', sob:'😭', cry:'😢',
    // positive faces
    smile:'😄', grin:'😁', wink:'😉', heart_eyes:'😍', kissing_heart:'😘',
    blush:'😊', yum:'😋', sunglasses:'😎', smirk:'😏', star_struck:'🤩',
    partying_face:'🥳', relieved:'😌', innocent:'😇', hugging_face:'🤗',
    slightly_smiling_face:'🙂', upside_down_face:'🙃', sweat:'😓',
    // neutral / negative
    unamused:'😒', disappointed:'😞', worried:'😟', pensive:'😔',
    confused:'😕', rolling_eyes:'🙄', expressionless:'😑', neutral_face:'😐',
    no_mouth:'😶', slightly_frowning_face:'🙁', frowning_face:'☹',
    persevere:'😣', confounded:'😖', anguished:'😧',
    // angry / shocked
    angry:'😠', rage:'😡', astonished:'😲', flushed:'😳', fearful:'😨',
    cold_sweat:'😰', scream:'😱', exploding_head:'🤯', face_with_symbols_on_mouth:'🤬',
    // tired / sick
    tired_face:'😫', weary:'😩', sleeping:'😴', mask:'😷', nerd:'🤓',
    sneezing_face:'🤧', hot_face:'🥵', cold_face:'🥶', woozy_face:'🥴',
    dizzy_face:'😵', face_vomiting:'🤮', nauseated_face:'🤢',
    // misc faces
    thinking:'🤔', pleading:'🥺', monocle_face:'🧐', shushing_face:'🤫',
    lying_face:'🤥', zany_face:'🤪', cowboy_hat_face:'🤠', clown_face:'🤡',
    imp:'👿', japanese_ogre:'👹', japanese_goblin:'👺', skull_and_crossbones:'☠',
    // non-face
    skull:'💀', ghost:'👻', alien:'👽', robot:'🤖', poop:'💩',
    // hands / gestures
    wave:'👋', clap:'👏', thumbsup:'👍', '+1':'👍', thumbsdown:'👎', '-1':'👎',
    ok_hand:'👌', raised_hands:'🙌', pray:'🙏', muscle:'💪', handshake:'🤝',
    point_right:'👉', point_left:'👈', point_up:'👆', point_up_2:'☝',
    point_down:'👇', v:'✌', crossed_fingers:'🤞', metal:'🤘', call_me_hand:'🤙',
    open_hands:'👐', raised_hand:'✋', vulcan_salute:'🖖', writing_hand:'✍',
    pinched_fingers:'🤌', middle_finger:'🖕',
    // hearts
    heart:'❤', orange_heart:'🧡', yellow_heart:'💛', green_heart:'💚',
    blue_heart:'💙', purple_heart:'💜', brown_heart:'🤎', black_heart:'🖤',
    white_heart:'🤍', broken_heart:'💔', two_hearts:'💕', sparkling_heart:'💖',
    heartpulse:'💗', heartbeat:'💓', revolving_hearts:'💞', cupid:'💘',
    heart_decoration:'💟', heavy_heart_exclamation:'❣',
    // objects / symbols
    fire:'🔥', sparkles:'✨', tada:'🎉', rocket:'🚀', eyes:'👀', zap:'⚡',
    boom:'💥', bomb:'💣', '100':'💯', sweat_drops:'💦', zzz:'💤',
    white_check_mark:'✅', x:'❌', warning:'⚠', question:'❓', exclamation:'❗',
    star:'⭐', star2:'🌟', dizzy:'💫', crown:'👑', gem:'💎', trophy:'🏆',
    snowflake:'❄', rainbow:'🌈', sun:'☀', moon:'🌙', sunny:'☀',
    cloud:'☁', umbrella:'☂', snowman:'⛄', comet:'☄',
    // nature
    rose:'🌹', sunflower:'🌻', cherry_blossom:'🌸', bouquet:'💐',
    four_leaf_clover:'🍀', maple_leaf:'🍁', fallen_leaf:'🍂', leaves:'🍃',
    mushroom:'🍄', cactus:'🌵', palm_tree:'🌴', evergreen_tree:'🌲',
    seedling:'🌱', herb:'🌿', shamrock:'☘',
    // animals
    dog:'🐶', cat:'🐱', mouse:'🐭', hamster:'🐹', rabbit:'🐰', fox_face:'🦊',
    bear:'🐻', panda_face:'🐼', koala:'🐨', tiger:'🐯', lion:'🦁', cow:'🐮',
    pig:'🐷', frog:'🐸', monkey_face:'🐵', see_no_evil:'🙈',
    hear_no_evil:'🙉', speak_no_evil:'🙊', penguin:'🐧', bird:'🐦',
    chicken:'🐔', duck:'🐥', owl:'🦉', wolf:'🐺', snake:'🐍', dragon:'🐲',
    whale:'🐳', dolphin:'🐬', fish:'🐟', shark:'🦈', octopus:'🐙',
    butterfly:'🦋', bee:'🐝', bug:'🐛', spider:'🕷', turtle:'🐢',
    // food / drink
    pizza:'🍕', hamburger:'🍔', fries:'🍟', hotdog:'🌭', sandwich:'🥪',
    taco:'🌮', burrito:'🌯', sushi:'🍣', ramen:'🍜', spaghetti:'🍝',
    cake:'🎂', cupcake:'🧁', cookie:'🍪', chocolate_bar:'🍫', candy:'🍬',
    lollipop:'🍭', ice_cream:'🍨', icecream:'🍦', apple:'🍎', grapes:'🍇',
    watermelon:'🍉', strawberry:'🍓', peach:'🍑', cherries:'🍒',
    pineapple:'🍍', mango:'🥭', banana:'🍌', avocado:'🥑', broccoli:'🥦',
    coffee:'☕', tea:'🍵', beer:'🍺', beers:'🍻', wine_glass:'🍷',
    cocktail:'🍸', champagne:'🍾', milk_glass:'🥛', juice_box:'🧃',
    // activities / sports
    soccer:'⚽', basketball:'🏀', football:'🏈', baseball:'⚾', tennis:'🎾',
    volleyball:'🏐', rugby_football:'🏉', flying_disc:'🥏', golf:'⛳',
    video_game:'🎮', dart:'🎯', chess_pawn:'♟', joystick:'🕹',
    slot_machine:'🎰', game_die:'🎲', spades:'♠', hearts:'♥',
    diamonds:'♦', clubs:'♣', jigsaw:'🧩',
    // travel / places
    car:'🚗', taxi:'🚕', bus:'🚌', train:'🚆', airplane:'✈', helicopter:'🚁',
    ship:'🚢', boat:'⛵', bicycle:'🚲', motorcycle:'🏍',
    house:'🏠', office:'🏢', hospital:'🏥', school:'🏫', bank:'🏦',
    city_sunrise:'🌇', night_with_stars:'🌃', earth_americas:'🌎',
    earth_africa:'🌍', earth_asia:'🌏', globe_with_meridians:'🌐',
    // misc objects
    gift:'🎁', balloon:'🎈', confetti_ball:'🎊', ribbon:'🎀', ticket:'🎟',
    medal_sports:'🏅', military_medal:'🎖', reminder_ribbon:'🎗',
    telephone:'☎', phone:'📱', computer:'💻', keyboard:'⌨', printer:'🖨',
    mouse2:'🖱', camera:'📷', video_camera:'📹', tv:'📺', radio:'📻',
    newspaper:'📰', books:'📚', book:'📖', pencil:'✏', pen:'🖊',
    paperclip:'📎', scissors:'✂', lock:'🔒', unlock:'🔓', key:'🔑',
    hammer:'🔨', wrench:'🔧', gear:'⚙', chain:'⛓', shield:'🛡',
    sword:'⚔', dagger:'🗡', gun:'🔫', knife:'🔪', axe:'🪓',
    magic_wand:'🪄', crystal_ball:'🔮', microscope:'🔬', telescope:'🔭',
    pill:'💊', syringe:'💉', stethoscope:'🩺', adhesive_bandage:'🩹',
    drop_of_blood:'🩸', dna:'🧬', test_tube:'🧪', petri_dish:'🧫',
    // music
    musical_note:'🎵', notes:'🎶', microphone:'🎤', headphones:'🎧',
    guitar:'🎸', piano:'🎹', trumpet:'🎺', violin:'🎻', drum:'🥁',
    // flags / misc
    checkered_flag:'🏁', triangular_flag_on_post:'🚩', crossed_flags:'🎌',
    white_flag:'🏳', rainbow_flag:'🏳️', pirate_flag:'🏴‍☠️',
    // punctuation helpers
    tm:'™', copyright:'©', registered:'®',
  };

  function renderWithEmoji(container, text) {
    const re = /:([a-zA-Z0-9_+\-]+):/g;
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) container.appendChild(document.createTextNode(text.slice(last, m.index)));
      const name = m[1];
      container.appendChild(document.createTextNode(EMOJI_MAP[name] ?? m[0]));
      last = m.index + m[0].length;
    }
    if (last < text.length) container.appendChild(document.createTextNode(text.slice(last)));
  }

  function markMessage(el, text, state) {
    if (el.dataset.ageState === 'ok') return;
    el.textContent = text;
    el.style.fontStyle = 'normal';
    el.style.color = ({ ok: '#889ce6', warn: '#fee75c', error: '#ed4245', pending: '#99aab5' })[state] ?? '#99aab5';
  }

  // ─── Banner ──────────────────────────────────────────────────────────────────

  const BANNER_COLORS = {
    info:  { bg: '#313338', border: '#5865f2', icon: '🔐', color: '#c9cdfb' },
    warn:  { bg: '#2b2400', border: '#fee75c', icon: '⚠️',  color: '#fee75c' },
    error: { bg: '#2c0f0f', border: '#ed4245', icon: '🔓',  color: '#f38183' },
    ok:    { bg: '#0d2117', border: '#57f287', icon: '🔒',  color: '#57f287' },
  };

  function showBanner(msg, type = 'info', autohide = true) {
    if (_bannerTimer) { clearTimeout(_bannerTimer); _bannerTimer = null; }
    const cfg = BANNER_COLORS[type] ?? BANNER_COLORS.info;
    if (!_banner) {
      _banner = document.createElement('div');
      _banner.id = 'age-banner';
      Object.assign(_banner.style, {
        position: 'fixed', bottom: '80px', left: '50%', transform: 'translateX(-50%)',
        zIndex: '999999', maxWidth: '480px', width: 'max-content',
        borderRadius: '14px', padding: '10px 18px 10px 14px',
        display: 'flex', alignItems: 'center', gap: '10px',
        boxShadow: '0 4px 24px rgba(0,0,0,.45)',
        fontFamily: '"Segoe UI",system-ui,sans-serif', fontSize: '13px',
        fontWeight: '500', lineHeight: '1.4', transition: 'opacity 0.2s ease',
      });
      document.body.appendChild(_banner);
    }
    Object.assign(_banner.style, {
      background: cfg.bg, border: `1px solid ${cfg.border}`,
      color: cfg.color, opacity: '1', display: 'flex',
    });
    const icon = Object.assign(document.createElement('span'), { textContent: cfg.icon });
    icon.style.cssText = 'font-size:16px;flex-shrink:0';
    const textEl = Object.assign(document.createElement('span'), { textContent: msg });
    textEl.style.cssText = 'max-width:360px;white-space:normal';
    _banner.replaceChildren(icon, textEl);
    if (autohide) _bannerTimer = setTimeout(hideBanner, 4000);
  }

  function hideBanner() {
    if (!_banner) return;
    _banner.style.opacity = '0';
    setTimeout(() => { if (_banner) _banner.style.display = 'none'; }, 220);
  }

  // ─── Extension messages ───────────────────────────────────────────────────────

  const LOCKED_MSG = '🔒 Unlock extension to decrypt.';
  const LOCKED_BANNER = 'Discord Age Encryption is locked — click the extension icon to unlock.';

  function listenForMessages() {
    chrome.runtime.onMessage.addListener(async (msg) => {

      if (msg.type === 'UNLOCK') {
        try {
          const data = await localGet(['contacts', 'globalOn']);
          _contacts = data.contacts || {};
          _globalOn = data.globalOn !== false;
          _identity   = msg.identity;
          _signingKey = await importSigningKey(msg.identity).catch(e => {
            console.error('[age] failed to import signing key:', e);
            return null;
          });
          hideBanner();
          attachEnterHook();
          scanExisting();
          rescanPending();
        } catch (e) {
          console.error('[age] unlock error:', e);
        }
        return;
      }

      if (msg.type === 'CONTACTS_UPDATED') {
        const prevOn = _globalOn;
        const data   = await localGet(['contacts', 'globalOn']);
        _contacts = data.contacts || {};
        _globalOn = data.globalOn !== false;
        if (_globalOn && !prevOn) {
          _processedIds.clear();
          _decryptedCache.clear();
          rescanPending();
        } else if (!_globalOn && prevOn) {
          _processedIds.clear();
          _decryptedCache.clear();
          document.querySelectorAll('[id^="message-content-"][data-age-state="ok"]').forEach(el => {
            el.dataset.ageState = '';
            el.textContent = '🔒 Decryption disabled.';
            el.style.color = '#99aab5';
          });
        }
        return;
      }

      if (msg.type === 'RELOCK') {
        _identity   = null;
        _signingKey = null;
        _processedIds.clear();
        _decryptedCache.clear();
        detachEnterHook();
        document.querySelectorAll('[id^="message-content-"][data-age-state="ok"]').forEach(el => {
          el.dataset.ageState = '';
          el.textContent = LOCKED_MSG;
          el.style.color = '#99aab5';
        });
        showBanner(LOCKED_BANNER, 'info', false);
      }
    });
  }

  // ─── SPA navigation ──────────────────────────────────────────────────────────

  function startNavObserver() {
    let lastUrl = location.href;
    new MutationObserver(() => {
      if (location.href === lastUrl) return;
      lastUrl = location.href;
      setTimeout(() => {
        if (_identity) attachEnterHook();
        _msgObserver?.disconnect();
        waitForMessageList();
      }, 800);
    }).observe(document.body, { subtree: true, childList: true });
  }

  // ─── Init ────────────────────────────────────────────────────────────────────

  async function init() {
    listenForMessages();
    startNavObserver();
    const data = await localGet(['contacts', 'globalOn']);
    _contacts = data.contacts || {};
    _globalOn = data.globalOn !== false;
    waitForMessageList(() => {
      if (!_identity) showBanner(LOCKED_BANNER, 'info', false);
    });
  }

  if (document.body) {
    init().catch(e => console.error('[age] init error:', e));
  } else {
    document.addEventListener('DOMContentLoaded', () => init().catch(e => console.error('[age] init error:', e)));
  }

})();
