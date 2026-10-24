/* বাংলা টেসলা — sound: effects, loops, voice lines and music.
 * Served over http(s) it uses Web Audio (gapless loops, overlapping effects). Opened straight
 * from disk, browsers block fetch() on file://, so it falls back to <audio> elements. */
(function () {
  'use strict';

  const BT = (window.BT = window.BT || {});
  const BASE = 'assets/audio/';

  // name: [file, base volume]
  const SOUNDS = {
    bell: ['sfx/bell.mp3', 0.6],
    'horn-car': ['sfx/horn-car.mp3', 0.45],
    'horn-bus': ['sfx/horn-bus.mp3', 0.5],
    crash: ['sfx/crash.mp3', 0.7],
    thud: ['sfx/thud.mp3', 0.75],
    coin: ['sfx/coin.mp3', 0.35],
    battery: ['sfx/battery.mp3', 0.5],
    boost: ['sfx/boost.mp3', 0.6],
    pothole: ['sfx/pothole.mp3', 0.55],
    splash: ['sfx/splash.mp3', 0.6],
    whoosh: ['sfx/whoosh.mp3', 0.45],
    brake: ['sfx/brake.mp3', 0.3],
    tea: ['sfx/tea.mp3', 0.55],
    click: ['sfx/click.mp3', 0.35],
    win: ['sfx/win.mp3', 0.75],
    lose: ['sfx/lose.mp3', 0.7],
    cheer: ['sfx/cheer.mp3', 0.5],
    sorry: ['amar-vul-hoyeche.mp3', 1],
    raag: ['rag-korla.mp3', 1],
  };
  const LOOPS = {
    motor: ['sfx/motor-loop.mp3', 0.25],
    'ambience-day': ['sfx/ambience-day.mp3', 0.3],
    'ambience-night': ['sfx/ambience-night.mp3', 0.38],
    rain: ['sfx/rain-loop.mp3', 0.4],
  };
  const MUSIC = {
    menu: ['music/menu.mp3', 0.5],
    'race-day': ['music/race-day.mp3', 0.32],
    'race-night': ['music/race-night.mp3', 0.32],
  };

  const AC = window.AudioContext || window.webkitAudioContext;
  const web = /^https?:$/.test(location.protocol) && !!AC;
  const settings = { sfx: true, music: true };
  let ac = null, master = null;
  const buffers = {}; // Web Audio buffers
  const pools = {}; // <audio> fallback
  const loops = {};
  const voices = {};
  let music = null; // { name, el, vol }
  const fading = new Set();

  function context() {
    if (!ac && AC) {
      ac = new AC();
      master = ac.createGain();
      master.gain.value = 0.9;
      master.connect(ac.destination);
    }
    return ac;
  }

  function pool(name) {
    if (!pools[name]) {
      const el = new Audio(BASE + SOUNDS[name][0]);
      el.preload = 'auto';
      pools[name] = [el];
    }
    return pools[name];
  }

  function preload() {
    if (!web) {
      for (const name in SOUNDS) pool(name);
      return;
    }
    const a = context();
    const all = Object.assign({}, SOUNDS, LOOPS);
    for (const name in all) {
      fetch(BASE + all[name][0])
        .then((r) => r.arrayBuffer())
        .then((b) => new Promise((res, rej) => a.decodeAudioData(b, res, rej)))
        .then((buf) => {
          buffers[name] = buf;
        })
        .catch(() => {});
    }
  }

  function setPitch(el, keep) {
    el.preservesPitch = keep;
    el.mozPreservesPitch = keep;
    el.webkitPreservesPitch = keep;
  }

  function play(name, opts = {}) {
    if (!settings.sfx || !SOUNDS[name]) return null;
    const vol = SOUNDS[name][1] * (opts.volume == null ? 1 : opts.volume);
    const rate = opts.rate || 1;
    if (web) {
      const buf = buffers[name];
      if (!buf || !ac) return null;
      const src = ac.createBufferSource();
      src.buffer = buf;
      src.playbackRate.value = rate;
      const g = ac.createGain();
      g.gain.value = vol;
      src.connect(g);
      g.connect(master);
      src.start();
      return { end: ac.currentTime + buf.duration / rate };
    }
    const p = pool(name);
    let el = p.find((e) => e.paused || e.ended);
    if (!el) {
      if (p.length < 4) p.push((el = p[0].cloneNode()));
      else el = p[0];
    }
    el.volume = Math.min(1, vol * 0.9);
    setPitch(el, rate === 1);
    el.playbackRate = rate;
    try {
      el.currentTime = 0;
    } catch (e) {
      // not seekable yet; it plays from the start anyway
    }
    el.play().catch(() => {});
    return { el };
  }

  // Voice lines never restart while they are still playing.
  function voice(name) {
    const v = voices[name];
    if (v && (v.el ? !v.el.paused && !v.el.ended : ac && ac.currentTime < v.end)) return;
    voices[name] = play(name);
  }

  // Starts a loop or updates its volume and pitch; call it every frame while it should play.
  function loop(name, vol = 1, rate = 1) {
    const def = LOOPS[name];
    if (!def) return;
    const v = settings.sfx ? def[1] * vol : 0;
    let L = loops[name];
    if (!L) {
      if (v <= 0.001) return;
      if (web) {
        const buf = buffers[name];
        if (!buf || !ac) return;
        const src = ac.createBufferSource();
        src.buffer = buf;
        src.loop = true;
        src.loopStart = 0.03; // skip mp3 padding at the seams
        src.loopEnd = buf.duration - 0.03;
        const g = ac.createGain();
        g.gain.value = 0;
        src.connect(g);
        g.connect(master);
        src.start(0, 0.03);
        L = loops[name] = { src, g };
      } else {
        const el = new Audio(BASE + def[0]);
        el.loop = true;
        el.volume = 0;
        el.play().catch(() => {});
        L = loops[name] = { el };
      }
    }
    if (L.g) {
      L.g.gain.setTargetAtTime(v, ac.currentTime, 0.1);
      L.src.playbackRate.setTargetAtTime(rate, ac.currentTime, 0.1);
    } else {
      L.el.volume = Math.min(1, v * 0.9);
      setPitch(L.el, false);
      L.el.playbackRate = rate;
    }
  }

  function stopLoops() {
    for (const name in loops) {
      const L = loops[name];
      if (L.src) {
        try {
          L.src.stop();
        } catch (e) {
          // already stopped
        }
      } else {
        L.el.pause();
      }
      delete loops[name];
    }
  }

  function fadeTo(el, target, stopAtEnd) {
    el._target = target;
    el._stop = !!stopAtEnd;
    fading.add(el);
  }

  setInterval(() => {
    for (const el of fading) {
      const d = el._target - el.volume;
      if (Math.abs(d) < 0.03) {
        el.volume = el._target;
        fading.delete(el);
        if (el._stop) el.pause();
      } else {
        el.volume = Math.max(0, Math.min(1, el.volume + Math.sign(d) * 0.04));
      }
    }
  }, 40);

  // Crossfades to a music track; null fades the music out.
  function setMusic(name) {
    if (music && music.name === name) return;
    if (music) fadeTo(music.el, 0, true);
    music = null;
    if (!name || !MUSIC[name]) return;
    const el = new Audio(BASE + MUSIC[name][0]);
    el.loop = true;
    el.volume = 0;
    music = { name, el, vol: MUSIC[name][1] };
    if (settings.music) {
      el.play().catch(() => {});
      fadeTo(el, music.vol);
    }
  }

  function set(opts) {
    if (opts.sfx != null) {
      settings.sfx = !!opts.sfx;
      if (!settings.sfx) for (const n in loops) loop(n, 0);
    }
    if (opts.music != null) {
      settings.music = !!opts.music;
      if (music) {
        if (settings.music) {
          music.el.play().catch(() => {});
          fadeTo(music.el, music.vol);
        } else {
          fadeTo(music.el, 0, true);
        }
      }
    }
  }

  // Browsers only allow sound after a click or key press.
  function unlock() {
    const a = context();
    if (a && a.state === 'suspended') a.resume();
    if (music && settings.music && music.el.paused) {
      music.el.play().catch(() => {});
      fadeTo(music.el, music.vol);
    }
  }

  // Synthesized countdown beep.
  function beep(freq, dur, vol) {
    if (!settings.sfx) return;
    const a = context();
    if (!a) return;
    const o = a.createOscillator(), g = a.createGain();
    const t0 = a.currentTime;
    o.type = 'square';
    o.frequency.value = freq;
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(vol, t0 + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    o.connect(g);
    g.connect(master);
    o.start(t0);
    o.stop(t0 + dur + 0.05);
  }

  BT.audio = { preload, unlock, play, voice, loop, stopLoops, music: setMusic, set, beep, settings };
})();
