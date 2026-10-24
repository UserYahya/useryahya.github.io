/* বাংলা টেসলা — sprite art.
 *
 * Every sprite is drawn with plain Canvas 2D calls, so the graphics preview and
 * the game share one source. Draw functions follow one convention:
 *   draw*(ctx, x, y, s, t, opts)
 * (x, y) is the ground-contact point, sprites face right, s is the scale and
 * t is time in seconds (spinning wheels, tassels, walking, blinking).
 */
(function () {
  'use strict';

  const BT = (window.BT = window.BT || {});
  const TAU = Math.PI * 2;
  const OL = '#1d1428'; // outline ink shared by every sprite
  const HAIR = '#1a1210';
  const FONT_DISPLAY = "'Galada', 'Hind Siliguri', 'Nirmala UI', 'Noto Sans Bengali', 'Vrinda', sans-serif";
  const FONT_UI = "'Hind Siliguri', 'Nirmala UI', 'Noto Sans Bengali', 'Vrinda', sans-serif";

  // ------------------------------------------------------------------ helpers

  function rrect(ctx, x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h / 2));
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function paint(ctx, fill, stroke, lw) {
    if (fill) {
      ctx.fillStyle = fill;
      ctx.fill();
    }
    if (stroke) {
      ctx.lineWidth = lw || 2;
      ctx.strokeStyle = stroke;
      ctx.stroke();
    }
  }

  function circle(ctx, x, y, r) {
    ctx.beginPath();
    ctx.arc(x, y, r, 0, TAU);
  }

  function ellipse(ctx, x, y, rx, ry, rot) {
    ctx.beginPath();
    ctx.ellipse(x, y, rx, ry, rot || 0, 0, TAU);
  }

  // A thick polyline with an ink outline: limbs, frame tubes, tassels.
  function tube(ctx, pts, color, lw, outline = OL) {
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.beginPath();
    ctx.moveTo(pts[0], pts[1]);
    for (let i = 2; i < pts.length; i += 2) ctx.lineTo(pts[i], pts[i + 1]);
    if (outline) {
      ctx.strokeStyle = outline;
      ctx.lineWidth = lw + 2.4;
      ctx.stroke();
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = lw;
    ctx.stroke();
  }

  // Lighten (amt > 0) or darken (amt < 0) a #rrggbb colour.
  function shade(hex, amt) {
    const n = parseInt(hex.slice(1), 16);
    let r = n >> 16, g = (n >> 8) & 255, b = n & 255;
    if (amt >= 0) {
      r += (255 - r) * amt; g += (255 - g) * amt; b += (255 - b) * amt;
    } else {
      r *= 1 + amt; g *= 1 + amt; b *= 1 + amt;
    }
    return 'rgb(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ')';
  }

  // Integer hash -> [0, 1). Scenery and decorations use it so they never flicker.
  function hash(n) {
    let h = Math.imul((n | 0) ^ 0x9e3779b9, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return (h >>> 0) / 4294967296;
  }

  function rng(seed) {
    let i = 0;
    return () => hash(seed * 7919 + (i++) * 104729);
  }

  const BN_DIGITS = '০১২৩৪৫৬৭৮৯';
  function bn(v) {
    return String(v).replace(/[0-9]/g, (d) => BN_DIGITS[d]);
  }

  // Gingham check for lungis and gamchhas, cached per context.
  const patternCache = new WeakMap();
  function check(ctx, a, b, size = 6) {
    let m = patternCache.get(ctx);
    if (!m) patternCache.set(ctx, (m = new Map()));
    const key = a + b + size;
    let p = m.get(key);
    if (!p) {
      const c = document.createElement('canvas');
      c.width = c.height = size * 2;
      const g = c.getContext('2d');
      g.fillStyle = a;
      g.fillRect(0, 0, size * 2, size * 2);
      g.fillStyle = b;
      g.globalAlpha = 0.5;
      g.fillRect(0, 0, size, size * 2);
      g.fillRect(0, 0, size * 2, size);
      p = ctx.createPattern(c, 'repeat');
      m.set(key, p);
    }
    return p;
  }

  // Centered text shrunk to fit maxW.
  function fitText(ctx, text, x, y, maxW, size, family, fill, stroke, lw, weight) {
    const w8 = weight ? weight + ' ' : '';
    ctx.font = w8 + size + 'px ' + family;
    const w = ctx.measureText(text).width;
    if (w > maxW) ctx.font = w8 + (size * maxW) / w + 'px ' + family;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    if (stroke) {
      ctx.lineJoin = 'round';
      ctx.lineWidth = lw || 3;
      ctx.strokeStyle = stroke;
      ctx.strokeText(text, x, y);
    }
    ctx.fillStyle = fill;
    ctx.fillText(text, x, y);
  }

  // Two-bone IK: the joint between root a and end b; bend picks the side.
  function joint(ax, ay, bx, by, l1, l2, bend) {
    const dx = bx - ax, dy = by - ay;
    const len = Math.hypot(dx, dy) || 1;
    const d = Math.max(Math.abs(l1 - l2) + 0.01, Math.min(l1 + l2 - 0.01, len));
    const a = (l1 * l1 - l2 * l2 + d * d) / (2 * d);
    const h = Math.sqrt(Math.max(0, l1 * l1 - a * a));
    const ux = dx / len, uy = dy / len;
    return [ax + ux * a - uy * h * bend, ay + uy * a + ux * h * bend];
  }

  function bolt(ctx, x, y, h, fill, stroke) {
    const k = h / 20;
    ctx.beginPath();
    ctx.moveTo(x + 2 * k, y - 10 * k);
    ctx.lineTo(x - 5 * k, y + 1 * k);
    ctx.lineTo(x - 0.5 * k, y + 1 * k);
    ctx.lineTo(x - 2 * k, y + 10 * k);
    ctx.lineTo(x + 5 * k, y - 2 * k);
    ctx.lineTo(x + 0.5 * k, y - 2 * k);
    ctx.closePath();
    paint(ctx, fill, stroke, 1.2);
  }

  function star(ctx, x, y, r, points = 5, inner = 0.45) {
    ctx.beginPath();
    for (let i = 0; i < points * 2; i++) {
      const a = -Math.PI / 2 + (i * Math.PI) / points;
      const rr = i % 2 ? r * inner : r;
      ctx.lineTo(x + Math.cos(a) * rr, y + Math.sin(a) * rr);
    }
    ctx.closePath();
  }

  // The eight-petal flower that shows up all over rickshaw art.
  function flower(ctx, x, y, r, petal, centre) {
    for (let i = 0; i < 8; i++) {
      const a = (i / 8) * TAU;
      ellipse(ctx, x + Math.cos(a) * r * 0.55, y + Math.sin(a) * r * 0.55, r * 0.42, r * 0.22, a);
      paint(ctx, petal, OL, 0.8);
    }
    circle(ctx, x, y, r * 0.28);
    paint(ctx, centre, OL, 0.8);
  }

  function easeOutBack(p) {
    const c1 = 1.70158, c3 = c1 + 1;
    return 1 + c3 * Math.pow(p - 1, 3) + c1 * Math.pow(p - 1, 2);
  }

  function rgba(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return 'rgba(' + (n >> 16) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + Math.max(0, Math.min(1, a)).toFixed(3) + ')';
  }

  // ------------------------------------------------------------------ night lighting
  // At night each depth layer is drawn with its daytime colours and darkened with a
  // multiply tint. Anything that gives off light queues an emit() while it is drawn,
  // and is painted again on top of its layer at full strength.

  const NIGHT_TINT = '#465087';
  const night = { on: false, items: [] };

  function beginNight(on) {
    night.on = !!on;
    night.items.length = 0;
  }

  const isNight = () => night.on;

  // Runs fn(ctx) in the light pass, with the transform that is current now.
  function emit(ctx, fn, op) {
    if (night.on) night.items.push({ m: ctx.getTransform(), fn, op: op || 'source-over' });
  }

  function glow(ctx, x, y, r, color, alpha) {
    emit(ctx, (c) => {
      const g = c.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, rgba(color, alpha));
      g.addColorStop(1, rgba(color, 0));
      c.fillStyle = g;
      c.fillRect(x - r, y - r, r * 2, r * 2);
    }, 'lighter');
  }

  // Headlight cone pointing right from (x, y), aimed slightly at the road.
  function beam(ctx, x, y, len, spread, color, alpha) {
    emit(ctx, (c) => {
      const g = c.createLinearGradient(x, 0, x + len, 0);
      g.addColorStop(0, rgba(color, alpha));
      g.addColorStop(1, rgba(color, 0));
      c.fillStyle = g;
      c.beginPath();
      c.moveTo(x, y - 3);
      c.lineTo(x + len, y - spread * 0.7);
      c.lineTo(x + len, y + spread * 1.3);
      c.lineTo(x, y + 3);
      c.closePath();
      c.fill();
    }, 'lighter');
  }

  // Draws one depth layer. At night the layer is painted off-screen, darkened on its own
  // (so nearer layers still cover its lit windows), composited, and then its lights go on top.
  const layerCache = new WeakMap();
  function layer(ctx, draw) {
    if (!night.on) {
      draw(ctx);
      return;
    }
    const cv = ctx.canvas;
    let L = layerCache.get(cv);
    if (!L) layerCache.set(cv, (L = { off: document.createElement('canvas'), tint: document.createElement('canvas') }));
    for (const c of [L.off, L.tint]) {
      if (c.width !== cv.width || c.height !== cv.height) {
        c.width = cv.width;
        c.height = cv.height;
      }
    }
    const oc = L.off.getContext('2d');
    oc.setTransform(1, 0, 0, 1, 0, 0);
    oc.clearRect(0, 0, cv.width, cv.height);
    oc.setTransform(ctx.getTransform());
    const outer = night.items;
    night.items = [];
    draw(oc);
    const lights = night.items;
    night.items = outer;
    // darken only the pixels this layer painted: tint = layer alpha × NIGHT_TINT, then multiply
    oc.setTransform(1, 0, 0, 1, 0, 0);
    const tc = L.tint.getContext('2d');
    tc.globalCompositeOperation = 'copy';
    tc.drawImage(L.off, 0, 0);
    tc.globalCompositeOperation = 'source-in';
    tc.fillStyle = NIGHT_TINT;
    tc.fillRect(0, 0, cv.width, cv.height);
    oc.globalCompositeOperation = 'multiply';
    oc.drawImage(L.tint, 0, 0);
    oc.globalCompositeOperation = 'source-over';
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(L.off, 0, 0);
    for (const it of lights) {
      ctx.setTransform(it.m);
      ctx.globalCompositeOperation = it.op;
      ctx.globalAlpha = 1;
      it.fn(ctx);
    }
    ctx.restore();
  }

  // ------------------------------------------------------------------ rickshaws

  const SKINS = {
    tesla: {
      name: 'বাংলা টেসলা', frame: '#12b5a5', trim: '#ffd23f', hood: '#8c1239',
      bands: ['#ff4fa3', '#ffd23f', '#35d07f', '#4cc3ff'], seat: '#ef3e6d',
      panel: '#1d2f6f', ink: '#ffd23f', mud: '#ff4fa3',
      shirt: '#f6f2e8', sleeve: false, lungi: ['#2457c5', '#0f2a66'], gamchha: ['#e63946', '#fff4e6'],
      skin: '#8a5a3c', shades: true, battery: true, led: true,
    },
    // garage skins for বাংলা টেসলা
    sky: {
      name: 'বাংলা টেসলা', frame: '#2b7de9', trim: '#ffffff', hood: '#0b3d91',
      bands: ['#4cc3ff', '#ffffff', '#ffd23f', '#35d07f'], seat: '#4cc3ff',
      panel: '#ffffff', ink: '#0b3d91', mud: '#ffd23f',
      shirt: '#f6f2e8', sleeve: false, lungi: ['#2457c5', '#0f2a66'], gamchha: ['#e63946', '#fff4e6'],
      skin: '#8a5a3c', shades: true, battery: true, led: true,
    },
    gold: {
      name: 'বাংলা টেসলা', frame: '#1b1b1f', trim: '#f4c430', hood: '#1b1b1f',
      bands: ['#f4c430', '#ffe28a', '#c9972b', '#ffffff'], seat: '#f4c430',
      panel: '#1b1b1f', ink: '#f4c430', mud: '#f4c430',
      shirt: '#f6f2e8', sleeve: false, lungi: ['#2457c5', '#0f2a66'], gamchha: ['#e63946', '#fff4e6'],
      skin: '#8a5a3c', shades: true, battery: true, led: true,
    },
    queen: {
      name: 'বাংলা টেসলা', frame: '#7b2cbf', trim: '#ff4fa3', hood: '#2b0a4f',
      bands: ['#ff4fa3', '#b388ff', '#4cc3ff', '#ffd23f'], seat: '#b388ff',
      panel: '#2b0a4f', ink: '#ff9de2', mud: '#ff4fa3',
      shirt: '#f6f2e8', sleeve: false, lungi: ['#2457c5', '#0f2a66'], gamchha: ['#e63946', '#fff4e6'],
      skin: '#8a5a3c', shades: true, battery: true, led: true,
    },
    peacock: {
      name: 'ময়ূরপঙ্খী', frame: '#2a9d4b', trim: '#ffd23f', hood: '#1c3d99',
      bands: ['#35d07f', '#ff9f1c', '#ff4fa3', '#ffd23f'], seat: '#ff9f1c',
      panel: '#5b1a8c', ink: '#ffffff', mud: '#ffd23f',
      shirt: '#ffb4a2', sleeve: true, lungi: ['#6a994e', '#2d4a22'], gamchha: ['#f4a261', '#fff4e6'],
      skin: '#7a4a2e',
    },
    redfairy: {
      name: 'লাল পরী', frame: '#d62828', trim: '#f8f9fa', hood: '#1b1b1f',
      bands: ['#ff4fa3', '#ffd23f', '#f8f9fa', '#35d07f'], seat: '#ffd23f',
      panel: '#d62828', ink: '#ffffff', mud: '#f8f9fa',
      shirt: '#9bc1ff', sleeve: true, lungi: ['#8d0801', '#3d0300'], gamchha: ['#2a9d8f', '#fff4e6'],
      skin: '#9a6444',
    },
    golden: {
      name: 'সোনার তরী', frame: '#f4b400', trim: '#d62828', hood: '#0b6e4f',
      bands: ['#ffd23f', '#ff4fa3', '#f8f9fa', '#ff9f1c'], seat: '#d62828',
      panel: '#0b6e4f', ink: '#ffd23f', mud: '#d62828',
      shirt: '#e9edc9', sleeve: true, lungi: ['#5e548e', '#231942'], gamchha: ['#e63946', '#fff4e6'],
      skin: '#6f4329',
    },
  };

  // Rickshaw geometry in local units (y is negative upwards).
  const RK = {
    rearX: -78, frontX: 104, wheelY: -31, wheelR: 31,
    bb: [34, -40], hip: [26, -107], shoulder: [38, -153], head: [48, -176], grip: [68, -126],
  };

  function wheel(ctx, x, y, r, rot, o = {}) {
    const far = !!o.far;
    ctx.save();
    ctx.translate(x, y);
    circle(ctx, 0, 0, r - 2.6);
    ctx.lineWidth = 5.2;
    ctx.strokeStyle = far ? '#0e0c12' : '#1c1922';
    ctx.stroke();
    circle(ctx, 0, 0, r - 5.8);
    ctx.lineWidth = 1.8;
    ctx.strokeStyle = far ? '#6b7480' : '#d7dee7';
    ctx.stroke();
    ctx.rotate(rot);
    ctx.beginPath();
    for (let i = 0; i < 18; i++) {
      const a = (i / 18) * TAU;
      ctx.moveTo(Math.cos(a) * 3.5, Math.sin(a) * 3.5);
      ctx.lineTo(Math.cos(a + 0.32) * (r - 6), Math.sin(a + 0.32) * (r - 6));
    }
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = far ? 'rgba(120,128,140,0.8)' : 'rgba(228,233,240,0.95)';
    ctx.stroke();
    if (o.beads && !far) {
      for (let i = 0; i < 6; i++) {
        const a = (i / 6) * TAU + 0.2;
        circle(ctx, Math.cos(a) * r * 0.6, Math.sin(a) * r * 0.6, 2.1);
        paint(ctx, o.beads[i % o.beads.length]);
      }
    }
    if (o.motor) {
      // the hub motor that makes it a "Tesla"
      circle(ctx, 0, 0, 9.5);
      paint(ctx, '#2b2f38', OL, 1.4);
      circle(ctx, 0, 0, 6);
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = '#9aa3ae';
      ctx.stroke();
    }
    circle(ctx, 0, 0, 3);
    paint(ctx, far ? '#59616b' : '#b9c2cc', OL, 1);
    ctx.restore();
  }

  function arcBand(ctx, cx, cy, r, a0, a1, color, lw) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, a0, a1);
    ctx.lineCap = 'butt';
    ctx.strokeStyle = OL;
    ctx.lineWidth = lw + 2.6;
    ctx.stroke();
    ctx.strokeStyle = color;
    ctx.lineWidth = lw;
    ctx.stroke();
  }

  // Folding hood (হুড): a fan of painted ribs around a pivot beside the seat.
  function hood(ctx, k, t) {
    const px = -84, py = -98, A0 = Math.PI, A1 = 0.72, N = 30;
    const pt = (a, sc) => {
      const rx = a > Math.PI / 2 ? 46 : 76; // tighter at the back, deeper over the passenger
      return [px + Math.cos(a) * rx * sc, py - Math.sin(a) * 90 * sc];
    };
    const edge = (sc, c = ctx) => {
      c.beginPath();
      for (let i = 0; i <= N; i++) {
        const p = pt(A0 + ((A1 - A0) * i) / N, sc);
        if (i) c.lineTo(p[0], p[1]);
        else c.moveTo(p[0], p[1]);
      }
    };
    if (k.led) {
      // chasing LED string along the hood trim, the বাংলা টেসলা's night look
      emit(ctx, (c) => {
        edge(1, c);
        c.lineCap = 'round';
        c.lineWidth = 3.2;
        c.shadowBlur = 8;
        ['#ff4fa3', '#4cc3ff', '#ffd23f'].forEach((col, i) => {
          c.setLineDash([2, 10]);
          c.lineDashOffset = -t * 40 - i * 4;
          c.strokeStyle = col;
          c.shadowColor = col;
          c.stroke();
        });
        c.setLineDash([]);
        c.shadowBlur = 0;
      });
    }
    edge(1);
    ctx.lineTo(px, py);
    ctx.closePath();
    paint(ctx, k.hood);
    ctx.save();
    ctx.clip();
    for (let j = 1; j <= 4; j++) {
      const p = pt(A0 + ((A1 - A0) * j) / 5, 1.1);
      tube(ctx, [px, py, p[0], p[1]], k.bands[j - 1], 5, null);
    }
    edge(0.84);
    ctx.strokeStyle = k.bands[0];
    ctx.lineWidth = 3;
    ctx.stroke();
    const fp = pt(1.75, 0.5);
    flower(ctx, fp[0], fp[1], 15, k.bands[1], k.bands[0]);
    ctx.restore();
    edge(1);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = OL;
    ctx.lineWidth = 10;
    ctx.stroke();
    ctx.strokeStyle = k.trim;
    ctx.lineWidth = 7;
    ctx.stroke();
    for (let i = 1; i < N; i += 2) {
      const p = pt(A0 + ((A1 - A0) * i) / N, 1);
      circle(ctx, p[0], p[1], 1.5);
      paint(ctx, '#eef2f7');
    }
    const f = pt(A1, 1);
    tube(ctx, [px, py, f[0], f[1]], k.trim, 4);
    circle(ctx, px, py, 4.5);
    paint(ctx, '#cfd6df', OL, 1.4);
  }

  function batteryPack(ctx, k, t) {
    ctx.beginPath();
    ctx.moveTo(-40, -33);
    ctx.quadraticCurveTo(-58, -20, RK.rearX + 8, RK.wheelY + 3);
    ctx.strokeStyle = '#111';
    ctx.lineWidth = 2;
    ctx.stroke();
    rrect(ctx, -44, -46, 40, 15, 3);
    paint(ctx, '#262a33', OL, 1.6);
    rrect(ctx, -40, -43, 20, 9, 2);
    paint(ctx, k.trim);
    bolt(ctx, -30, -38.5, 8.5, OL);
    const blink = 0.5 + 0.5 * Math.sin(t * 6);
    circle(ctx, -11, -38.5, 2.4);
    paint(ctx, 'rgba(57,255,136,' + (0.45 + 0.55 * blink).toFixed(2) + ')');
  }

  // Hurricane lantern hung under the seat after dark (pedal rickshaws have no headlight).
  function lantern(ctx, x, y, t) {
    tube(ctx, [x, y, x, y + 7], '#3a3640', 1.2, null);
    rrect(ctx, x - 4, y + 6, 8, 3, 1);
    paint(ctx, '#3a3640');
    ellipse(ctx, x, y + 15, 5, 6.5);
    paint(ctx, '#ffd98a', OL, 1);
    rrect(ctx, x - 5, y + 21, 10, 3, 1);
    paint(ctx, '#3a3640');
    const flicker = 0.8 + Math.sin(t * 13) * 0.08 + Math.sin(t * 7.3) * 0.06;
    glow(ctx, x, y + 15, 46, '#ffb347', flicker);
    emit(ctx, (c) => {
      ellipse(c, x, y + 15, 4.2, 5.6);
      c.fillStyle = '#fff1b8';
      c.fill();
    });
  }

  const TASSELS = ['#ff4fa3', '#ffd23f', '#35d07f', '#4cc3ff', '#ff9f1c', '#f1f5f9'];
  function tassels(ctx, ax, ay, t, sway) {
    for (let i = 0; i < TASSELS.length; i++) {
      const len = 20 + (i % 3) * 5;
      const ang = 0.5 * sway + Math.sin(t * 8 + i * 0.9) * (0.1 + 0.12 * sway);
      const x0 = ax + i * 1.7;
      const ex = x0 - Math.sin(ang) * len, ey = ay + Math.cos(ang) * len;
      tube(ctx, [x0, ay, (x0 + ex) / 2 - 1.5 * sway, (ay + ey) / 2, ex, ey], TASSELS[i], 2.2, null);
    }
  }

  function riderLeg(ctx, hip, foot, k, far) {
    const knee = joint(hip[0], hip[1], foot[0], foot[1], 38, 42, -1);
    const skin = far ? shade(k.skin, -0.3) : k.skin;
    tube(ctx, [knee[0], knee[1], foot[0], foot[1]], skin, 8);
    ellipse(ctx, foot[0] + 4, foot[1] + 1, 7.5, 3.2);
    paint(ctx, far ? '#2a1f18' : '#4a3426', OL, 1.2);
    const lungi = check(ctx, far ? shade(k.lungi[0], -0.35) : k.lungi[0], k.lungi[1]);
    tube(ctx, [hip[0], hip[1], knee[0], knee[1]], lungi, 15);
  }

  function riderArm(ctx, sh, hand, k, far) {
    const el = joint(sh[0], sh[1], hand[0], hand[1], 21, 21, 1);
    const skin = far ? shade(k.skin, -0.3) : k.skin;
    tube(ctx, [sh[0], sh[1], el[0], el[1], hand[0], hand[1]], skin, 7);
    if (k.sleeve) {
      const mx = sh[0] + (el[0] - sh[0]) * 0.65, my = sh[1] + (el[1] - sh[1]) * 0.65;
      tube(ctx, [sh[0], sh[1], mx, my], far ? shade(k.shirt, -0.3) : k.shirt, 10);
    }
    circle(ctx, hand[0], hand[1], 4.2);
    paint(ctx, skin, OL, 1.2);
  }

  function gamchha(ctx, hx, hy, k, t, sway) {
    const pat = check(ctx, k.gamchha[0], k.gamchha[1], 3);
    const f = Math.sin(t * 10) * 2.5, f2 = Math.sin(t * 10 + 1.3) * 2.5, sw = sway * 6;
    ctx.save();
    ctx.translate(hx, hy);
    ctx.rotate(-0.12);
    ctx.beginPath();
    ctx.moveTo(-11, -8);
    ctx.quadraticCurveTo(-20 - sw, -10 + f, -28 - sw * 1.5, -5 + f);
    ctx.lineTo(-27 - sw * 1.5, f);
    ctx.quadraticCurveTo(-19, -3, -11, -4);
    ctx.closePath();
    paint(ctx, pat, OL, 1.1);
    ctx.beginPath();
    ctx.moveTo(-11, -6);
    ctx.quadraticCurveTo(-17 - sw, 1 + f2, -23 - sw, 7 + f2);
    ctx.lineTo(-19 - sw, 9 + f2);
    ctx.quadraticCurveTo(-14, 2, -10, -2);
    ctx.closePath();
    paint(ctx, pat, OL, 1.1);
    rrect(ctx, -12.5, -10, 25, 6, 3);
    paint(ctx, pat, OL, 1.2);
    circle(ctx, -12, -6.5, 3.2);
    paint(ctx, pat, OL, 1.1);
    ctx.restore();
  }

  function rider(ctx, k, t, o, footN, sway) {
    const [hx, hy] = RK.head;
    const sh = RK.shoulder, grip = RK.grip;
    const pose = o.pose;
    // far arm, behind the body
    const handF = pose === 'sorry' ? [hx + 1, hy] : [grip[0] + 3, grip[1] - 2];
    riderArm(ctx, [sh[0] - 3, sh[1] - 1], handF, k, true);
    // torso
    ctx.beginPath();
    ctx.moveTo(13, -103);
    ctx.quadraticCurveTo(13, -141, 29, -162);
    ctx.lineTo(46, -160);
    ctx.quadraticCurveTo(53, -131, 41, -104);
    ctx.closePath();
    paint(ctx, k.shirt, OL, 1.8);
    if (!k.sleeve) {
      // sleeveless vest (স্যান্ডো গেঞ্জি): show the chest above the scoop neck
      ctx.beginPath();
      ctx.moveTo(40, -160);
      ctx.lineTo(46.5, -160);
      ctx.quadraticCurveTo(48, -152, 46, -148);
      ctx.quadraticCurveTo(41, -152, 40, -160);
      paint(ctx, k.skin);
    }
    // lungi hitched up for riding
    ctx.beginPath();
    ctx.moveTo(10, -113);
    ctx.lineTo(40, -115);
    ctx.lineTo(46, -101);
    ctx.quadraticCurveTo(28, -96, 9, -100);
    ctx.closePath();
    paint(ctx, check(ctx, k.lungi[0], k.lungi[1]), OL, 1.6);
    riderLeg(ctx, RK.hip, footN, k, false);
    // head
    rrect(ctx, 40, -168, 9, 11, 3);
    paint(ctx, k.skin, OL, 1.2);
    circle(ctx, hx, hy, 11.5);
    paint(ctx, k.skin, OL, 1.8);
    ctx.beginPath();
    ctx.arc(hx, hy, 11.8, Math.PI * 0.86, Math.PI * 1.86);
    ctx.quadraticCurveTo(hx + 1, hy - 5, hx - 10, hy + 2);
    ctx.closePath();
    paint(ctx, HAIR);
    ellipse(ctx, hx - 3, hy + 1.5, 2.6, 3.6);
    paint(ctx, shade(k.skin, -0.12), OL, 1);
    if (k.shades) {
      ctx.beginPath();
      ctx.moveTo(hx + 1, hy - 4.5);
      ctx.lineTo(hx + 12.5, hy - 4.5);
      ctx.lineTo(hx + 11.5, hy + 0.5);
      ctx.quadraticCurveTo(hx + 6, hy + 2.5, hx + 3, hy - 0.5);
      ctx.closePath();
      paint(ctx, '#101018', OL, 1);
      tube(ctx, [hx + 5, hy - 3, hx + 8.5, hy - 3], 'rgba(120,220,255,0.9)', 1.2, null);
      tube(ctx, [hx + 1, hy - 3.5, hx - 3, hy - 1.5], '#101018', 1.4, null);
    } else {
      circle(ctx, hx + 6.5, hy - 1.5, 1.5);
      paint(ctx, OL);
      tube(ctx, [hx + 4, hy - 5, hx + 9, hy - 5.5], HAIR, 1.3, null);
    }
    ctx.beginPath();
    ctx.moveTo(hx + 10.8, hy - 1.5);
    ctx.lineTo(hx + 14.5, hy + 3.5);
    ctx.lineTo(hx + 10.3, hy + 4.6);
    paint(ctx, k.skin, OL, 1.2);
    ellipse(ctx, hx + 9.2, hy + 6.4, 4, 1.6, -0.25);
    paint(ctx, HAIR);
    if (o.talk) {
      ellipse(ctx, hx + 8.6, hy + 9, 2, 1.4 + Math.abs(Math.sin(t * 16)) * 1.6);
      paint(ctx, '#5a1a1a');
    }
    gamchha(ctx, hx, hy, k, t, sway);
    // handlebar, bell and tassels
    tube(ctx, [88, -115, 84, -124, 70, -126], '#cfd6df', 3.2);
    rrect(ctx, 61, -129.5, 11, 6.5, 3);
    paint(ctx, '#26222b', OL, 1);
    circle(ctx, 80, -129, 3.2);
    paint(ctx, '#e9eef5', OL, 1);
    tassels(ctx, 64, -124, t, sway);
    // near arm: on the handlebar, or holding his ears / scratching his head
    const handN = pose === 'sorry' ? [hx - 3, hy + 1] : pose === 'scratch' ? [hx - 4, hy - 12] : grip;
    riderArm(ctx, sh, handN, k, false);
  }

  function sparks(ctx, t) {
    const f = Math.floor(t * 24);
    ctx.save();
    ctx.lineCap = 'round';
    for (let i = 0; i < 4; i++) {
      let px = RK.rearX - 28, py = RK.wheelY - 14 + i * 9;
      ctx.beginPath();
      ctx.moveTo(px, py);
      for (let j = 0; j < 6; j++) {
        px -= 10 + hash(f * 31 + i * 7 + j) * 8;
        py += (hash(f * 17 + i * 5 + j) - 0.5) * 16;
        ctx.lineTo(px, py);
      }
      ctx.strokeStyle = OL;
      ctx.lineWidth = 4;
      ctx.stroke();
      ctx.strokeStyle = i % 2 ? '#7fe7ff' : '#fff27a';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    ctx.strokeStyle = 'rgba(255,255,255,0.7)';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    for (let i = 0; i < 5; i++) {
      const yy = -160 + i * 28 + (hash(f + i) - 0.5) * 8;
      const xx = -150 - hash(f * 3 + i) * 30;
      ctx.moveTo(xx, yy);
      ctx.lineTo(xx - 40 - hash(i + f) * 40, yy);
    }
    ctx.stroke();
    ctx.restore();
  }

  function headBeam(ctx) {
    const g = ctx.createLinearGradient(100, 0, 340, 0);
    g.addColorStop(0, 'rgba(255,244,190,0.6)');
    g.addColorStop(1, 'rgba(255,244,190,0)');
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.moveTo(101, -111);
    ctx.lineTo(340, -150);
    ctx.lineTo(340, -10);
    ctx.lineTo(101, -104);
    ctx.closePath();
    ctx.fill();
  }

  /* Rickshaw, side view. opts:
   *   skin      one of SKINS (default: বাংলা টেসলা)
   *   wheelRot  wheel angle in radians
   *   pedal     true = pedalling; default is pedalling unless the skin has a battery
   *   crank     crank angle when pedalling
   *   pose      'sorry' (holds his ears) | 'scratch' (scratches his head)
   *   talk      flap the mouth
   *   sway      0..1, how hard the tassels and gamchha blow back
   *   boost, lights, bob (px), tilt (rad)
   */
  function drawRickshaw(ctx, x, y, s, t, o = {}) {
    const k = o.skin || SKINS.tesla;
    const rot = o.wheelRot || 0;
    const pedal = o.pedal != null ? o.pedal : !k.battery;
    const crank = pedal ? (o.crank != null ? o.crank : rot * 0.55) : 0.5;
    const sway = o.sway != null ? o.sway : 0.6;
    const RX = RK.rearX, FX = RK.frontX, WY = RK.wheelY, WR = RK.wheelR, BB = RK.bb;

    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 6, 0, 134, 8);
    paint(ctx, 'rgba(0,0,0,0.22)');
    if (o.bob) ctx.translate(0, o.bob);
    if (o.tilt) {
      ctx.translate(RX, 0);
      ctx.rotate(o.tilt);
      ctx.translate(-RX, 0);
    }

    // on battery the rider rests his feet on the pegs ("autopilot")
    const pedN = [BB[0] + Math.cos(crank) * 13, BB[1] + Math.sin(crank) * 13];
    const pedF = [BB[0] - Math.cos(crank) * 13, BB[1] - Math.sin(crank) * 13];
    const footN = pedal ? pedN : [57, -61];
    const footF = pedal ? pedF : [61, -64];

    // far side, drawn first and darker
    wheel(ctx, RX - 6, WY - 4, WR, rot + 0.3, { far: true });
    riderLeg(ctx, RK.hip, footF, k, true);
    ctx.beginPath();
    ctx.moveTo(BB[0], BB[1] - 8);
    ctx.lineTo(RX, WY - 5);
    ctx.moveTo(BB[0], BB[1] + 8);
    ctx.lineTo(RX, WY + 5);
    ctx.strokeStyle = '#3d3a44';
    ctx.lineWidth = 1.6;
    ctx.stroke();
    tube(ctx, [BB[0], BB[1], pedF[0], pedF[1]], '#7d8691', 2.6, null);

    // passenger carriage
    arcBand(ctx, RX, WY, WR + 6, Math.PI * 1.08, Math.PI * 1.92, k.mud, 5);
    if (k.battery) batteryPack(ctx, k, t);
    else if (night.on) lantern(ctx, -22, -47, t);
    rrect(ctx, -127, -106, 9, 58, 3); // painted back board, seen edge-on
    paint(ctx, k.panel, OL, 1.6);
    for (let i = 0; i < 4; i++) {
      circle(ctx, -122.5, -97 + i * 13, 2);
      paint(ctx, k.bands[i]);
    }
    rrect(ctx, -118, -92, 76, 30, 4); // seat box with the name plate
    paint(ctx, k.panel, OL, 1.8);
    rrect(ctx, -114.5, -88.5, 69, 23, 3);
    ctx.strokeStyle = k.trim;
    ctx.lineWidth = 1.4;
    ctx.stroke();
    fitText(ctx, k.name, -80, -76, 62, 15, FONT_DISPLAY, k.ink, OL, 2.6);
    rrect(ctx, -47, -64, 5, 14, 2);
    paint(ctx, k.frame, OL, 1.2);
    rrect(ctx, -46, -53, 52, 6, 2); // passenger footboard
    paint(ctx, k.trim, OL, 1.5);
    rrect(ctx, 2, -61, 5, 14, 2);
    paint(ctx, k.trim, OL, 1.2);
    rrect(ctx, -120, -104, 82, 13, 6); // seat cushion
    paint(ctx, k.seat, OL, 1.8);
    for (let i = 0; i < 5; i++) {
      circle(ctx, -110 + i * 16, -97.5, 1.4);
      paint(ctx, shade(k.seat, -0.4));
    }
    hood(ctx, k, t);

    // frame
    tube(ctx, [6, -50, 92, -91], k.frame, 6);
    tube(ctx, [10, -52, 88, -89], k.trim, 1.2, null);
    tube(ctx, [6, -50, BB[0], BB[1]], k.frame, 5);
    tube(ctx, [BB[0], BB[1], 27, -101], k.frame, 5);
    tube(ctx, [29, -92, 88, -110], k.frame, 4.5);
    tube(ctx, [50, -61, 64, -61], '#cfd6df', 2.6);
    tube(ctx, [93, -88, 88, -115], k.frame, 7);

    // wheels, fork, mudguard, headlight
    wheel(ctx, RX, WY, WR, rot, { beads: k.bands, motor: k.battery });
    wheel(ctx, FX, WY, WR, rot + 1.1, { beads: k.bands });
    tube(ctx, [93, -88, FX, WY], '#cfd6df', 3.6);
    arcBand(ctx, FX, WY, WR + 5, Math.PI * 1.12, Math.PI * 1.86, k.mud, 5);
    if (o.lights && !night.on) headBeam(ctx);
    rrect(ctx, 94, -113, 9, 11, 3);
    paint(ctx, '#cfd6df', OL, 1.2);
    circle(ctx, 101, -107.5, 4.2);
    paint(ctx, o.lights ? '#fffbe0' : '#ffe58a', OL, 1);
    if (night.on && (k.battery || o.lights)) {
      beam(ctx, 104, -107, 320, 75, '#fff2c4', 0.4);
      glow(ctx, 101, -107.5, 18, '#fff2c4', 0.95);
    }
    circle(ctx, BB[0], BB[1], 8.5);
    ctx.strokeStyle = '#9aa3ae';
    ctx.lineWidth = 2.2;
    ctx.stroke();
    tube(ctx, [BB[0], BB[1], pedN[0], pedN[1]], '#c3cbd5', 2.8);
    ctx.beginPath(); // saddle
    ctx.moveTo(10, -102);
    ctx.quadraticCurveTo(11, -111, 26, -110);
    ctx.lineTo(46, -107);
    ctx.lineTo(45, -102);
    ctx.quadraticCurveTo(28, -100, 10, -102);
    ctx.closePath();
    paint(ctx, '#3a2a22', OL, 1.4);

    rider(ctx, k, t, o, footN, sway);
    if (o.boost) {
      sparks(ctx, t);
      emit(ctx, (c) => sparks(c, t));
    }
    ctx.restore();
  }

  // ------------------------------------------------------------------ private car

  const CAR_COLORS = ['#f2f4f7', '#c3cad3', '#2b2f36', '#7a1f2b'];
  let carShell, carGlass;
  function carPaths() {
    if (carShell) return;
    carShell = new Path2D();
    carShell.moveTo(-168, -22);
    carShell.lineTo(-178, -30);
    carShell.lineTo(-179, -52);
    carShell.quadraticCurveTo(-178, -70, -164, -73);
    carShell.lineTo(-120, -78);
    carShell.quadraticCurveTo(-102, -101, -80, -110);
    carShell.quadraticCurveTo(-32, -119, 12, -115);
    carShell.quadraticCurveTo(38, -101, 62, -81);
    carShell.quadraticCurveTo(118, -76, 156, -70);
    carShell.quadraticCurveTo(177, -66, 179, -50);
    carShell.lineTo(179, -31);
    carShell.lineTo(170, -22);
    carShell.arc(112, -27, 34, 0.15, Math.PI - 0.15, true);
    carShell.arc(-108, -27, 34, 0.15, Math.PI - 0.15, true);
    carShell.closePath();
    carGlass = new Path2D();
    carGlass.moveTo(-113, -80);
    carGlass.quadraticCurveTo(-97, -100, -78, -106);
    carGlass.quadraticCurveTo(-32, -114, 9, -110);
    carGlass.quadraticCurveTo(32, -98, 54, -82);
    carGlass.closePath();
  }

  function carWheel(ctx, x, y, r, rot) {
    ctx.save();
    ctx.translate(x, y);
    circle(ctx, 0, 0, r);
    paint(ctx, '#1b1a20', OL, 1.4);
    circle(ctx, 0, 0, r * 0.62);
    paint(ctx, '#c6ced8', OL, 1);
    ctx.rotate(rot);
    ctx.fillStyle = '#6f7983';
    for (let i = 0; i < 5; i++) {
      ctx.rotate(TAU / 5);
      ctx.beginPath();
      ctx.moveTo(-2.4, -4);
      ctx.lineTo(2.4, -4);
      ctx.lineTo(4, -r * 0.55);
      ctx.lineTo(-4, -r * 0.55);
      ctx.closePath();
      ctx.fill();
    }
    circle(ctx, 0, 0, 3.6);
    paint(ctx, '#e5eaf0', OL, 1);
    ctx.restore();
  }

  /* Private car (প্রাইভেট কার), a sedan with a chauffeur and the saheb in the back.
   * opts: color, wheelRot, dent (after a rickshaw hits its rear), hazard (blink), jolt (px). */
  function drawCar(ctx, x, y, s, t, o = {}) {
    carPaths();
    const body = o.color || CAR_COLORS[0];
    const blink = o.hazard && Math.sin(t * 12) > 0;
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, 0, 186, 9);
    paint(ctx, 'rgba(0,0,0,0.25)');
    if (o.jolt) ctx.translate(o.jolt, 0);
    for (const wx of [-108, 112]) {
      ctx.beginPath();
      ctx.arc(wx, -27, 33, Math.PI, 0);
      ctx.closePath();
      paint(ctx, '#141318');
    }
    const g = ctx.createLinearGradient(0, -118, 0, -22);
    g.addColorStop(0, shade(body, 0.35));
    g.addColorStop(0.5, body);
    g.addColorStop(1, shade(body, -0.25));
    ctx.fillStyle = g;
    ctx.fill(carShell);
    // glass, with the chauffeur (cap) and the saheb as silhouettes
    const gg = ctx.createLinearGradient(0, -114, 0, -80);
    gg.addColorStop(0, '#4a6075');
    gg.addColorStop(1, '#1b2530');
    ctx.fillStyle = gg;
    ctx.fill(carGlass);
    ctx.save();
    ctx.clip(carGlass);
    ctx.fillStyle = 'rgba(6,10,16,0.6)';
    circle(ctx, 24, -95, 8);
    ctx.fill();
    rrect(ctx, 13, -88, 22, 14, 6);
    ctx.fill();
    ctx.fillRect(15, -105, 19, 4.5);
    circle(ctx, -50, -96, 9);
    ctx.fill();
    rrect(ctx, -63, -88, 26, 14, 7);
    ctx.fill();
    ctx.fillStyle = 'rgba(255,255,255,0.16)';
    ctx.beginPath();
    ctx.moveTo(-62, -116); ctx.lineTo(-44, -116); ctx.lineTo(-74, -78); ctx.lineTo(-92, -78);
    ctx.closePath();
    ctx.fill();
    ctx.beginPath();
    ctx.moveTo(14, -116); ctx.lineTo(24, -116); ctx.lineTo(2, -78); ctx.lineTo(-8, -78);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
    ctx.lineWidth = 1.6;
    ctx.strokeStyle = OL;
    ctx.stroke(carGlass);
    rrect(ctx, -22, -113, 7, 34, 2);
    paint(ctx, '#161a20');
    // chrome, door seams, handles, crease
    tube(ctx, [-114, -80, 56, -81], '#dfe5ec', 2, null);
    ctx.beginPath();
    ctx.moveTo(-18, -79); ctx.lineTo(-20, -30);
    ctx.moveTo(58, -80); ctx.quadraticCurveTo(64, -60, 62, -34);
    ctx.moveTo(-98, -79); ctx.quadraticCurveTo(-104, -56, -100, -34);
    ctx.strokeStyle = shade(body, -0.35);
    ctx.lineWidth = 1.2;
    ctx.stroke();
    rrect(ctx, -40, -71, 12, 3.5, 1.7);
    paint(ctx, shade(body, -0.3));
    rrect(ctx, 38, -71, 12, 3.5, 1.7);
    paint(ctx, shade(body, -0.3));
    tube(ctx, [-174, -57, 172, -55], 'rgba(255,255,255,0.55)', 1.4, null);
    // lights, bumpers, mirror
    ctx.beginPath();
    ctx.moveTo(160, -69); ctx.quadraticCurveTo(176, -66, 178, -56); ctx.lineTo(166, -57);
    ctx.closePath();
    paint(ctx, '#fff6c4', OL, 1.2);
    rrect(ctx, 169, -54, 8, 5, 2);
    paint(ctx, blink ? '#ffb703' : '#d98e04', OL, 1);
    rrect(ctx, -180, -68, 9, 13, 3);
    paint(ctx, blink ? '#ffb703' : '#e63946', OL, 1.2);
    if (blink) {
      for (const [lx, ly] of [[-176, -61], [173, -51]]) {
        const hg = ctx.createRadialGradient(lx, ly, 1, lx, ly, 22);
        hg.addColorStop(0, 'rgba(255,183,3,0.7)');
        hg.addColorStop(1, 'rgba(255,183,3,0)');
        ctx.fillStyle = hg;
        circle(ctx, lx, ly, 22);
        ctx.fill();
      }
    }
    if (night.on) {
      beam(ctx, 178, -60, 380, 60, '#fff4cf', 0.36);
      glow(ctx, 171, -62, 20, '#fff4cf', 0.95);
      glow(ctx, -176, -61, 24, blink ? '#ffb703' : '#ff3b3b', 0.75);
      if (blink) glow(ctx, 173, -51, 22, '#ffb703', 0.8);
      emit(ctx, (c) => {
        rrect(c, -180, -68, 9, 13, 3);
        c.fillStyle = blink ? '#ffd166' : '#ff6b6b';
        c.fill();
        c.beginPath();
        c.moveTo(160, -69); c.quadraticCurveTo(176, -66, 178, -56); c.lineTo(166, -57);
        c.closePath();
        c.fillStyle = '#fffbe8';
        c.fill();
      });
    }
    rrect(ctx, 166, -40, 15, 11, 4);
    paint(ctx, shade(body, -0.35), OL, 1.2);
    rrect(ctx, -182, -42, 14, 12, 4);
    paint(ctx, shade(body, -0.35), OL, 1.2);
    ctx.beginPath();
    ctx.moveTo(56, -86); ctx.lineTo(68, -88); ctx.lineTo(69, -80); ctx.lineTo(58, -79);
    ctx.closePath();
    paint(ctx, shade(body, -0.1), OL, 1.2);
    if (o.dent) {
      ellipse(ctx, -167, -44, 11, 8);
      paint(ctx, 'rgba(0,0,0,0.16)');
      ctx.beginPath();
      ctx.moveTo(-179, -50); ctx.lineTo(-168, -45); ctx.lineTo(-173, -39); ctx.lineTo(-160, -35);
      ctx.strokeStyle = shade(body, -0.55);
      ctx.lineWidth = 1.4;
      ctx.stroke();
    }
    ctx.lineWidth = 2.4;
    ctx.strokeStyle = OL;
    ctx.stroke(carShell);
    carWheel(ctx, -108, -27, 26, o.wheelRot || 0);
    carWheel(ctx, 112, -27, 26, (o.wheelRot || 0) + 0.7);
    ctx.restore();
  }

  // ------------------------------------------------------------------ bus and CNG

  function discWheel(ctx, x, y, r, rot, rim, studs) {
    ctx.save();
    ctx.translate(x, y);
    circle(ctx, 0, 0, r);
    paint(ctx, '#1b1a20', OL, 1.6);
    circle(ctx, 0, 0, r * 0.56);
    paint(ctx, rim, OL, 1.2);
    ctx.rotate(rot);
    for (let i = 0; i < studs; i++) {
      const a = (i / studs) * TAU;
      circle(ctx, Math.cos(a) * r * 0.34, Math.sin(a) * r * 0.34, r * 0.06 + 0.4);
      paint(ctx, '#3a3f47');
    }
    circle(ctx, 0, 0, r * 0.15);
    paint(ctx, '#d0d6de', OL, 1);
    ctx.restore();
  }

  let busShell;
  function busPath() {
    if (busShell) return busShell;
    busShell = new Path2D();
    busShell.moveTo(-284, -32);
    busShell.lineTo(-287, -214);
    busShell.quadraticCurveTo(-287, -238, -262, -239);
    busShell.lineTo(252, -239);
    busShell.quadraticCurveTo(274, -238, 281, -214);
    busShell.lineTo(293, -112);
    busShell.lineTo(295, -44);
    busShell.quadraticCurveTo(295, -32, 283, -32);
    busShell.arc(186, -32, 40, 0, Math.PI, true);
    busShell.arc(-176, -32, 40, 0, Math.PI, true);
    busShell.closePath();
    return busShell;
  }

  const SKIN_TONES = ['#8a5a3c', '#a26b49', '#6f4329', '#b47a55'];
  const SHIRTS = ['#e63946', '#f1faee', '#a8dadc', '#ffd166', '#90be6d', '#cdb4db', '#f4a261'];

  function busHelper(ctx, t) {
    // the helper hanging out of the door, calling out the route
    tube(ctx, [250, -136, 233, -150, 219, -160], '#7a4a2e', 6);
    tube(ctx, [244, -96, 236, -40], '#3a3f58', 8);
    tube(ctx, [246, -96, 252, -44], '#2e3248', 8);
    ctx.save();
    ctx.translate(244, -96);
    ctx.rotate(0.32 + Math.sin(t * 2) * 0.04);
    rrect(ctx, -9, -48, 19, 50, 7);
    paint(ctx, '#f28482', OL, 1.6);
    circle(ctx, 2, -60, 10);
    paint(ctx, '#7a4a2e', OL, 1.6);
    ctx.beginPath();
    ctx.arc(2, -60, 10.3, Math.PI * 0.9, Math.PI * 1.9);
    ctx.closePath();
    paint(ctx, HAIR);
    circle(ctx, 8, -61, 1.3);
    paint(ctx, OL);
    ellipse(ctx, 10, -54, 2.4, 2.2 + Math.abs(Math.sin(t * 9)) * 1.6);
    paint(ctx, '#5a1a1a');
    const wv = Math.sin(t * 6);
    tube(ctx, [4, -40, 22, -50 + wv * 4, 30 + wv * 3, -70 + wv * 8], '#7a4a2e', 6);
    circle(ctx, 30 + wv * 3, -70 + wv * 8, 4);
    paint(ctx, '#7a4a2e', OL, 1.2);
    ctx.restore();
  }

  /* Local bus (লোকাল বাস): dented, crowded, smoking. opts: color, stripe, stripe2, seed, wheelRot. */
  function drawBus(ctx, x, y, s, t, o = {}) {
    const base = o.color || '#d62839';
    const shell = busPath();
    const r = rng(o.seed || 7);
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, 0, 300, 11);
    paint(ctx, 'rgba(0,0,0,0.28)');
    for (let i = 0; i < 4; i++) {
      const p = (t * 0.7 + i / 4) % 1;
      circle(ctx, -294 - p * 90, -38 - p * 36, 7 + p * 20);
      paint(ctx, 'rgba(48,46,54,' + (0.42 * (1 - p)).toFixed(3) + ')');
    }
    for (const wx of [-176, 186]) {
      ctx.beginPath();
      ctx.arc(wx, -32, 39, Math.PI, 0);
      ctx.closePath();
      paint(ctx, '#121115');
    }
    ctx.fillStyle = base;
    ctx.fill(shell);
    ctx.save();
    ctx.clip(shell);
    ctx.fillStyle = '#f4efe1';
    ctx.fillRect(-300, -245, 600, 30);
    ctx.fillStyle = o.stripe || '#ffb703';
    ctx.fillRect(-300, -112, 600, 10);
    ctx.fillStyle = o.stripe2 || '#1b998b';
    ctx.fillRect(-300, -102, 600, 7);
    ctx.fillStyle = shade(base, -0.32);
    ctx.fillRect(-300, -58, 600, 30);
    const grime = ctx.createLinearGradient(0, -100, 0, -30);
    grime.addColorStop(0, 'rgba(80,58,34,0)');
    grime.addColorStop(1, 'rgba(80,58,34,0.5)');
    ctx.fillStyle = grime;
    ctx.fillRect(-300, -100, 600, 70);
    for (let i = 0; i < 6; i++) {
      // dents
      const dx = -250 + r() * 500, dy = -210 + r() * 160, dr = 16 + r() * 18;
      const dg = ctx.createRadialGradient(dx, dy, 0, dx, dy, dr);
      dg.addColorStop(0, 'rgba(0,0,0,0.3)');
      dg.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = dg;
      ctx.fillRect(dx - dr, dy - dr, dr * 2, dr * 2);
    }
    ctx.beginPath();
    for (let i = 0; i < 16; i++) {
      // scrapes
      const sx = -270 + r() * 520, sy = -128 + r() * 84;
      ctx.moveTo(sx, sy);
      ctx.lineTo(sx + 16 + r() * 44, sy + (r() - 0.5) * 10);
    }
    ctx.strokeStyle = 'rgba(255,255,255,0.5)';
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.restore();

    // windows full of passengers
    for (let i = 0; i < 9; i++) {
      const wx = -262 + i * 52;
      rrect(ctx, wx, -206, 44, 66, 5);
      const wg = ctx.createLinearGradient(0, -206, 0, -140);
      wg.addColorStop(0, '#5f7488');
      wg.addColorStop(1, '#222c37');
      ctx.fillStyle = wg;
      ctx.fill();
      ctx.save();
      ctx.clip();
      const n = r() < 0.8 ? (r() < 0.45 ? 2 : 1) : 0;
      for (let j = 0; j < n; j++) {
        const px = wx + 11 + r() * 22;
        rrect(ctx, px - 11, -154, 22, 20, 7);
        paint(ctx, SHIRTS[Math.floor(r() * SHIRTS.length)]);
        circle(ctx, px, -163, 7.5);
        paint(ctx, SKIN_TONES[Math.floor(r() * SKIN_TONES.length)]);
        ctx.beginPath();
        ctx.ellipse(px, -166, 7.7, 5, 0, Math.PI, TAU);
        paint(ctx, HAIR);
      }
      ctx.restore();
      rrect(ctx, wx, -206, 44, 66, 5);
      paint(ctx, null, OL, 2);
      tube(ctx, [wx + 3, -174, wx + 41, -174], '#c9d1da', 2, null);
    }
    // door, grab rail, helper
    rrect(ctx, 214, -206, 40, 170, 4);
    paint(ctx, '#17191e', OL, 1.8);
    tube(ctx, [219, -200, 219, -44], '#c9d1da', 2.4, null);
    busHelper(ctx, t);
    // windscreen with the "লোকাল" card
    ctx.beginPath();
    ctx.moveTo(262, -232); ctx.lineTo(279, -212); ctx.lineTo(290, -116); ctx.lineTo(262, -116);
    ctx.closePath();
    const ws = ctx.createLinearGradient(0, -232, 0, -116);
    ws.addColorStop(0, '#7f97ab');
    ws.addColorStop(1, '#2b3846');
    paint(ctx, ws, OL, 1.8);
    rrect(ctx, 263, -134, 25, 13, 2);
    paint(ctx, '#ffffff', OL, 1);
    fitText(ctx, 'লোকাল', 275.5, -127.5, 22, 10, FONT_UI, '#d62828', null, 0, '700');
    // route board, company name, sticker
    rrect(ctx, 112, -236, 128, 21, 3);
    paint(ctx, '#111216', OL, 1.4);
    fitText(ctx, 'মিরপুর - গুলিস্তান', 176, -225.5, 118, 13, FONT_UI, '#ff9f1c', null, 0, '700');
    fitText(ctx, o.name || 'ঠেলাঠেলি পরিবহন', -40, -76, 300, 28, FONT_DISPLAY, '#ffffff', OL, 4);
    rrect(ctx, -276, -132, 82, 16, 3);
    paint(ctx, '#ffffff', OL, 1.2);
    fitText(ctx, 'সিটিং সার্ভিস', -235, -124, 74, 11, FONT_UI, '#d62828', null, 0, '700');
    // lights and bumpers
    circle(ctx, 287, -62, 7);
    paint(ctx, '#fff1a8', OL, 1.4);
    rrect(ctx, 266, -46, 32, 12, 4);
    paint(ctx, '#2b2b31', OL, 1.4);
    rrect(ctx, -292, -80, 9, 18, 3);
    paint(ctx, '#e63946', OL, 1.2);
    rrect(ctx, -296, -46, 22, 12, 4);
    paint(ctx, '#2b2b31', OL, 1.4);
    if (night.on) {
      // tube lights inside, the LED route board and the headlights
      emit(ctx, (c) => {
        c.fillStyle = 'rgba(255,224,160,0.42)';
        for (let i = 0; i < 9; i++) {
          rrect(c, -262 + i * 52, -206, 44, 66, 5);
          c.fill();
        }
      }, 'lighter');
      emit(ctx, (c) => {
        c.shadowColor = '#ff9f1c';
        c.shadowBlur = 8;
        fitText(c, 'মিরপুর - গুলিস্তান', 176, -225.5, 118, 13, FONT_UI, '#ffc46b', null, 0, '700');
        c.shadowBlur = 0;
      });
      beam(ctx, 294, -62, 420, 80, '#fff4cf', 0.36);
      glow(ctx, 287, -62, 24, '#fff4cf', 0.95);
      glow(ctx, -288, -71, 24, '#ff3b3b', 0.7);
    }
    ctx.lineWidth = 2.6;
    ctx.strokeStyle = OL;
    ctx.stroke(shell);
    discWheel(ctx, -176, -32, 30, o.wheelRot || 0, '#6c7480', 8);
    discWheel(ctx, 186, -32, 30, (o.wheelRot || 0) + 0.4, '#6c7480', 8);
    ctx.restore();
  }

  let cngShell;
  function cngPath() {
    if (cngShell) return cngShell;
    cngShell = new Path2D();
    cngShell.moveTo(-100, -20);
    cngShell.lineTo(-108, -100);
    cngShell.quadraticCurveTo(-110, -146, -66, -148);
    cngShell.lineTo(52, -148);
    cngShell.quadraticCurveTo(70, -147, 74, -134);
    cngShell.lineTo(90, -86);
    cngShell.quadraticCurveTo(120, -82, 124, -48);
    cngShell.lineTo(122, -20);
    cngShell.arc(92, -20, 24, 0, Math.PI, true);
    cngShell.arc(-62, -20, 24, 0, Math.PI, true);
    cngShell.closePath();
    return cngShell;
  }

  /* CNG auto-rickshaw, with the locked grille door Dhaka CNGs are known for. opts: color, wheelRot. */
  function drawCNG(ctx, x, y, s, t, o = {}) {
    const body = o.color || '#2f9e44';
    const shell = cngPath();
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 6, 0, 124, 7);
    paint(ctx, 'rgba(0,0,0,0.24)');
    for (const wx of [-62, 92]) {
      ctx.beginPath();
      ctx.arc(wx, -20, 23, Math.PI, 0);
      ctx.closePath();
      paint(ctx, '#121115');
    }
    const g = ctx.createLinearGradient(0, -148, 0, -20);
    g.addColorStop(0, shade(body, 0.2));
    g.addColorStop(1, shade(body, -0.25));
    ctx.fillStyle = g;
    ctx.fill(shell);
    ctx.save();
    ctx.clip(shell);
    ctx.fillStyle = shade(body, -0.45);
    ctx.fillRect(-120, -152, 250, 22);
    ctx.fillStyle = 'rgba(255,255,255,0.75)';
    ctx.fillRect(-120, -44, 250, 3);
    ctx.restore();
    // passengers behind the grille
    rrect(ctx, -96, -126, 106, 78, 8);
    paint(ctx, '#132018');
    ctx.save();
    ctx.clip();
    for (const [px, c, sk] of [[-62, '#ffb4a2', '#8a5a3c'], [-26, '#9bc1ff', '#a26b49']]) {
      rrect(ctx, px - 13, -92, 26, 40, 9);
      paint(ctx, c);
      circle(ctx, px, -102, 9);
      paint(ctx, sk);
      ctx.beginPath();
      ctx.ellipse(px, -106, 9.2, 6, 0, Math.PI, TAU);
      paint(ctx, HAIR);
    }
    ctx.restore();
    ctx.beginPath();
    for (let bx = -88; bx <= 4; bx += 9) {
      ctx.moveTo(bx, -124);
      ctx.lineTo(bx, -50);
    }
    ctx.moveTo(-96, -88);
    ctx.lineTo(10, -88);
    ctx.strokeStyle = '#a3abb4';
    ctx.lineWidth = 2;
    ctx.stroke();
    rrect(ctx, -96, -126, 106, 78, 8);
    paint(ctx, null, '#5f6b73', 3.5);
    // driver
    rrect(ctx, 16, -128, 54, 64, 6);
    paint(ctx, '#132018', OL, 1.4);
    ctx.save();
    ctx.clip();
    rrect(ctx, 28, -100, 26, 40, 8);
    paint(ctx, '#e9c46a');
    circle(ctx, 42, -110, 9.5);
    paint(ctx, '#7a4a2e');
    ctx.beginPath();
    ctx.ellipse(41, -114, 9.6, 6, 0, Math.PI, TAU);
    paint(ctx, HAIR);
    tube(ctx, [46, -92, 64, -86], '#7a4a2e', 6, null);
    ctx.restore();
    ctx.beginPath();
    ctx.moveTo(62, -142); ctx.lineTo(74, -134); ctx.lineTo(88, -88); ctx.lineTo(72, -88);
    ctx.closePath();
    paint(ctx, 'rgba(190,225,240,0.55)', OL, 1.4);
    circle(ctx, 116, -64, 6.5);
    paint(ctx, '#fff1a8', OL, 1.2);
    rrect(ctx, -111, -68, 7, 18, 1.5);
    paint(ctx, '#ffffff', OL, 1);
    if (night.on) {
      beam(ctx, 122, -64, 320, 70, '#fff4cf', 0.36);
      glow(ctx, 116, -64, 18, '#fff4cf', 0.95);
      glow(ctx, -108, -40, 16, '#ff3b3b', 0.6);
    }
    ctx.lineWidth = 2.4;
    ctx.strokeStyle = OL;
    ctx.stroke(shell);
    discWheel(ctx, -62, -20, 19, o.wheelRot || 0, '#aeb6c0', 4);
    discWheel(ctx, 92, -20, 19, (o.wheelRot || 0) + 0.5, '#aeb6c0', 4);
    ctx.restore();
  }

  // ------------------------------------------------------------------ people

  const PEOPLE = {
    office: { skin: '#9a6444', top: '#e9f1fb', sleeves: 'long', bottom: 'pants', pants: '#2b3445', tie: '#c1121f', hair: 'side', prop: 'phone' },
    saree: { skin: '#a26b49', top: '#ffd23f', bottom: 'saree', saree: '#d62828', border: '#ffd23f', hair: 'long', prop: 'handbag' },
    lungi: { skin: '#7a4a2e', top: '#7fb3d5', bottom: 'lungi', lungi: ['#2f6f3e', '#163a20'], hair: 'short', prop: 'bazar', mustache: true },
    student: { skin: '#b47a55', top: '#ffffff', bottom: 'pants', pants: '#1d3557', hair: 'short', prop: 'backpack', bag: '#e63946' },
    hawker: { skin: '#6f4329', top: 'vest', bottom: 'lungi', lungi: ['#7b2cbf', '#3c096c'], hair: 'short', prop: 'basket', mustache: true },
  };
  const PEOPLE_NAMES = {
    office: 'অফিসযাত্রী',
    saree: 'শাড়ি পরা আপা',
    lungi: 'বাজারের চাচা',
    student: 'স্কুলছাত্র',
    hawker: 'ফেরিওয়ালা',
  };

  function personLower(ctx, p, sw) {
    const lifts = [[-7, Math.max(0, sw) * 7], [7, Math.max(0, -sw) * 7]];
    if (p.bottom === 'pants') {
      for (const [lx, lift] of lifts) {
        rrect(ctx, lx - 5.5, -77, 11, 73 - lift, 4);
        paint(ctx, p.pants, OL, 1.6);
        ellipse(ctx, lx, -3.5 - lift, 7.5, 4);
        paint(ctx, '#231a16', OL, 1.2);
      }
      return;
    }
    for (const [lx, lift] of lifts) {
      ellipse(ctx, lx, -3.5 - lift, 7, 3.6);
      paint(ctx, p.skin, OL, 1.2);
      tube(ctx, [lx - 5, -5 - lift, lx + 5, -5 - lift], '#6b3f1d', 1.8, null);
    }
    if (p.bottom === 'lungi') {
      const hem = sw * 3;
      ctx.beginPath();
      ctx.moveTo(-15, -79); ctx.lineTo(15, -79); ctx.lineTo(18 + hem, -9); ctx.lineTo(-18 + hem, -9);
      ctx.closePath();
      paint(ctx, check(ctx, p.lungi[0], p.lungi[1], 5), OL, 1.6);
      ctx.beginPath();
      ctx.moveTo(-3, -79);
      ctx.quadraticCurveTo(3, -70, 0, -60);
      ctx.strokeStyle = OL;
      ctx.lineWidth = 1.2;
      ctx.stroke();
      return;
    }
    // saree
    const hem = sw * 2.5;
    ctx.beginPath();
    ctx.moveTo(-15, -81); ctx.lineTo(15, -81); ctx.lineTo(21 + hem, -6); ctx.lineTo(-21 + hem, -6);
    ctx.closePath();
    paint(ctx, p.saree);
    ctx.save();
    ctx.clip();
    ctx.fillStyle = p.border;
    ctx.fillRect(-30, -17, 60, 11);
    ctx.beginPath();
    for (let i = -2; i <= 2; i++) {
      ctx.moveTo(i * 3, -66);
      ctx.lineTo(i * 4.5 + hem, -6);
    }
    ctx.strokeStyle = shade(p.saree, -0.3);
    ctx.lineWidth = 1.2;
    ctx.stroke();
    ctx.restore();
    ctx.beginPath();
    ctx.moveTo(-15, -81); ctx.lineTo(15, -81); ctx.lineTo(21 + hem, -6); ctx.lineTo(-21 + hem, -6);
    ctx.closePath();
    paint(ctx, null, OL, 1.6);
  }

  function personTorso(ctx, p) {
    ctx.beginPath();
    ctx.moveTo(-18, -104);
    ctx.quadraticCurveTo(-18, -110, -11, -110);
    ctx.lineTo(11, -110);
    ctx.quadraticCurveTo(18, -110, 18, -104);
    ctx.lineTo(15, -74);
    ctx.lineTo(-15, -74);
    ctx.closePath();
    paint(ctx, p.top === 'vest' ? '#f4f1ea' : p.top, OL, 1.6);
    if (p.top === 'vest') {
      ctx.beginPath();
      ctx.moveTo(-8, -110);
      ctx.quadraticCurveTo(0, -94, 8, -110);
      ctx.closePath();
      paint(ctx, p.skin, OL, 1.2);
    } else if (p.bottom === 'saree') {
      // the pallu (আঁচল) across the chest and over the shoulder
      ctx.beginPath();
      ctx.moveTo(19, -110); ctx.lineTo(5, -110); ctx.lineTo(-16, -81); ctx.lineTo(-16, -73);
      ctx.lineTo(-4, -73); ctx.lineTo(19, -99);
      ctx.closePath();
      paint(ctx, p.saree, OL, 1.4);
      tube(ctx, [16, -107, -13, -77], p.border, 2.4, null);
    } else {
      ctx.beginPath();
      ctx.moveTo(-6, -110); ctx.lineTo(0, -102); ctx.lineTo(6, -110);
      paint(ctx, null, OL, 1.4);
      if (p.tie) {
        ctx.beginPath();
        ctx.moveTo(-2.5, -103); ctx.lineTo(2.5, -103); ctx.lineTo(4, -84); ctx.lineTo(0, -79); ctx.lineTo(-4, -84);
        ctx.closePath();
        paint(ctx, p.tie, OL, 1.1);
      } else {
        for (let i = 0; i < 3; i++) {
          circle(ctx, 0, -98 + i * 8, 1.1);
          paint(ctx, OL);
        }
      }
      if (p.bottom === 'pants') {
        rrect(ctx, -15, -78, 30, 4.5, 1);
        paint(ctx, '#1b1b1f');
      }
    }
    if (p.prop === 'backpack') {
      rrect(ctx, -13, -110, 5, 30, 2);
      paint(ctx, p.bag, OL, 1);
      rrect(ctx, 8, -110, 5, 30, 2);
      paint(ctx, p.bag, OL, 1);
    }
  }

  function personArms(ctx, p, sw, angry, t) {
    const sleeve = p.top === 'vest' ? null : p.top;
    const arms = [
      { side: -1, sh: [-17, -106], hand: [-22, -67 + sw * 3] },
      { side: 1, sh: [17, -106], hand: [22, -67 - sw * 3] },
    ];
    if (p.prop === 'phone') arms[1].hand = [12, -121]; // phone to the ear, eyes off the road
    if (p.prop === 'basket') arms[1].hand = [17, -142];
    if (angry) arms[1].hand = [25, -140 + Math.sin(t * 28) * 3]; // shaking a fist
    for (const a of arms) {
      const bend = a.hand[1] < a.sh[1] - 4 ? a.side : -a.side;
      const el = joint(a.sh[0], a.sh[1], a.hand[0], a.hand[1], 19, 20, bend);
      tube(ctx, [a.sh[0], a.sh[1], el[0], el[1], a.hand[0], a.hand[1]], p.skin, 7.5);
      if (sleeve) {
        if (p.sleeves === 'long') {
          const wx = el[0] + (a.hand[0] - el[0]) * 0.8, wy = el[1] + (a.hand[1] - el[1]) * 0.8;
          tube(ctx, [a.sh[0], a.sh[1], el[0], el[1], wx, wy], sleeve, 9);
        } else {
          tube(ctx, [a.sh[0], a.sh[1], a.sh[0] + (el[0] - a.sh[0]) * 0.7, a.sh[1] + (el[1] - a.sh[1]) * 0.7], sleeve, 10);
        }
      }
      circle(ctx, a.hand[0], a.hand[1], 4.3);
      paint(ctx, p.skin, OL, 1.2);
    }
    const lh = arms[0].hand, rh = arms[1].hand;
    if (p.prop === 'phone') {
      rrect(ctx, rh[0] + 1, rh[1] - 10, 6, 12, 1.5);
      paint(ctx, '#1c1c22', OL, 1);
      glow(ctx, rh[0] + 4, rh[1] - 4, 18, '#9fdcff', 0.55);
      rrect(ctx, lh[0] - 11, lh[1] + 2, 22, 16, 2); // briefcase
      paint(ctx, '#6b4423', OL, 1.4);
      tube(ctx, [lh[0] - 4, lh[1] + 2, lh[0] - 4, lh[1] - 1, lh[0] + 4, lh[1] - 1, lh[0] + 4, lh[1] + 2], '#3b2614', 1.6, null);
    } else if (p.prop === 'bazar') {
      // jute bazar bag with greens and a fish tail poking out
      for (let i = 0; i < 3; i++) {
        ellipse(ctx, lh[0] - 6 + i * 4, lh[1] + 7, 2.6, 7, -0.5 + i * 0.4);
        paint(ctx, '#3f9b3a', OL, 1);
      }
      ctx.beginPath();
      ctx.moveTo(lh[0] + 5, lh[1] + 9); ctx.lineTo(lh[0] + 13, lh[1] - 1); ctx.lineTo(lh[0] + 16, lh[1] + 5);
      ctx.closePath();
      paint(ctx, '#c9d3dc', OL, 1);
      rrect(ctx, lh[0] - 11, lh[1] + 8, 22, 19, 4);
      paint(ctx, '#a47148', OL, 1.4);
      ctx.beginPath();
      for (let k = 0; k < 3; k++) {
        ctx.moveTo(lh[0] - 9, lh[1] + 13 + k * 5);
        ctx.lineTo(lh[0] + 9, lh[1] + 13 + k * 5);
      }
      ctx.strokeStyle = 'rgba(70,40,20,0.5)';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(lh[0] - 7, lh[1] + 9);
      ctx.quadraticCurveTo(lh[0], lh[1] - 5, lh[0] + 7, lh[1] + 9);
      ctx.strokeStyle = '#6b4423';
      ctx.lineWidth = 1.6;
      ctx.stroke();
    } else if (p.prop === 'handbag') {
      rrect(ctx, lh[0] - 8, lh[1] + 2, 16, 13, 3);
      paint(ctx, '#7b2cbf', OL, 1.3);
    }
  }

  function personHead(ctx, p, angry) {
    const hy = -125;
    rrect(ctx, -4.5, -118, 9, 10, 3);
    paint(ctx, p.skin, OL, 1.2);
    ellipse(ctx, -12, hy + 1, 2.6, 4);
    paint(ctx, p.skin, OL, 1.1);
    ellipse(ctx, 12, hy + 1, 2.6, 4);
    paint(ctx, p.skin, OL, 1.1);
    ellipse(ctx, 0, hy, 12, 13.5);
    paint(ctx, p.skin, OL, 1.8);
    if (angry) {
      ellipse(ctx, 0, hy + 2, 11, 12);
      paint(ctx, 'rgba(230,57,70,0.3)');
    }
    ctx.fillStyle = HAIR;
    ctx.beginPath();
    if (p.hair === 'long') {
      ctx.ellipse(0, hy - 4, 13, 11, 0, Math.PI, TAU);
      ctx.fill();
      tube(ctx, [0, hy - 14.5, 0, hy - 7], p.skin, 1.2, null); // middle parting
    } else if (p.hair === 'side') {
      ctx.ellipse(0, hy - 5, 12.5, 9.5, 0, Math.PI, TAU);
      ctx.fill();
      ctx.beginPath();
      ctx.moveTo(-12, hy - 5);
      ctx.quadraticCurveTo(-3, hy - 13, 12, hy - 6);
      ctx.lineTo(12.5, hy - 3);
      ctx.quadraticCurveTo(0, hy - 9, -12, hy - 5);
      ctx.fill();
    } else {
      ctx.ellipse(0, hy - 5, 12.5, 9, 0, Math.PI, TAU);
      ctx.fill();
    }
    for (const ex of [-4.5, 4.5]) {
      circle(ctx, ex, hy + 1, 1.6);
      paint(ctx, OL);
    }
    ctx.beginPath();
    if (angry) {
      ctx.moveTo(-8, hy - 5); ctx.lineTo(-2, hy - 2);
      ctx.moveTo(8, hy - 5); ctx.lineTo(2, hy - 2);
    } else {
      ctx.moveTo(-7, hy - 3.5); ctx.lineTo(-2.5, hy - 3.5);
      ctx.moveTo(7, hy - 3.5); ctx.lineTo(2.5, hy - 3.5);
    }
    ctx.strokeStyle = HAIR;
    ctx.lineWidth = 1.6;
    ctx.stroke();
    if (p.mustache) {
      ellipse(ctx, 0, hy + 5.5, 5, 1.7);
      paint(ctx, HAIR);
    }
    if (angry) {
      ellipse(ctx, 0, hy + 9, 3.6, 2.8);
      paint(ctx, '#5a1a1a');
    } else {
      ctx.beginPath();
      ctx.arc(0, hy + 6, 3.2, 0.25 * Math.PI, 0.75 * Math.PI);
      ctx.strokeStyle = OL;
      ctx.lineWidth = 1.2;
      ctx.stroke();
    }
  }

  function personBasket(ctx) {
    const by = -142;
    for (const [fx, fy] of [[-16, -6], [-6, -9], [5, -7], [15, -5], [0, -14], [-10, -15], [10, -14]]) {
      circle(ctx, fx, by + fy, 5.5);
      paint(ctx, '#ff9f1c', OL, 1);
    }
    ctx.beginPath();
    ctx.moveTo(-22, by - 12);
    ctx.quadraticCurveTo(-14, by - 22, -4, by - 18);
    ctx.lineTo(-6, by - 14);
    ctx.quadraticCurveTo(-14, by - 17, -20, by - 9);
    ctx.closePath();
    paint(ctx, '#ffd23f', OL, 1);
    ellipse(ctx, 0, by, 30, 7);
    paint(ctx, '#c8963e', OL, 1.6);
    ctx.beginPath();
    for (let i = -24; i <= 24; i += 6) {
      ctx.moveTo(i, by - 5);
      ctx.lineTo(i + 3, by + 5);
    }
    ctx.strokeStyle = '#8a6020';
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  /* Pedestrian, front view (they cross the road towards the camera). opts:
   *   type   'office' | 'saree' | 'lungi' | 'student' | 'hawker'
   *   walk   false to stand still
   *   phase  stride offset
   *   look   overrides for the type's look, e.g. { prop: null }
   *   hit    seconds since the rickshaw hit them, or null:
   *          0–0.7 spin and hop, 0.7–2.6 angry with dizzy stars, then back to normal
   */
  function drawPerson(ctx, x, y, s, t, o = {}) {
    const type = PEOPLE[o.type] || PEOPLE.lungi;
    const p = o.look ? Object.assign({}, type, o.look) : type;
    const hit = o.hit;
    const spinning = hit != null && hit < 0.7;
    const angry = hit != null && hit >= 0.7 && hit < 2.6;
    const walking = o.walk !== false && !spinning && !angry;
    const ph = (o.phase || 0) + t * 8;
    const sw = walking ? Math.sin(ph) : 0;
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, 0, 21, 5);
    paint(ctx, 'rgba(0,0,0,0.22)');
    if (spinning) {
      const k = hit / 0.7;
      ctx.translate(0, -Math.sin(k * Math.PI) * 38 - 70);
      ctx.rotate(k * TAU * (o.spinDir || 1));
      ctx.translate(0, 70);
    } else if (walking) {
      ctx.translate(0, -Math.abs(Math.cos(ph)) * 2);
    }
    if (p.prop === 'backpack') {
      rrect(ctx, -21, -117, 42, 44, 9);
      paint(ctx, shade(p.bag, -0.2), OL, 1.6);
    }
    if (p.hair === 'long') {
      rrect(ctx, -15, -138, 30, 46, 12);
      paint(ctx, HAIR, OL, 1.4);
    }
    if (p.bottom === 'saree') {
      // the end of the pallu hanging down the back
      ctx.beginPath();
      ctx.moveTo(13, -108); ctx.lineTo(22, -106); ctx.lineTo(27, -64); ctx.lineTo(17, -67);
      ctx.closePath();
      paint(ctx, shade(p.saree, -0.15), OL, 1.3);
    }
    personLower(ctx, p, sw);
    personTorso(ctx, p);
    personArms(ctx, p, sw, angry, t);
    personHead(ctx, p, angry);
    if (p.prop === 'basket') personBasket(ctx);
    if (hit != null && hit > 0.3 && hit < 2.6) {
      for (let i = 0; i < 3; i++) {
        const a = t * 6 + (i * TAU) / 3;
        star(ctx, Math.cos(a) * 18, -152 + Math.sin(a) * 5, 5);
        paint(ctx, '#ffd23f', OL, 1.2);
      }
    }
    if (angry) {
      for (const side of [-1, 1]) {
        const k = (t * 1.6 + (side > 0 ? 0.5 : 0)) % 1;
        circle(ctx, side * (17 + k * 8), -134 - k * 16, 3 + k * 4);
        paint(ctx, 'rgba(255,255,255,' + (0.9 * (1 - k)).toFixed(2) + ')', 'rgba(29,20,40,' + (0.6 * (1 - k)).toFixed(2) + ')', 1);
      }
    }
    ctx.restore();
  }

  // ------------------------------------------------------------------ pickups and hazards

  function hover(ctx, x, y, s, t, seed) {
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, 0, 14, 4);
    paint(ctx, 'rgba(0,0,0,0.2)');
    ctx.translate(0, -38 + Math.sin(t * 3 + seed) * 4);
  }

  function drawCoin(ctx, x, y, s, t, o = {}) {
    ctx.save();
    hover(ctx, x, y, s, t, o.seed || 0);
    glow(ctx, 0, 0, 30, '#ffd23f', 0.45);
    ctx.scale(Math.max(0.15, Math.abs(Math.cos(t * 3.2 + (o.seed || 0)))), 1);
    circle(ctx, 0, 0, 15);
    paint(ctx, '#f4b400', OL, 2);
    circle(ctx, 0, 0, 11);
    paint(ctx, null, '#ffe28a', 1.5);
    ctx.font = '700 17px ' + FONT_UI;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#7a4d00';
    ctx.fillText('৳', 0, 1);
    ctx.restore();
  }

  function drawBatteryPickup(ctx, x, y, s, t, o = {}) {
    ctx.save();
    hover(ctx, x, y, s, t, o.seed || 0);
    const g = ctx.createRadialGradient(0, 0, 2, 0, 0, 34);
    g.addColorStop(0, 'rgba(80,255,160,0.55)');
    g.addColorStop(1, 'rgba(80,255,160,0)');
    ctx.fillStyle = g;
    circle(ctx, 0, 0, 34);
    ctx.fill();
    rrect(ctx, -12, -20, 24, 40, 5);
    paint(ctx, '#20242c', OL, 2);
    rrect(ctx, -5.5, -25, 11, 6, 2);
    paint(ctx, '#c9d1da', OL, 1.4);
    for (let i = 0; i < 3; i++) {
      rrect(ctx, -8, 8 - i * 10, 16, 7, 2);
      paint(ctx, '#39ff88');
    }
    bolt(ctx, 0, 0, 24, '#ffd23f', OL);
    glow(ctx, 0, 0, 42, '#50ffa0', 0.5);
    ctx.restore();
  }

  function drawBoostPickup(ctx, x, y, s, t, o = {}) {
    ctx.save();
    hover(ctx, x, y, s, t, o.seed || 0);
    const g = ctx.createRadialGradient(0, 0, 4, 0, 0, 38);
    g.addColorStop(0, 'rgba(76,195,255,0.6)');
    g.addColorStop(1, 'rgba(76,195,255,0)');
    ctx.fillStyle = g;
    circle(ctx, 0, 0, 38);
    ctx.fill();
    circle(ctx, 0, 0, 19);
    paint(ctx, '#1d2f6f', '#4cc3ff', 3);
    bolt(ctx, 0, 0, 28, '#4cc3ff', OL);
    for (let i = 0; i < 4; i++) {
      const a = t * 2 + (i * TAU) / 4;
      star(ctx, Math.cos(a) * 27, Math.sin(a) * 27, 4, 4, 0.4);
      paint(ctx, '#ffffff', OL, 0.8);
    }
    glow(ctx, 0, 0, 46, '#4cc3ff', 0.55);
    ctx.restore();
  }

  function drawTea(ctx, x, y, s, t, o = {}) {
    ctx.save();
    hover(ctx, x, y, s, t, o.seed || 0);
    ctx.lineCap = 'round';
    ctx.lineWidth = 2;
    for (let i = 0; i < 2; i++) {
      const k = (t * 0.8 + i * 0.5) % 1;
      ctx.strokeStyle = 'rgba(120,110,130,' + (0.7 * (1 - k)).toFixed(2) + ')';
      ctx.beginPath();
      ctx.moveTo(-4 + i * 8, -18 - k * 10);
      ctx.bezierCurveTo(-10 + i * 8, -24 - k * 10, 2 + i * 8, -28 - k * 10, -4 + i * 8, -34 - k * 10);
      ctx.stroke();
    }
    ellipse(ctx, 0, 15, 17, 4);
    paint(ctx, '#f4f1ea', OL, 1.4);
    const glass = () => {
      ctx.beginPath();
      ctx.moveTo(-11, -15); ctx.lineTo(11, -15); ctx.lineTo(8, 13); ctx.lineTo(-8, 13);
      ctx.closePath();
    };
    glass();
    paint(ctx, 'rgba(255,255,255,0.5)');
    ctx.beginPath();
    ctx.moveTo(-10, -7); ctx.lineTo(10, -7); ctx.lineTo(8, 13); ctx.lineTo(-8, 13);
    ctx.closePath();
    paint(ctx, '#b0703a');
    glass();
    paint(ctx, null, OL, 1.8);
    glow(ctx, 0, 0, 30, '#ffb347', 0.35);
    ctx.restore();
  }

  function drawPothole(ctx, x, y, s) {
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, -4, 48, 13);
    paint(ctx, '#3a3631');
    ellipse(ctx, 0, -3, 40, 10);
    paint(ctx, '#6a5438');
    ellipse(ctx, -10, -6, 15, 2.6);
    paint(ctx, 'rgba(255,255,255,0.28)');
    ctx.beginPath();
    ctx.moveTo(44, -6); ctx.lineTo(60, -10); ctx.lineTo(70, -6);
    ctx.moveTo(-46, -2); ctx.lineTo(-62, 2);
    ctx.strokeStyle = 'rgba(20,20,24,0.6)';
    ctx.lineWidth = 1.4;
    ctx.stroke();
    ctx.restore();
  }

  function drawPuddle(ctx, x, y, s, t) {
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ellipse(ctx, 0, -4, 96, 17);
    paint(ctx, 'rgba(92,110,128,0.85)', 'rgba(60,70,80,0.6)', 2);
    for (let i = 0; i < 3; i++) {
      const k = (t * 0.6 + i / 3) % 1;
      ellipse(ctx, -20 + i * 22, -4, 10 + k * 34, 2 + k * 7);
      paint(ctx, null, 'rgba(230,240,250,' + (0.55 * (1 - k)).toFixed(2) + ')', 1.2);
    }
    ellipse(ctx, 30, -8, 26, 2.5);
    paint(ctx, 'rgba(255,255,255,0.3)');
    ctx.restore();
  }

  function drawBarricade(ctx, x, y, s, t = 0) {
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    // warning blinker on the sign
    tube(ctx, [0, -114, 0, -122], '#6c737b', 2.5);
    circle(ctx, 0, -126, 5);
    paint(ctx, '#c1121f', OL, 1.2);
    if (Math.sin(t * 7) > 0) {
      glow(ctx, 0, -126, 34, '#ff3b3b', 0.9);
      emit(ctx, (c) => {
        circle(c, 0, -126, 4);
        c.fillStyle = '#ff8a8a';
        c.fill();
      });
    }
    ellipse(ctx, 10, 0, 80, 6);
    paint(ctx, 'rgba(0,0,0,0.2)');
    tube(ctx, [-50, 0, -44, -46], '#6c737b', 4);
    tube(ctx, [50, 0, 44, -46], '#6c737b', 4);
    rrect(ctx, -60, -62, 120, 22, 3);
    ctx.save();
    ctx.clip();
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(-60, -62, 120, 22);
    ctx.fillStyle = '#e63946';
    for (let i = -4; i < 9; i++) {
      ctx.beginPath();
      ctx.moveTo(i * 18, -62); ctx.lineTo(i * 18 + 9, -62); ctx.lineTo(i * 18 - 13, -40); ctx.lineTo(i * 18 - 22, -40);
      ctx.closePath();
      ctx.fill();
    }
    ctx.restore();
    rrect(ctx, -60, -62, 120, 22, 3);
    paint(ctx, null, OL, 2);
    tube(ctx, [0, -68, 0, -62], '#6c737b', 3);
    rrect(ctx, -46, -114, 92, 46, 4);
    paint(ctx, '#ffd23f', OL, 2);
    fitText(ctx, 'সাবধান!', 0, -101, 78, 16, FONT_UI, '#d62828', null, 0, '700');
    fitText(ctx, 'কাজ চলিতেছে', 0, -81, 82, 14, FONT_UI, OL, null, 0, '700');
    // traffic cone
    ctx.beginPath();
    ctx.moveTo(70, -2); ctx.lineTo(80, -40); ctx.lineTo(86, -40); ctx.lineTo(96, -2);
    ctx.closePath();
    paint(ctx, '#ff7a00', OL, 1.6);
    rrect(ctx, 73, -26, 20, 6, 1);
    paint(ctx, '#ffffff');
    rrect(ctx, 64, -4, 38, 5, 2);
    paint(ctx, '#ff7a00', OL, 1.4);
    ctx.restore();
  }

  // ------------------------------------------------------------------ effects

  /* Comic speech bubble whose tail points at (x, y). opts: size, pop (0..1 pop-in), side (1 right, -1 left). */
  function drawBubble(ctx, x, y, text, o = {}) {
    const size = o.size || 22;
    const lines = String(text).split('\n');
    ctx.save();
    ctx.font = '700 ' + size + 'px ' + FONT_UI;
    let w = 0;
    for (const l of lines) w = Math.max(w, ctx.measureText(l).width);
    w += 36;
    const lh = size * 1.35, h = lines.length * lh + 18;
    const pop = o.pop == null ? 1 : Math.max(0, Math.min(1, o.pop));
    const sc = 0.4 + 0.6 * easeOutBack(pop);
    const side = o.side || 1;
    const bx = side > 0 ? x - 34 : x - w + 34, by = y - 24 - h;
    ctx.translate(x, y);
    ctx.scale(sc, sc);
    ctx.translate(-x, -y);
    const tail = () => {
      ctx.beginPath();
      ctx.moveTo(x + side * 6, by + h - 3);
      ctx.lineTo(x + side * 30, by + h - 3);
      ctx.lineTo(x, y);
      ctx.closePath();
    };
    ctx.save();
    ctx.translate(4, 5);
    ctx.fillStyle = 'rgba(0,0,0,0.25)';
    rrect(ctx, bx, by, w, h, 18);
    ctx.fill();
    tail();
    ctx.fill();
    ctx.restore();
    ctx.lineJoin = 'round';
    ctx.strokeStyle = OL;
    ctx.lineWidth = 6;
    rrect(ctx, bx, by, w, h, 18);
    ctx.stroke();
    tail();
    ctx.stroke();
    ctx.fillStyle = o.fill || '#fffdf3';
    rrect(ctx, bx, by, w, h, 18);
    ctx.fill();
    tail();
    ctx.fill();
    ctx.fillStyle = o.ink || OL;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    lines.forEach((l, i) => ctx.fillText(l, bx + w / 2, by + 9 + lh * (i + 0.5)));
    ctx.restore();
  }

  /* Comic impact burst ("ধুম!", "ধপাস!"). */
  function drawBurst(ctx, x, y, text, s, o = {}) {
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(s, s);
    ctx.rotate(o.rot != null ? o.rot : -0.1);
    ctx.beginPath();
    for (let i = 0; i < 22; i++) {
      const a = (i / 22) * TAU;
      const r = i % 2 ? 30 : 50 + (hash(i * 13 + (o.seed || 0)) - 0.5) * 16;
      ctx.lineTo(Math.cos(a) * r * 1.3, Math.sin(a) * r);
    }
    ctx.closePath();
    paint(ctx, o.fill || '#ffd23f', o.ring || '#e63946', 4);
    ctx.font = '40px ' + FONT_DISPLAY;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.lineJoin = 'round';
    ctx.lineWidth = 6;
    ctx.strokeStyle = '#ffffff';
    ctx.strokeText(text, 0, 3);
    ctx.fillStyle = o.ink || '#d62828';
    ctx.fillText(text, 0, 3);
    ctx.restore();
  }

  function drawFloatText(ctx, x, y, text, color, alpha) {
    ctx.save();
    ctx.globalAlpha = Math.max(0, Math.min(1, alpha));
    ctx.font = '700 28px ' + FONT_UI;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.lineJoin = 'round';
    ctx.lineWidth = 6;
    ctx.strokeStyle = OL;
    ctx.strokeText(text, x, y);
    ctx.fillStyle = color;
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  BT.art = {
    TAU, OL, FONT_DISPLAY, FONT_UI,
    rrect, paint, circle, ellipse, tube, shade, hash, rng, bn, check, fitText, star, flower, bolt, easeOutBack, rgba,
    beginNight, isNight, layer, emit, glow, beam,
    SKINS, CAR_COLORS, PEOPLE_NAMES,
    PEOPLE_TYPES: Object.keys(PEOPLE),
    drawRickshaw, drawCar, drawBus, drawCNG, drawPerson,
    drawCoin, drawBatteryPickup, drawBoostPickup, drawTea,
    drawPothole, drawPuddle, drawBarricade,
    drawBubble, drawBurst, drawFloatText,
  };
})();
