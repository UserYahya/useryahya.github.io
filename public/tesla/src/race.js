/* বাংলা টেসলা — the race engine. A Race runs one race (or the endless জ্যাম মোড, or the
 * self-driving demo behind the menus): the hero, rivals, traffic, people, pickups,
 * collisions, effects and the HUD. update(dt, input) advances it; render(ctx, scale) draws it. */
(function () {
  'use strict';

  const A = window.BT.art;
  const S = window.BT.scenery;
  const { bn } = A;
  const LANES = S.LANES;

  const HERO_X = 300; // hero's usual screen x
  const PX_PER_KM = 12000;
  const CRUISE = 420; // px/s on battery, shown as 28 km/h
  const TOP = 560; // holding the throttle
  const BOOST = 800;
  const PEDAL_CRUISE = 250, PEDAL_TOP = 300; // flat battery: the rider pedals
  const KMH = 28 / CRUISE;

  const pick = (a) => a[Math.floor(Math.random() * a.length)];
  const rand = (a, b) => a + Math.random() * (b - a);
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const ease = (p) => (p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2);

  const KIND = {
    car: { half: 182, solid: true, wheel: 26 },
    bus: { half: 296, solid: true, wheel: 30 },
    cng: { half: 124, solid: true, wheel: 19 },
    rival: { half: 132, solid: true, wheel: 31 },
    barricade: { half: 62, solid: true },
    person: { half: 16 },
    coin: { half: 16, pickup: true },
    battery: { half: 16, pickup: true },
    boost: { half: 20, pickup: true },
    tea: { half: 16, pickup: true },
    pothole: { half: 46, decal: true },
    puddle: { half: 66, decal: true },
  };

  const FINES = { car: 200, bus: 100, cng: 50, person: 50 };
  const BONUS = [400, 250, 120, 40];
  const ORDINAL = ['১ম', '২য়', '৩য়', '৪র্থ'];
  const BUS_COLORS = ['#d62839', '#1d4e89', '#2a9d4b', '#e09f00'];

  const ROUTES = [
    {
      id: 'farmgate', from: 'ফার্মগেট', to: 'কারওয়ান বাজার', km: 2.5, rival: 0.9, density: 0.85,
      about: 'সহজ রাস্তা, হালকা ভিড়। হাত গরম করার রুট।',
      mix: { car: 3, bus: 1, cng: 1, person: 1.3, pothole: 1, barricade: 0.3, coin: 3, battery: 1, boost: 0.4, tea: 0.4 },
    },
    {
      id: 'dhanmondi', from: 'ধানমন্ডি ২৭', to: 'নিউ মার্কেট', km: 3, rival: 0.97, density: 1,
      about: 'ছাত্রছাত্রী আর ক্রেতাদের ভিড়। ঘণ্টি কাজে লাগান।',
      mix: { car: 2.5, bus: 1, cng: 1.2, person: 3.2, pothole: 1, barricade: 0.4, coin: 3, battery: 1, boost: 0.5, tea: 0.6 },
    },
    {
      id: 'gulshan', from: 'গুলশান ২', to: 'বনানী', km: 3.4, rival: 1, density: 1.1,
      about: 'প্রাইভেট কারের রাজত্ব। ক্ষমা চাইতে চাইতে মুখ ব্যথা!',
      mix: { car: 6.5, bus: 0.5, cng: 1, person: 1, pothole: 0.6, barricade: 0.5, coin: 3, battery: 1, boost: 0.6, tea: 0.8 },
    },
    {
      id: 'puran', from: 'সদরঘাট', to: 'চকবাজার', km: 3.6, rival: 1.03, density: 1.15,
      about: 'পুরান ঢাকার রাস্তা: গর্ত, ব্যারিকেড আর ফেরিওয়ালা।',
      mix: { car: 2, bus: 1, cng: 2, person: 3, pothole: 3, barricade: 1.1, coin: 3.5, battery: 1, boost: 0.6, tea: 0.6 },
    },
    {
      id: 'motijheel', from: 'মতিঝিল', to: 'কমলাপুর', km: 4, rival: 1.1, density: 1.15, night: true, rain: true,
      about: 'বর্ষার রাত: বৃষ্টি আর জলাবদ্ধতা পেরিয়ে শেষ ট্রেন ধরতে হবে।',
      mix: { car: 3, bus: 1.2, cng: 1.5, person: 1.4, pothole: 1, puddle: 3.2, barricade: 0.6, coin: 3, battery: 1.2, boost: 0.7, tea: 0.7 },
    },
  ];
  const ENDLESS = {
    id: 'endless', from: 'জ্যাম মোড', to: '', km: Infinity, density: 0.9, endless: true,
    mix: { car: 3.5, bus: 1, cng: 1.5, person: 2, pothole: 1.2, barricade: 0.6, coin: 3, battery: 1.3, boost: 0.6, tea: 0.8 },
  };
  const DEMO = {
    id: 'demo', from: '', to: '', km: Infinity, rival: 1, density: 0.7,
    mix: { car: 3, bus: 0.8, cng: 1, coin: 2.5, battery: 0.8, pothole: 0.6 },
  };

  function weighted(mix) {
    let total = 0;
    for (const k in mix) total += mix[k];
    let r = Math.random() * total;
    for (const k in mix) if ((r -= mix[k]) <= 0) return k;
    return 'coin';
  }

  // HUD layout for a screen W logical px wide at HUD scale s: battery on the left, position,
  // taka and time on the right, the pause button in the top-right corner, progress in between.
  function hudLayout(W, s) {
    const top = 14, h = 76 * s, side = 300 * s, btn = 52 * s;
    const left = { x: 16, w: side };
    const pause = { x: W - 16 - btn, y: top + (h - btn) / 2, size: btn };
    const right = { x: pause.x - 12 - side, w: side };
    const center = { x: left.x + side + 12, w: right.x - 12 - (left.x + side + 12) };
    return { top, h, s, left, right, center, pause };
  }

  function fmtTime(s) {
    const m = Math.floor(s / 60), sec = Math.floor(s % 60);
    return bn(String(m).padStart(2, '0') + ':' + String(sec).padStart(2, '0'));
  }

  class Race {
    /* opts: route, demo, night, audio (BT.audio), sound, upgrades {battery, motor, bell},
     *       skin, touch (show touch hints), onEvent(type, data) — 'finish' and 'over' */
    constructor(opts) {
      this.route = opts.route || DEMO;
      this.demo = !!opts.demo;
      this.touch = !!opts.touch;
      this.hudScale = 1;
      this.night = opts.night != null ? !!opts.night : !!this.route.night;
      this.audio = opts.audio || null;
      this.sound = opts.sound != null ? !!opts.sound : !this.demo;
      this.up = Object.assign({ battery: 0, motor: 0, bell: 0 }, opts.upgrades);
      this.skin = opts.skin || A.SKINS.tesla;
      this.onEvent = opts.onEvent || (() => {});
      this.len = this.route.km * PX_PER_KM;
      this.t = 0;
      this.time = 0;
      this.phase = this.demo ? 'race' : 'countdown';
      this.countT = 3.6;
      this.lastBeep = 4;
      this.hero = {
        kind: 'hero', x: 0, lane: 1, prevLane: 1, y: LANES[1], from: LANES[1], laneT: 1,
        speed: this.demo ? CRUISE : 0, rot: 0, crank: 0, battery: 100,
        boostT: 0, boostCd: 0, bellCd: 0, bell: 0, stun: 0, invuln: 0, bump: 0, puddle: 0,
        pose: null, poseT: 0, bubble: null, tea: false, flatWarned: false,
      };
      this.screenX = HERO_X;
      this.objs = [];
      this.fx = [];
      this.parts = [];
      this.shake = 0;
      this.coins = 0;
      this.fines = 0;
      this.hits = { car: 0, person: 0, other: 0 };
      this.forgive = 3;
      this.nextSpawn = 900;
      this.rivals = [];
      this.cap = Infinity;
      this.gagIn = 3;
      this.gag = 0;
      this.carBellHint = false;
      if (!this.route.endless) this.addRivals();
    }

    // ---------------------------------------------------------------- helpers

    camX() {
      return this.hero.x - this.screenX;
    }

    sfx(name, volume, rate) {
      if (this.sound && this.audio) this.audio.play(name, { volume, rate });
    }

    voice(name) {
      if (this.sound && this.audio) this.audio.voice(name);
    }

    add(o) {
      o.y = o.y != null ? o.y : LANES[o.lane];
      o.s = S.scaleAt(o.kind === 'person' ? o.y : LANES[o.lane]);
      o.vx = o.vx || 0;
      o.cruise = o.vx;
      o.rot = 0;
      o.laneT = 1;
      this.objs.push(o);
      return o;
    }

    float(text, x, y, color, opts = {}) {
      this.fx.push({ kind: 'text', x, y, text, color, t: 0, life: opts.life || 1.3 });
    }

    // A message pinned to the HUD: 'taka' floats under the money, 'center' under the progress bar.
    hudMsg(text, color, at, life) {
      this.fx.push({ kind: 'hud', at, text, color, t: 0, life: life || 1.3 });
    }

    burst(text, x, y) {
      this.fx.push({ kind: 'burst', x, y, text, t: 0, life: 0.7, seed: Math.floor(Math.random() * 99) });
    }

    // Is anything solid (or a pothole/puddle) in `lane` overlapping world span [x0, x1]?
    blocked(lane, x0, x1, except, decals = true, rivals = true) {
      for (const o of this.objs) {
        if (o === except || o.gone || o.lane !== lane || (!rivals && o.kind === 'rival')) continue;
        const k = KIND[o.kind];
        if (!(k.solid || (decals && k.decal))) continue;
        if (o.x + k.half * o.s > x0 && o.x - k.half * o.s < x1) return true;
      }
      return false;
    }

    // Would a solid in `lane` at x close off all three lanes?
    wall(lane, x) {
      return [0, 1, 2].filter((q) => q !== lane).every((q) => this.blocked(q, x - 700, x + 700, null, false));
    }

    // Nearest solid ahead of o in its lane (the hero counts too): { gap, vx, hero }.
    leader(o) {
      const k = KIND[o.kind];
      const front = o.x + k.half * o.s;
      let best = null;
      for (const q of this.objs) {
        if (q === o || q.gone || !KIND[q.kind].solid || q.lane !== o.lane || q.x <= o.x) continue;
        const gap = q.x - KIND[q.kind].half * q.s - front;
        if (!best || gap < best.gap) best = { gap, vx: q.vx };
      }
      const h = this.hero;
      if (Math.abs(h.y - o.y) < 40 && h.x > o.x) {
        const gap = h.x - 128 * S.scaleAt(h.y) - front;
        if (!best || gap < best.gap) best = { gap, vx: h.speed, hero: true };
      }
      return best;
    }

    laneTo(o, l) {
      o.from = o.y;
      o.lane = l;
      o.laneT = 0;
    }

    // ---------------------------------------------------------------- setup and spawning

    addRivals() {
      const grid = [
        { skin: A.SKINS.peacock, lane: 0, x: 0, pace: 0.99 },
        { skin: A.SKINS.redfairy, lane: 2, x: 0, pace: 1.03 },
        { skin: A.SKINS.golden, lane: 1, x: -330, pace: 1.01 },
      ];
      grid.forEach((g, i) => {
        const r = this.add({ kind: 'rival', lane: g.lane, x: g.x, skin: g.skin, pace: g.pace, vx: this.demo ? CRUISE : 0 });
        // in the demo each rival keeps its own distance from the hero, so they spread across the screen
        Object.assign(r, { surge: rand(3, 7), surgeT: 0, delay: 0, finished: false, finishTime: 0, demoGap: [560, -460, 1000][i] });
        this.rivals.push(r);
      });
    }

    density() {
      if (this.route.endless) return this.route.density * (1 + Math.min(1.2, this.hero.x / 90000));
      return this.route.density;
    }

    spawnTick() {
      const horizon = this.camX() + S.W + 520;
      const stop = this.len + 1200;
      while (this.nextSpawn < horizon && this.nextSpawn < stop) {
        this.spawnOne(this.nextSpawn);
        this.nextSpawn += rand(180, 340) / this.density();
      }
    }

    spawnOne(x) {
      const h = this.hero;
      const kind = weighted(this.route.mix);
      // during a staged demo moment, keep the hero's lane clear
      const lanes = [0, 1, 2].filter((l) => !(h.lock > 0 && l === h.lane));
      const lane = pick(lanes);
      const others = lanes.filter((l) => l !== h.lane);
      switch (kind) {
        case 'car':
          if (!this.blocked(lane, x - 560, x + 560) && !this.wall(lane, x)) {
            this.add({ kind: 'car', lane, x, vx: rand(170, 260), color: Math.random() < 0.6 ? A.CAR_COLORS[0] : pick(A.CAR_COLORS), honkCd: rand(1, 3) });
          }
          break;
        case 'bus':
          if (lanes.includes(0) && !this.blocked(0, x - 700, x + 1000) && !this.wall(0, x + 300)) {
            this.add({ kind: 'bus', lane: 0, x: x + 300, vx: rand(125, 150), color: pick(BUS_COLORS), seed: Math.floor(rand(1, 999)), stopIn: rand(4, 9), stopT: 0, honkCd: rand(1, 3) });
          }
          break;
        case 'cng': {
          // CNGs come from behind and overtake
          const l = pick(others);
          const bx = this.camX() - 380;
          if (l != null && !this.blocked(l, bx - 400, bx + 900, null, false)) this.add({ kind: 'cng', lane: l, x: bx, vx: rand(620, 700), honkCd: rand(1, 3) });
          break;
        }
        case 'person': {
          const top = Math.random() < 0.6;
          this.add({ kind: 'person', type: pick(A.PEOPLE_TYPES), x, y: top ? S.FOOT_TOP + 34 : S.H + 40, vy: (top ? 1 : -1) * rand(50, 85), phase: rand(0, 6) });
          break;
        }
        case 'pothole':
        case 'puddle':
          if (!this.blocked(lane, x - 260, x + 260)) this.add({ kind, lane, x });
          break;
        case 'barricade':
          if (!this.blocked(lane, x - 500, x + 500) && !this.wall(lane, x)) this.add({ kind: 'barricade', lane, x });
          break;
        case 'coin':
          for (let i = 0, n = 3 + Math.floor(rand(0, 3)); i < n; i++) this.add({ kind: 'coin', lane, x: x + i * 70, seed: i });
          break;
        default: // battery, boost, tea
          this.add({ kind, lane, x, seed: rand(0, 6) });
      }
    }

    // ---------------------------------------------------------------- hero actions

    heroLane(l, bounce) {
      const h = this.hero;
      if (l < 0 || l > 2 || l === h.lane) return;
      h.prevLane = bounce ? l : h.lane;
      h.from = h.y;
      h.lane = l;
      h.laneT = 0;
    }

    ringBell() {
      const h = this.hero;
      const range = 520 * (1 + 0.3 * this.up.bell);
      h.bellCd = 1.2 * (1 - 0.2 * this.up.bell);
      h.bell = 1;
      this.sfx('bell', 0.9);
      const front = h.x + 120;
      for (const o of this.objs) {
        if (o.kind === 'person' && o.hit == null && !o.hurry && o.x > front - 60 && o.x - front < range) {
          o.hurry = true;
          o.vy = Math.sign(o.vy || 1) * 290; // they hurry out of the way
        }
      }
      if (!this.carBellHint && !this.demo) {
        const car = this.objs.find((o) => o.kind === 'car' && o.lane === h.lane && o.x > h.x && o.x - h.x < range + 200);
        if (car) {
          this.carBellHint = true;
          this.hudMsg('প্রাইভেট কার ঘণ্টি শোনে না!', '#ffd23f', 'center', 2);
        }
      }
    }

    startBoost(free) {
      const h = this.hero;
      if (!free) {
        if (h.battery < 15) {
          h.boostCd = 0.6;
          this.hudMsg('বুস্টের চার্জ নেই', '#ff6b6b', 'center');
          return;
        }
        h.battery -= 15;
      }
      h.boostT = 2;
      h.boostCd = 2.6;
      this.sfx('boost', 0.9);
      this.float('লুডিক্রাস মোড!', h.x + 60, h.y - 240, '#4cc3ff');
    }

    fine(amount) {
      const h = this.hero;
      if (h.tea) {
        h.tea = false;
        this.hudMsg('চা খেয়ে মাথা ঠান্ডা, জরিমানা মাফ!', '#ffd23f', 'center', 2);
        return;
      }
      this.fines += amount;
      this.hudMsg('−৳' + bn(amount), '#ff6b6b', 'taka', 1.8);
    }

    // ---------------------------------------------------------------- collisions

    collide() {
      const h = this.hero;
      if (this.phase !== 'race' && this.phase !== 'finished') return;
      const hs = S.scaleAt(h.y);
      const back = h.x - 128 * hs, front = h.x + 136 * hs;
      for (const o of this.objs) {
        if (o.gone) continue;
        const k = KIND[o.kind];
        const person = o.kind === 'person';
        if (Math.abs(o.y - h.y) > (person ? 16 : 30)) continue;
        const s = person ? S.scaleAt(o.y) : o.s;
        const ob = o.x - k.half * s, of = o.x + k.half * s;
        if (of < back || ob > front) continue;
        if (k.pickup) {
          this.collect(o);
        } else if (o.kind === 'pothole') {
          if (!o.done) {
            o.done = true;
            h.speed *= 0.65;
            h.bump = 0.45;
            this.shake = Math.max(this.shake, 0.2);
            this.sfx('pothole', 0.8);
          }
        } else if (o.kind === 'puddle') {
          h.puddle = 0.25;
          if (!o.done) {
            o.done = true;
            this.sfx('splash', 0.8);
            for (let i = 0; i < 18; i++) this.parts.push({ x: h.x + rand(-90, 120), y: h.y - rand(0, 10), vx: rand(-160, 160), vy: -rand(120, 320), t: 0, life: rand(0.4, 0.8), r: rand(2, 4.5), c: '#bcd3ea' });
          }
        } else if (k.solid) {
          if (o.struck || h.invuln > 0 || this.phase !== 'race') this.stuckBehind(o, ob, hs);
          else this.hitSolid(o, ob, hs);
        } else if (person && o.hit == null && h.invuln <= 0 && this.phase === 'race') {
          this.hitPerson(o);
        }
      }
    }

    // Something you already bumped just blocks the lane: you stay behind it until you change lanes.
    stuckBehind(o, ob, hs) {
      const h = this.hero;
      if (h.x >= o.x || h.laneT < 1) return;
      h.x = Math.min(h.x, ob - 136 * hs - 1);
      h.speed = Math.min(h.speed, Math.max(0, o.vx));
    }

    hitSolid(o, ob, hs) {
      const h = this.hero;
      if (h.laneT < 1 && h.x > ob) {
        this.heroLane(h.prevLane, true); // swerved into its side: bounce back
      } else if (h.x < o.x) {
        h.x = Math.min(h.x, ob - 136 * hs - 2); // rear-ended it
      }
      o.struck = true;
      h.invuln = 1.1;
      h.lock = 0; // a staged demo moment has played out
      this.shake = 0.4;
      this.burst(o.kind === 'rival' ? 'ঠুস!' : 'ধুম!', Math.max(ob, h.x + 100 * hs), h.y - 120 * hs);
      this.sfx('crash', 0.9);
      switch (o.kind) {
        case 'car':
          h.speed = 0;
          h.stun = 0.6;
          o.dent = true;
          o.hazard = 5;
          o.jolt = 1;
          this.hits.car++;
          this.sfx('horn-car', 0.8);
          this.fine(FINES.car);
          h.pose = 'sorry';
          h.poseT = 2.4;
          h.bubble = { text: 'আমার ভুল হয়েছে,\nক্ষমা করে দেন!', t: 0, life: 2.4 };
          this.voice('sorry');
          if (this.route.endless) {
            this.forgive--;
            if (this.forgive < 0) this.gameOver();
            else this.hudMsg('ক্ষমা বাকি: ' + bn(this.forgive), '#ffd23f', 'center', 1.6);
          }
          break;
        case 'bus':
          h.speed = 0;
          h.stun = 0.6;
          this.hits.other++;
          this.sfx('horn-bus', 0.8);
          this.fine(FINES.bus);
          break;
        case 'cng':
          h.speed *= 0.3;
          this.hits.other++;
          this.sfx('horn-car', 0.6, 1.25);
          this.fine(FINES.cng);
          break;
        case 'rival':
          h.speed *= 0.5;
          o.vx *= 0.6;
          this.hits.other++;
          this.sfx('bell', 0.6, 0.9);
          break;
        default: // barricade
          h.speed = 0;
          h.stun = 0.5;
          this.hits.other++;
      }
    }

    hitPerson(o) {
      const h = this.hero;
      o.hit = 0;
      o.vy = 0;
      o.knock = h.lane === 2 ? -1 : 1; // knocked into the next lane
      o.spinDir = Math.random() < 0.5 ? -1 : 1;
      h.speed *= 0.35;
      h.bump = 0.3;
      h.invuln = 0.8;
      h.lock = 0;
      this.shake = Math.max(this.shake, 0.25);
      this.burst('ধপাস!', o.x, o.y - 110 * S.scaleAt(o.y));
      this.sfx('thud', 0.9);
      this.hits.person++;
      this.fine(FINES.person);
      h.pose = 'scratch';
      h.poseT = 1.8;
      h.bubble = { text: 'রাগ করলা?', t: 0, life: 1.9 };
      this.voice('raag');
    }

    collect(o) {
      const h = this.hero;
      o.gone = true;
      const y = o.y - 100 * o.s;
      switch (o.kind) {
        case 'coin':
          this.coins += 10;
          this.sfx('coin', 0.8, rand(0.95, 1.1));
          this.float('+৳' + bn(10), o.x, y, '#ffd23f', { life: 0.9 });
          break;
        case 'battery':
          h.battery = Math.min(100, h.battery + 25);
          this.sfx('battery', 0.8);
          this.float('+' + bn(25) + '% চার্জ', o.x, y, '#39ff88');
          break;
        case 'boost':
          this.startBoost(true);
          break;
        case 'tea':
          h.tea = true;
          this.sfx('tea', 0.9);
          this.float('গরম চা! পরের জরিমানা মাফ', o.x, y, '#ffb347', { life: 1.6 });
          break;
      }
    }

    gameOver() {
      if (this.phase === 'over') return;
      this.phase = 'over';
      this.overT = 0;
      this.sfx('lose', 0.9);
      this.result = this.makeResult(null);
      this.onEvent('over', this.result);
    }

    makeResult(pos) {
      const bonus = pos ? BONUS[pos - 1] : 0;
      return {
        route: this.route, pos, time: this.time, coins: this.coins, fines: this.fines, bonus,
        total: Math.max(0, bonus + this.coins - this.fines), hits: Object.assign({}, this.hits),
        stars: pos ? Math.max(0, 4 - pos) : 0, km: this.hero.x / PX_PER_KM, night: this.night,
      };
    }

    // ---------------------------------------------------------------- update

    update(dt, input) {
      dt = Math.min(dt, 0.05);
      this.t += dt;
      const inp = this.demo ? this.autopilot(dt) : input || {};
      if (this.phase === 'countdown') {
        this.countT -= dt;
        const n = Math.ceil(this.countT - 0.6);
        if (n < this.lastBeep && n >= 0) {
          this.lastBeep = n;
          if (this.sound && this.audio) this.audio.beep(n === 0 ? 880 : 440, n === 0 ? 0.5 : 0.18, 0.18);
        }
        if (this.countT <= 0.6) this.phase = 'race';
      }
      if (this.phase === 'race' && !this.demo) this.time += dt;
      this.updateHero(dt, inp);
      if (this.phase !== 'countdown') {
        this.spawnTick();
        this.updateTraffic(dt);
        this.updateRivals(dt);
      }
      this.updatePeople(dt);
      this.collide();
      if (this.phase === 'race' && !this.demo && this.hero.x >= this.len) this.finish();
      if (this.phase === 'over') this.overT += dt;
      // effects
      for (const f of this.fx) f.t += dt;
      this.fx = this.fx.filter((f) => f.t < f.life);
      for (const p of this.parts) {
        p.t += dt;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.vy += 900 * dt;
      }
      this.parts = this.parts.filter((p) => p.t < p.life);
      this.shake = Math.max(0, this.shake - dt);
      // camera leads a little when going fast
      const want = HERO_X + clamp((this.hero.speed - CRUISE) * 0.22, -40, 90);
      this.screenX += (want - this.screenX) * Math.min(1, dt * 2.5);
      const cx = this.camX();
      this.objs = this.objs.filter((o) => o.kind === 'rival' || (!o.gone && o.x > cx - 1100 && o.x < cx + S.W + 3200 && !(o.kind === 'person' && (o.y > S.H + 90 || o.y < S.FOOT_TOP - 10))));
      if (this.sound && this.audio) {
        const h = this.hero;
        const moving = this.phase !== 'over' && h.speed > 25;
        this.audio.loop('motor', moving ? (h.battery > 0 ? 0.55 + h.speed / 1600 : 0.25) : 0, 0.75 + h.speed / 900);
        this.audio.loop(this.night ? 'ambience-night' : 'ambience-day', 1);
        if (this.route.rain) this.audio.loop('rain', 1);
      }
    }

    updateHero(dt, inp) {
      const h = this.hero;
      const motor = 1 + 0.05 * this.up.motor;
      const flat = h.battery <= 0;
      const racing = this.phase === 'race';
      let target;
      if (this.phase === 'countdown' || this.phase === 'over') target = 0;
      else if (this.phase === 'finished') target = 140;
      else if (h.stun > 0) target = 0;
      else if (h.boostT > 0) target = BOOST * motor;
      else if (inp.brake) target = 0;
      else if (inp.accel) target = (flat ? PEDAL_TOP : TOP) * motor;
      else target = (flat ? PEDAL_CRUISE : CRUISE) * motor;
      if (h.puddle > 0) target = Math.min(target, 250);
      target = Math.min(target, this.cap);
      const rate = target > h.speed ? (h.boostT > 0 ? 1500 : flat ? 220 : 380) : inp.brake ? 950 : 520;
      if (inp.brake && h.speed > 300 && !h.braking) this.sfx('brake', 0.6);
      h.braking = !!inp.brake && h.speed > 60;
      h.speed += clamp(target - h.speed, -rate * dt, rate * dt);
      h.x += h.speed * dt;
      h.rot += (h.speed * dt) / 31;
      h.crank += ((h.speed * dt) / 31) * 0.55;
      if (racing && !this.demo) {
        const drain = (h.speed < 40 ? 0 : inp.accel ? 2.0 : 0.85) * (1 - 0.18 * this.up.battery);
        h.battery = Math.max(0, h.battery - drain * dt);
        if (h.battery <= 0 && !h.flatWarned) {
          h.flatWarned = true;
          this.hudMsg('ব্যাটারি শেষ! এবার প্যাডেল মারো!', '#ff6b6b', 'center', 2.2);
        }
        if (h.battery > 5) h.flatWarned = false;
      }
      if (racing && h.laneT > 0.6) {
        if (inp.up) this.heroLane(h.lane - 1);
        else if (inp.down) this.heroLane(h.lane + 1);
      }
      if (h.laneT < 1) {
        h.laneT = Math.min(1, h.laneT + dt / 0.24);
        h.y = h.from + (LANES[h.lane] - h.from) * ease(h.laneT);
      }
      if (racing && inp.bell && h.bellCd <= 0) this.ringBell();
      if (racing && inp.boost && h.boostT <= 0 && h.boostCd <= 0) this.startBoost(false);
      for (const k of ['boostT', 'boostCd', 'bellCd', 'bell', 'stun', 'invuln', 'bump', 'puddle', 'lock']) if (h[k] > 0) h[k] = Math.max(0, h[k] - dt);
      if (h.poseT > 0 && (h.poseT -= dt) <= 0) h.pose = null;
      if (h.bubble && (h.bubble.t += dt) > h.bubble.life) h.bubble = null;
    }

    updateTraffic(dt) {
      const h = this.hero;
      for (const o of this.objs) {
        const k = KIND[o.kind];
        if (!k.solid || o.kind === 'rival' || o.kind === 'barricade') continue;
        let cruise = o.cruise;
        if (o.kind === 'bus') {
          // buses stop wherever passengers wave
          if ((o.stopIn -= dt) <= 0) {
            o.stopT = rand(2, 3.2);
            o.stopIn = rand(7, 12);
          }
          if (o.stopT > 0) {
            o.stopT -= dt;
            cruise = 0;
          }
        }
        let want = cruise;
        const lead = this.leader(o);
        if (lead && lead.gap < 90) want = Math.min(want, lead.vx);
        if (lead && lead.gap < 20) want = Math.min(want, lead.vx * 0.7);
        if (lead && lead.gap < 240 && lead.vx < cruise * 0.7 && o.laneT >= 1 && o.kind !== 'bus' && Math.random() < dt * 2.5) {
          const opts = [o.lane - 1, o.lane + 1].filter((l) => l >= 0 && l <= 2 && !this.blocked(l, o.x - 280, o.x + 440, o, false) && !(l === h.lane && Math.abs(h.x - o.x) < 420));
          if (opts.length) this.laneTo(o, pick(opts));
        }
        if (lead && lead.hero && lead.gap < 160 && (o.honkCd -= dt) <= 0) {
          o.honkCd = rand(2.5, 5); // Dhaka manners: stuck behind you, they honk
          this.sfx(o.kind === 'bus' ? 'horn-bus' : 'horn-car', 0.35, o.kind === 'cng' ? 1.3 : 1);
        }
        o.vx += (want - o.vx) * Math.min(1, dt * 4);
        o.x += o.vx * dt;
        o.rot += (o.vx * dt) / k.wheel;
        if (o.laneT < 1) {
          o.laneT = Math.min(1, o.laneT + dt / 0.55);
          o.y = o.from + (LANES[o.lane] - o.from) * ease(o.laneT);
        }
        if (o.hazard > 0) o.hazard -= dt;
        if (o.jolt > 0) o.jolt = Math.max(0, o.jolt - dt * 2.5);
        if (o.kind === 'cng' && !o.passed && o.x > h.x) {
          o.passed = true;
          if (Math.abs(o.y - h.y) < 120) this.sfx('whoosh', 0.6);
        }
      }
    }

    updateRivals(dt) {
      const h = this.hero;
      for (const r of this.rivals) {
        let target = r.pace * this.route.rival * CRUISE;
        const gap = r.x - h.x;
        if (this.demo) target = Math.max(0, h.speed + clamp((r.demoGap - gap) * 0.6, -300, 300)); // hold their spot on screen
        else target *= gap > 2600 ? 0.9 : gap < -2600 ? 1.1 : 1; // keep the race close
        if ((r.surge -= dt) <= 0) {
          r.surgeT = rand(1, 2.5);
          r.surge = rand(4, 9);
        }
        if (r.surgeT > 0) {
          r.surgeT -= dt;
          target *= 1.12;
        }
        if (r.finished) target = 150;
        if (Math.abs(gap) < 1800) {
          // puddles and potholes slow rivals down too
          for (const o of this.objs) {
            if (KIND[o.kind].decal && o.lane === r.lane && Math.abs(o.x - r.x) < KIND[o.kind].half * o.s + 100) target *= o.kind === 'puddle' ? 0.6 : 0.75;
          }
          const lead = this.leader(r);
          if (lead && lead.gap < 100) target = Math.min(target, lead.vx);
          if (lead && lead.gap < 280 && lead.vx < target * 0.8 && r.laneT >= 1 && Math.random() < dt * 3) {
            const opts = [r.lane - 1, r.lane + 1].filter((l) => l >= 0 && l <= 2 && !this.blocked(l, r.x - 280, r.x + 420, r) && !(l === h.lane && Math.abs(h.x - r.x) < 330));
            if (opts.length) this.laneTo(r, pick(opts));
          }
        } else if (!this.demo) {
          // off screen they still meet traffic now and then
          if (r.delay > 0) {
            r.delay -= dt;
            target *= 0.55;
          } else if (Math.random() < dt * 0.22) {
            r.delay = rand(0.5, 1.6);
          }
        }
        if (this.demo && r.lane === h.lane && r.laneT >= 1) {
          // in the demo, rivals keep out of the hero's lane so its staged moments can play
          const opts = [0, 1, 2].filter((l) => l !== h.lane && !this.blocked(l, r.x - 300, r.x + 400, r, false));
          if (opts.length) this.laneTo(r, pick(opts));
        }
        if (this.phase === 'countdown') target = 0;
        r.vx += (target - r.vx) * Math.min(1, dt * 2);
        r.x += r.vx * dt;
        r.rot += (r.vx * dt) / 31;
        if (r.laneT < 1) {
          r.laneT = Math.min(1, r.laneT + dt / 0.5);
          r.y = r.from + (LANES[r.lane] - r.from) * ease(r.laneT);
        }
        if (!this.demo && !r.finished && r.x >= this.len) {
          r.finished = true;
          r.finishTime = this.time;
        }
      }
    }

    updatePeople(dt) {
      const h = this.hero;
      const front = h.x + 110;
      const ly = LANES[h.lane];
      for (const o of this.objs) {
        if (o.kind !== 'person') continue;
        if (o.hit != null) {
          o.hit += dt;
          if (o.hit < 0.7) o.y += o.knock * 130 * dt;
          else if (o.hit > 2.6) o.y += (o.knock > 0 ? 70 : -70) * dt; // dusts off and keeps going
          continue;
        }
        if (o.staged && o.y < ly + 20) {
          // demo: pace the walk to meet the rickshaw, or hurry off when it rings the bell
          if (o.staged === 'bell' && !o.belled && o.x - front < 420) {
            o.belled = true;
            h.bell = 1;
            this.sfx('bell', 0.9);
            this.float('ক্রিং ক্রিং!', h.x + 90, h.y - 215, '#ffffff', { life: 1.2 });
          }
          if (o.belled) o.vy = 280;
          else if (o.y < ly) {
            const tt = Math.max(0.05, (o.x - front) / Math.max(80, h.speed));
            o.vy = clamp((ly - o.y) / tt, 25, 170);
          }
        } else if (o.staged && Math.abs(o.vy) > 90) {
          o.vy = 90;
          if (o.belled) h.lock = 0;
        }
        o.y += o.vy * dt;
      }
    }

    finish() {
      const h = this.hero;
      this.phase = 'finished';
      const pos = 1 + this.rivals.filter((r) => r.finished).length;
      this.result = this.makeResult(pos);
      this.finishPos = pos;
      this.sfx(pos === 1 ? 'win' : pos <= 3 ? 'cheer' : 'lose', 0.9);
      if (pos <= 3 && pos !== 1) this.sfx('win', 0.5);
      if (pos === 1) this.sfx('cheer', 0.7);
      h.bubble = { text: pos === 1 ? 'বাংলা টেসলা জিতেছে!' : pos <= 3 ? 'খারাপ না!' : 'পরের বার!', t: 0, life: 3 };
      this.onEvent('finish', this.result);
    }

    // ---------------------------------------------------------------- demo autopilot

    autopilot(dt) {
      const h = this.hero;
      const inp = {};
      if ((this.gagIn -= dt) <= 0) this.gagIn = this.stage() ? 6.5 : 1;
      this.cap = Infinity;
      if (h.lock > 0) return inp;
      const front = h.x + 140;
      const look = 340 * Math.max(1, h.speed / CRUISE);
      if (!this.blocked(h.lane, front - 30, front + look)) return inp;
      if (h.laneT >= 1) {
        const opts = [h.lane - 1, h.lane + 1].filter((l) => l >= 0 && l <= 2 && !this.blocked(l, h.x - 330, h.x + 280 + look));
        if (opts.length) {
          this.heroLane(pick(opts));
          return inp;
        }
      }
      // boxed in: tuck in behind whatever is ahead
      for (const o of this.objs) {
        const k = KIND[o.kind];
        if (k.solid && o.lane === h.lane && o.x > h.x && o.x - k.half * o.s - front < look) this.cap = Math.min(this.cap, o.vx * 0.9);
      }
      return inp;
    }

    // Staged moments in rotation: bump a private car, bell someone clear, bump someone, boost.
    stage() {
      const h = this.hero;
      const kind = ['car', 'bell', 'person', 'boost'][this.gag % 4];
      if (kind === 'boost') {
        this.startBoost(true);
        this.gag++;
        return true;
      }
      if (h.laneT < 1 || this.cap < Infinity) return false;
      // rivals step out of the hero's lane on their own, so they don't count here
      if (this.blocked(h.lane, h.x - 200, h.x + 1500, null, true, false)) {
        const l = [h.lane - 1, h.lane + 1].find((q) => q >= 0 && q <= 2 && !this.blocked(q, h.x - 330, h.x + 1500, null, true, false));
        if (l != null) this.heroLane(l);
        return false;
      }
      if (kind === 'car') this.add({ kind: 'car', lane: h.lane, x: h.x + 1300, vx: 170, color: A.CAR_COLORS[0], honkCd: 9 });
      else this.add({ kind: 'person', type: pick(A.PEOPLE_TYPES), x: h.x + 120 + CRUISE * 3.2, y: S.FOOT_TOP + 34, vy: 60, staged: kind, phase: rand(0, 6) });
      h.lock = 7; // hold the lane until it plays out
      this.gag++;
      return true;
    }

    // ---------------------------------------------------------------- drawing

    // hudScale > 1 enlarges the HUD and speech bubbles on small (phone) screens.
    render(ctx, scale, hudScale) {
      this.hudScale = hudScale || 1;
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      A.beginNight(this.night);
      const cx = this.camX();
      ctx.save();
      if (this.shake > 0) ctx.translate((Math.random() - 0.5) * 16 * this.shake, (Math.random() - 0.5) * 10 * this.shake);
      let banner = null;
      if (!this.demo && !this.route.endless) {
        if (this.len - cx < S.W + 300) banner = { x: this.len - cx, label: this.route.to };
        else if (cx < 500) banner = { x: 170 - cx, label: this.route.from };
      }
      S.drawScene(ctx, cx, this.t, (c) => this.drawWorld(c, cx), banner);
      if (this.route.rain) S.drawRain(ctx, this.t, 1);
      this.drawFx(ctx, cx);
      ctx.restore();
      A.beginNight(false);
      if (!this.demo) this.drawHud(ctx);
      if (this.phase === 'countdown') this.drawCountdown(ctx);
      if (this.phase === 'finished') this.drawFinish(ctx);
      if (this.phase === 'over') this.drawOver(ctx);
    }

    drawWorld(c, cx) {
      const t = this.t;
      for (const o of this.objs) {
        const x = o.x - cx;
        if (x < -400 || x > S.W + 400) continue;
        if (o.kind === 'pothole') A.drawPothole(c, x, o.y, o.s);
        else if (o.kind === 'puddle') A.drawPuddle(c, x, o.y, o.s * 0.7, t);
      }
      const list = [this.hero];
      for (const o of this.objs) if (!KIND[o.kind].decal && !o.gone) list.push(o);
      list.sort((a, b) => a.y - (KIND[a.kind] && KIND[a.kind].pickup ? 1 : 0) - (b.y - (KIND[b.kind] && KIND[b.kind].pickup ? 1 : 0)));
      for (const o of list) {
        if (o === this.hero) this.drawHero(c);
        else this.drawObj(c, o, cx, t);
      }
      for (const p of this.parts) {
        A.circle(c, p.x - cx, p.y, p.r);
        A.paint(c, A.rgba('#bcd3ea', 0.9 * (1 - p.t / p.life)));
      }
    }

    drawObj(c, o, cx, t) {
      const x = o.x - cx;
      if (x < -700 || x > S.W + 700) return;
      const s = o.kind === 'person' ? S.scaleAt(o.y) : o.s;
      switch (o.kind) {
        case 'car':
          A.drawCar(c, x, o.y, s, t, { color: o.color, wheelRot: o.rot, dent: o.dent, hazard: o.hazard > 0, jolt: o.jolt ? Math.sin(o.jolt * 30) * o.jolt * 8 : 0 });
          break;
        case 'bus':
          A.drawBus(c, x, o.y, s, t, { color: o.color, seed: o.seed, wheelRot: o.rot });
          break;
        case 'cng':
          A.drawCNG(c, x, o.y, s, t, { wheelRot: o.rot });
          break;
        case 'rival':
          A.drawRickshaw(c, x, o.y, s, t, { skin: o.skin, wheelRot: o.rot, sway: Math.min(1, o.vx / 600) });
          break;
        case 'barricade':
          A.drawBarricade(c, x, o.y, s * 0.9, t);
          break;
        case 'person':
          A.drawPerson(c, x, o.y, s, t, { type: o.type, phase: o.phase, hit: o.hit, spinDir: o.spinDir });
          break;
        case 'coin':
          A.drawCoin(c, x, o.y, s, t, { seed: o.seed });
          break;
        case 'battery':
          A.drawBatteryPickup(c, x, o.y, s, t, { seed: o.seed });
          break;
        case 'boost':
          A.drawBoostPickup(c, x, o.y, s, t, { seed: o.seed });
          break;
        case 'tea':
          A.drawTea(c, x, o.y, s, t, { seed: o.seed });
          break;
      }
    }

    heroBob() {
      const h = this.hero;
      return h.bump > 0 ? -Math.abs(Math.sin(h.bump * 20)) * 9 * (h.bump / 0.45) : h.speed > 20 ? Math.sin(this.t * 15) * 0.6 : 0;
    }

    drawHero(c) {
      const h = this.hero;
      if (h.invuln > 0 && h.stun <= 0 && Math.floor(this.t * 14) % 2 === 0) return; // blink while recovering
      const hs = S.scaleAt(h.y);
      const bob = this.heroBob();
      A.drawRickshaw(c, this.screenX, h.y, hs, this.t, {
        skin: this.skin, wheelRot: h.rot, crank: h.crank, bob, pose: h.pose, talk: !!h.bubble,
        boost: h.boostT > 0, sway: Math.min(1, h.speed / 600), pedal: h.battery <= 0,
      });
      if (h.bell > 0) {
        const bx = this.screenX + 80 * hs, by = h.y + (bob - 129) * hs;
        c.save();
        c.lineCap = 'round';
        for (let i = 1; i <= 3; i++) {
          const r = i * 9 + (1.2 - h.bell) * 22;
          for (const [a0, a1] of [[-1.2, -0.3], [Math.PI + 0.3, Math.PI + 1.2]]) {
            c.beginPath();
            c.arc(bx, by, r, a0, a1);
            c.strokeStyle = A.OL;
            c.lineWidth = 5;
            c.stroke();
            c.strokeStyle = '#ffd23f';
            c.lineWidth = 2.5;
            c.stroke();
          }
        }
        c.restore();
      }
    }

    drawFx(ctx, cx) {
      for (const f of this.fx) {
        const p = f.t / f.life;
        if (f.kind === 'burst') {
          const sc = p < 0.7 ? 0.45 + 0.55 * A.easeOutBack(Math.min(1, f.t / 0.16)) : (1 - p) / 0.3;
          A.drawBurst(ctx, f.x - cx, f.y, f.text, sc, { seed: f.seed });
        } else if (f.kind === 'text') {
          A.drawFloatText(ctx, f.x - cx, f.y - p * 50, f.text, f.color, p < 0.7 ? 1 : (1 - p) / 0.3);
        }
      }
      const h = this.hero;
      if (h.bubble) {
        const hs = S.scaleAt(h.y);
        A.drawBubble(ctx, this.screenX + 60 * hs, h.y + (this.heroBob() - 168) * hs, h.bubble.text, { pop: h.bubble.t / 0.22, size: 24 * Math.min(1.3, this.hudScale) });
      }
    }

    // ---------------------------------------------------------------- HUD

    positions() {
      // finished racers by finish time, the rest by distance
      const racers = [{ hero: true, x: this.hero.x, finished: this.phase === 'finished', finishTime: this.result ? this.result.time : 0 }];
      for (const r of this.rivals) racers.push({ x: r.x, finished: r.finished, finishTime: r.finishTime, skin: r.skin });
      racers.sort((a, b) => (a.finished && b.finished ? a.finishTime - b.finishTime : a.finished ? -1 : b.finished ? 1 : b.x - a.x));
      return racers;
    }

    drawHud(ctx) {
      const L = hudLayout(S.W, this.hudScale);
      const s = L.s, UI = A.FONT_UI, CREAM = '#fff7e8';
      const h = this.hero;
      const label = (text, x, y, font, color, align) => {
        ctx.font = font;
        ctx.textAlign = align || 'left';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = color;
        ctx.fillText(text, x, y);
        return ctx.measureText(text).width;
      };
      // each panel is drawn unscaled (76px tall) in its own frame, then scaled up on phones
      const panel = (p, draw) => {
        const w = p.w / s;
        ctx.save();
        ctx.translate(p.x, L.top);
        ctx.scale(s, s);
        A.rrect(ctx, 0, 0, w, 76, 14);
        A.paint(ctx, 'rgba(29,20,40,0.82)', '#ffd23f', 2.5);
        draw(w);
        ctx.restore();
      };
      // battery, speed, boost / flat / tea
      panel(L.left, (w) => {
        const b = h.battery / 100;
        A.bolt(ctx, 24, 38, 34, b > 0 ? '#ffd23f' : '#ff4d4d', A.OL);
        label('ব্যাটারি', 46, 20, '700 15px ' + UI, CREAM);
        A.rrect(ctx, 114, 12, 124, 16, 5);
        A.paint(ctx, 'rgba(255,255,255,0.12)', CREAM, 1.5);
        if (b > 0) {
          A.rrect(ctx, 117, 15, 118 * b, 10, 3);
          A.paint(ctx, b > 0.5 ? '#39ff88' : b > 0.2 ? '#ffd23f' : '#ff4d4d');
        }
        label(bn(Math.round(h.battery)) + '%', 246, 20, '700 15px ' + UI, b > 0.2 ? CREAM : '#ff6b6b');
        const sw = label(bn(Math.round(h.speed * KMH)), 46, 54, '700 26px ' + UI, '#ffd23f');
        label('কিমি/ঘণ্টা', 52 + sw, 56, '600 14px ' + UI, CREAM);
        if (h.boostT > 0) label('বুস্ট!', w - 12, 56, '700 17px ' + UI, '#4cc3ff', 'right');
        else if (b <= 0) label('প্যাডেল!', w - 12, 56, '700 16px ' + UI, '#ff6b6b', 'right');
        else if (h.tea) label('চা ☕', w - 12, 56, '700 16px ' + UI, '#ffb347', 'right');
      });
      panel(L.center, (w) => {
        if (this.route.endless) {
          label('জ্যাম মোড', 16, 24, '24px ' + A.FONT_DISPLAY, '#ffd23f');
          label(bn((h.x / PX_PER_KM).toFixed(2)) + ' কিমি', w - 16, 24, '700 19px ' + UI, CREAM, 'right');
          label('ক্ষমা', 16, 56, '700 15px ' + UI, CREAM);
          for (let i = 0; i < 3; i++) {
            A.circle(ctx, 72 + i * 28, 56, 10);
            A.paint(ctx, i < this.forgive ? '#ff4fa3' : 'rgba(255,255,255,0.15)', CREAM, 1.5);
          }
          if (w >= 420) label('কারে ৪ বার ধাক্কা = শেষ', w - 16, 56, '600 14px ' + UI, '#cbbbe8', 'right');
          return;
        }
        // route progress with every racer
        const left = 'আর ' + bn((Math.max(0, this.len - h.x) / PX_PER_KM).toFixed(1)) + ' কিমি';
        if (w >= 420) {
          label(this.route.from, 16, 20, '700 15px ' + UI, CREAM);
          label(left, w / 2, 20, '600 14px ' + UI, '#cbbbe8', 'center');
        } else {
          label(left, 16, 20, '600 14px ' + UI, '#cbbbe8');
        }
        label(this.route.to, w - 16, 20, '700 15px ' + UI, CREAM, 'right');
        const x0 = 16, x1 = w - 34;
        const prog = (x) => x0 + (x1 - x0) * clamp(x / this.len, 0, 1);
        A.rrect(ctx, x0, 48, x1 - x0, 8, 4);
        A.paint(ctx, 'rgba(255,255,255,0.15)');
        A.rrect(ctx, x0, 48, Math.max(8, prog(h.x) - x0), 8, 4);
        A.paint(ctx, '#ff4fa3');
        for (const r of this.rivals) {
          A.circle(ctx, prog(r.x), 52, 6);
          A.paint(ctx, r.skin.frame, A.OL, 1.5);
        }
        A.circle(ctx, prog(h.x), 52, 9);
        A.paint(ctx, this.skin.frame, '#ffd23f', 2.5);
        for (let r = 0; r < 3; r++) {
          for (let c = 0; c < 2; c++) {
            ctx.fillStyle = (r + c) % 2 ? '#ffffff' : '#111111';
            ctx.fillRect(w - 26 + c * 5, 44 + r * 5, 5, 5);
          }
        }
      });
      // position (or money in জ্যাম মোড), taka, time
      panel(L.right, () => {
        const net = this.coins - this.fines;
        if (this.route.endless) {
          label('৳ ' + bn(net), 16, 38, '700 25px ' + UI, net < 0 ? '#ff6b6b' : '#ffd23f');
        } else {
          const pos = this.positions().findIndex((r) => r.hero) + 1;
          const pw = label(ORDINAL[pos - 1], 14, 40, '48px ' + A.FONT_DISPLAY, '#ffd23f');
          label('/' + bn(4), 18 + pw, 52, '600 17px ' + UI, CREAM);
          label('৳ ' + bn(net), 150, 22, '700 21px ' + UI, net < 0 ? '#ff6b6b' : '#ffd23f');
        }
        label('⏱ ' + fmtTime(this.time), 150, this.route.endless ? 38 : 55, '600 16px ' + UI, CREAM);
      });
      for (const f of this.fx) {
        if (f.kind !== 'hud') continue;
        const p = f.t / f.life;
        const x = f.at === 'taka' ? L.right.x + 150 * s : S.W / 2;
        const y = L.top + L.h + (f.at === 'taka' ? 26 : 58) * s - p * 40;
        ctx.save();
        ctx.translate(x, y);
        ctx.scale(s, s);
        A.drawFloatText(ctx, 0, 0, f.text, f.color, p < 0.7 ? 1 : (1 - p) / 0.3);
        ctx.restore();
      }
    }

    bigText(ctx, text, y, size, color, sc) {
      ctx.save();
      ctx.translate(S.W / 2, y);
      ctx.scale(sc, sc);
      ctx.font = size + 'px ' + A.FONT_DISPLAY;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.lineJoin = 'round';
      ctx.lineWidth = 14;
      ctx.strokeStyle = A.OL;
      ctx.strokeText(text, 0, 0);
      ctx.fillStyle = color;
      ctx.fillText(text, 0, 0);
      ctx.restore();
    }

    drawCountdown(ctx) {
      const n = Math.ceil(this.countT - 0.6);
      const frac = (this.countT - 0.6) % 1;
      const text = n >= 1 ? bn(n) : 'চলো!';
      const p = n >= 1 ? 1 - frac : 1 - this.countT / 0.6;
      this.bigText(ctx, text, 330, 150, n >= 1 ? '#ffd23f' : '#35d07f', 0.6 + 0.4 * A.easeOutBack(Math.min(1, p * 3)));
      const hint = this.touch
        ? '▲ ▼ লেন বদল · গতি · ব্রেক · ঘণ্টি · বুস্ট'
        : '↑ ↓ লেন বদল · → গতি · ← ব্রেক · Space ঘণ্টি · Shift বুস্ট';
      ctx.save();
      ctx.translate(S.W / 2, 461);
      ctx.scale(this.hudScale, this.hudScale);
      ctx.font = '700 20px ' + A.FONT_UI;
      const bw = ctx.measureText(hint).width + 60;
      A.rrect(ctx, -bw / 2, -20, bw, 40, 20);
      A.paint(ctx, 'rgba(29,20,40,0.78)');
      ctx.fillStyle = '#fff7e8';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(hint, 0, 1);
      ctx.restore();
    }

    drawFinish(ctx) {
      const p = Math.min(1, (this.result ? this.t - (this.finishAt || (this.finishAt = this.t)) : 0) * 3);
      this.bigText(ctx, 'শেষ!', 260, 120, '#ffd23f', 0.5 + 0.5 * A.easeOutBack(p));
      this.bigText(ctx, ORDINAL[this.finishPos - 1] + ' হয়েছেন!', 380, 64, '#fff7e8', 0.5 + 0.5 * A.easeOutBack(p));
    }

    drawOver(ctx) {
      const p = Math.min(1, this.overT * 3);
      this.bigText(ctx, 'আর ক্ষমা নেই!', 300, 96, '#ff6b6b', 0.5 + 0.5 * A.easeOutBack(p));
    }

    stopSounds() {
      if (this.audio) this.audio.stopLoops();
    }
  }

  window.BT.Race = Race;
  window.BT.ROUTES = ROUTES;
  window.BT.ENDLESS = ENDLESS;
  window.BT.DEMO = DEMO;
  window.BT.fmtTime = fmtTime;
  window.BT.hudLayout = hudLayout;
  window.BT.ORDINAL = ORDINAL;
})();
