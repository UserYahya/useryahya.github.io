/* বাংলা টেসলা 3D — the Dhaka street, built in 32 m chunks that stream in ahead of the
 * camera: shops with Bengali signboards, windows that light up at night, balconies with
 * laundry, water tanks and billboards on the roofs, electric poles with their famous
 * tangle of wires, flame trees, tea stalls, a median with lamps, the metro rail overhead on
 * some routes and footbridges with adverts. Everything is seeded by chunk number, so a route
 * looks the same every time.
 *
 * The race routes are the real streets, from OpenStreetMap (src/routes/, made by
 * tools/osm-routes.js): the road bends the way they do, the buildings are as tall as the real
 * ones, and the side streets, landmarks, metro and footbridges come where they really are
 * (squeezed into the race's length). Jam mode and the demo get a made-up straight avenue.
 *
 * Road coordinates: s metres along the road from the start, lateral metres across it (lanes
 * at -2.8, 0, 2.8; the kerb lane on the left), y up. Chunks are built as if the road ran
 * straight down -z (x = lateral, z = -s), then bent onto the route's path. */
(function () {
  'use strict';

  const { T, Builder, MAT, tf, cell } = window.BT.k3;
  const X = window.BT.tex3;
  const A = window.BT.art;
  const hash = A.hash;

  const CH = 32; // chunk length
  const ROAD = 4.2; // half the road width (three 2.8 m lanes)
  const KERB = 0.25, KERB_H = 0.18;
  const TAU = Math.PI * 2;

  const FACADES = ['#efe6d6', '#e8dcc6', '#f4a261', '#e9c46a', '#8ecae6', '#f7c6c7', '#b5e48c', '#ffd6a5', '#cdb4db', '#d9d4c7', '#90be6d', '#f28482', '#a8dadc', '#e6e2d6'];
  const OLD_FACADES = ['#b5533c', '#c98a4b', '#d9b98c', '#a7745a', '#e1cfa8', '#a8b5a2', '#c4795c', '#d8c3a5'];
  const TOWER = ['#d9dde0', '#c7ccd1', '#e3ddd2', '#b9c3c9'];
  const LAUNDRY = ['#e63946', '#ffd23f', '#4cc3ff', '#ff4fa3', '#f1faee', '#35d07f', '#ff9f1c'];
  const SHIRTS = ['#e63946', '#f1faee', '#a8dadc', '#ffd166', '#90be6d', '#cdb4db', '#f4a261', '#7fb3d5'];
  const SKINS = ['#8a5a3c', '#a26b49', '#6f4329', '#b47a55'];
  const RICKSHAW_HOODS = ['#8c1239', '#1c3d99', '#1b1b1f', '#0b6e4f', '#5b1a8c'];

  /* Street looks: footpath widths, a median with oncoming lanes (or none, in old Dhaka),
   * the metro overhead, building heights and styles. */
  const THEMES = {
    avenue: { median: true, metro: false, footL: 3.6, footR: 3.2, oncoming: 6.6, road: 'avenue', floors: [3, 8], bw: [5, 10], palette: FACADES, glass: 0.05, trees: 0.45, flame: 0.3, overpass: 0.18, alley: 0.12, stalls: 0.6 },
    metro: { median: true, metro: true, footL: 3.6, footR: 3.2, oncoming: 6.6, road: 'avenue', floors: [4, 9], bw: [6, 11], palette: FACADES, glass: 0.12, trees: 0.3, flame: 0.2, overpass: 0.15, alley: 0.1, stalls: 0.6 },
    dhanmondi: { median: true, metro: false, footL: 3.8, footR: 3.4, oncoming: 6.6, road: 'avenue', floors: [3, 7], bw: [6, 11], palette: FACADES, glass: 0.08, trees: 0.8, flame: 0.6, overpass: 0.15, alley: 0.12, stalls: 0.7 },
    gulshan: { median: true, metro: false, footL: 4.0, footR: 3.6, oncoming: 6.6, road: 'gulshan', floors: [7, 15], bw: [9, 15], palette: TOWER, glass: 0.6, trees: 0.8, flame: 0.35, overpass: 0.12, alley: 0.2, stalls: 0.3 },
    puran: { median: false, metro: false, footL: 1.8, footR: 1.6, oncoming: 0, road: 'puran', floors: [2, 5], bw: [3.5, 6.5], palette: OLD_FACADES, glass: 0, trees: 0.12, flame: 0.2, overpass: 0, alley: 0.18, stalls: 0.8, old: true },
    motijheel: { median: true, metro: true, footL: 3.6, footR: 3.2, oncoming: 6.6, road: 'night', floors: [8, 18], bw: [9, 14], palette: TOWER, glass: 0.45, trees: 0.25, flame: 0.1, overpass: 0.15, alley: 0.15, stalls: 0.5 },
  };
  const ROUTE_THEME = { farmgate: 'metro', dhanmondi: 'dhanmondi', gulshan: 'gulshan', puran: 'puran', motijheel: 'motijheel', endless: 'avenue', demo: 'metro' };

  // Where things stand across the road for a theme.
  function layout(th) {
    const L = {};
    L.kerbL = -ROAD - KERB;
    L.buildL = L.kerbL - th.footL;
    if (th.median) {
      L.median0 = ROAD;
      L.median1 = ROAD + 1.2;
      L.kerbR = L.median1 + th.oncoming;
      L.buildR = L.kerbR + KERB + th.footR;
    } else {
      L.kerbR = ROAD;
      L.buildR = ROAD + KERB + th.footR;
    }
    L.poleL = L.kerbL - 0.35;
    L.poleR = L.kerbR + KERB + 0.35;
    return L;
  }

  // ------------------------------------------------------------------ the road's path

  /* The centre line of the road: s → world (x, z). Without route data the road runs straight
   * down -z. pos() gives the world point for road coordinates; heading() the yaw that turns a
   * model facing +x to face down the road. */
  class RoadPath {
    constructor(data) {
      this.curved = !!data;
      if (!data) return;
      this.s0 = data.s0;
      this.step = data.step;
      const n = (this.n = data.path.length / 2);
      this.x = new Float32Array(n);
      this.z = new Float32Array(n);
      for (let i = 0; i < n; i++) {
        this.x[i] = data.path[i * 2];
        this.z[i] = data.path[i * 2 + 1];
      }
      // tangents at the samples (central differences), blended between samples for smooth turning
      this.tx = new Float32Array(n);
      this.tz = new Float32Array(n);
      for (let i = 0; i < n; i++) {
        const a = Math.max(0, i - 1), b = Math.min(n - 1, i + 1);
        const dx = this.x[b] - this.x[a], dz = this.z[b] - this.z[a], l = Math.hypot(dx, dz) || 1;
        this.tx[i] = dx / l;
        this.tz[i] = dz / l;
      }
      // where to cut long faces so they follow the bends: close together where the road turns
      // hard, so a face 10 m out from the centre line stays within a centimetre of the curve,
      // and none where it runs straight. (Curvature is measured over 16 m: the samples are
      // rounded to the centimetre, too coarse for a shorter baseline.)
      const kap = new Float32Array(n);
      for (let i = 0; i < n; i++) {
        const a = Math.max(0, i - 4), b = Math.min(n - 1, i + 4);
        let d = Math.atan2(this.tz[b], this.tx[b]) - Math.atan2(this.tz[a], this.tx[a]);
        d -= Math.round(d / TAU) * TAU;
        kap[i] = b > a ? Math.abs(d) / ((b - a) * this.step) : 0;
      }
      const cuts = [], end = this.s0 + (n - 1) * this.step;
      for (let s = this.s0; s < end; ) {
        let k = 0;
        for (let j = Math.floor((s - this.s0) / this.step); j <= Math.ceil((s + 16 - this.s0) / this.step) && j < n; j++) k = Math.max(k, kap[j]);
        if (k < 3e-4) {
          s += 16;
          continue;
        }
        cuts.push(s);
        s += Math.max(1, Math.min(16, Math.sqrt(0.08 / ((1 / k + 10) * k * k))));
      }
      this.cuts = Float64Array.from(cuts);
    }

    // centre point (x, z) and unit direction of travel (tx, tz) at s; past either end it runs on straight
    frame(s, f = {}) {
      if (!this.curved) {
        f.x = 0;
        f.z = -s;
        f.tx = 0;
        f.tz = -1;
        return f;
      }
      const u = (s - this.s0) / this.step;
      const i = Math.max(0, Math.min(this.n - 2, Math.floor(u)));
      const k = u - i;
      f.x = this.x[i] + (this.x[i + 1] - this.x[i]) * k;
      f.z = this.z[i] + (this.z[i + 1] - this.z[i]) * k;
      const kk = Math.max(0, Math.min(1, k));
      const tx = this.tx[i] + (this.tx[i + 1] - this.tx[i]) * kk, tz = this.tz[i] + (this.tz[i + 1] - this.tz[i]) * kk;
      const l = Math.hypot(tx, tz) || 1;
      f.tx = tx / l;
      f.tz = tz / l;
      return f;
    }

    // world point of road coordinates (lateral + is to the right of travel)
    pos(s, lat, y, out) {
      const f = this.frame(s, _fr);
      return out.set(f.x - f.tz * lat, y, f.z + f.tx * lat);
    }

    heading(s) {
      const f = this.frame(s, _fr);
      return Math.atan2(-f.tz, f.tx);
    }
  }
  const _fr = {};

  // Bends geometry built along a straight road (x = lateral, z = -s) onto the path: positions in
  // place, normals turned with the road. Works on a Builder's arrays, or a flat position list.
  function bendArrays(path, P, N) {
    if (!path.curved) return;
    const f = {};
    for (let i = 0; i < P.length; i += 3) {
      const lat = P[i], s = -P[i + 2];
      path.frame(s, f);
      P[i] = f.x - f.tz * lat;
      P[i + 2] = f.z + f.tx * lat;
      if (N) {
        const nx = N[i], nz = N[i + 2];
        // the turn that takes the straight road's direction (0, -1) to (tx, tz)
        N[i] = -nx * f.tz - nz * f.tx;
        N[i + 2] = nx * f.tx - nz * f.tz;
      }
    }
  }
  const bend = (path, b) => bendArrays(path, b.p, b.n);

  // ------------------------------------------------------------------ materials

  const lit = (map, glowMap, extra) => MAT.toon(Object.assign({ map, emissive: new T.Color('#ffffff'), emissiveMap: glowMap, emissiveIntensity: 0 }, extra));
  let M = null;
  let nightOn = false;
  // name boards (one atlas per route), lit at night like the shop signs
  const nameMats = new Set();
  function nameMaterial(tex) {
    const m = lit(tex, tex);
    m.emissiveIntensity = nightOn ? 0.6 : 0;
    nameMats.add(m);
    return m;
  }
  function materials() {
    if (M) return M;
    const decal = X.decals();
    M = {
      solid: MAT.vc,
      windows: lit(X.windows(), X.windowsGlow(), { vertexColors: true }),
      glass: lit(X.glassFacade(), X.glassGlow()),
      signs: lit(X.signs(), X.signs()),
      ads: lit(X.ads(), X.ads()),
      shops: lit(X.shops(), X.shopsGlow()),
      decals: MAT.toon({ map: decal, transparent: true, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -2, polygonOffsetUnits: -2 }),
      wires: new T.LineBasicMaterial({ color: '#1c1820' }),
      foot: {},
      road: {},
      kerb: MAT.toon({ map: X.kerb() }),
      train: MAT.toon({ map: X.train() }),
    };
    return M;
  }
  const roadMat = (look) => M.road[look] || (M.road[look] = MAT.toon({ map: X.road(look) }));
  const footMat = (look) => M.foot[look] || (M.foot[look] = MAT.toon({ map: X.foot(look) }));

  function setNight(on) {
    materials();
    M.windows.emissiveIntensity = on ? 1 : 0;
    M.glass.emissiveIntensity = on ? 0.85 : 0;
    M.signs.emissiveIntensity = on ? 0.75 : 0;
    M.ads.emissiveIntensity = on ? 0.55 : 0;
    M.shops.emissiveIntensity = on ? 0.9 : 0;
    M.wires.color.set(on ? '#08070c' : '#1c1820');
    nightOn = on;
    for (const m of nameMats) m.emissiveIntensity = on ? 0.6 : 0;
  }

  // ------------------------------------------------------------------ small street things

  // A bystander standing still: legs, body, arms, head (one colour set, no outline).
  function bystander(b, x, z, r, face = 0) {
    const shirt = SHIRTS[Math.floor(r() * SHIRTS.length)], skin = SKINS[Math.floor(r() * SKINS.length)];
    const lungi = r() < 0.4;
    const low = lungi ? ['#2f6f3e', '#6a994e', '#5e548e', '#1d3557'][Math.floor(r() * 4)] : ['#2b3445', '#3a3f58', '#1d3557', '#5b4a3a'][Math.floor(r() * 4)];
    const cs = Math.cos(face), sn = Math.sin(face);
    const P = (dx, dz) => [x + dx * cs - dz * sn, z + dx * sn + dz * cs];
    for (const s of [-1, 1]) {
      const [lx, lz] = P(0, s * 0.09);
      b.box(lx, 0.42 + KERB_H, lz, 0.13, 0.84, 0.13, low, 0, face);
    }
    if (lungi) {
      const [lx, lz] = P(0, 0);
      b.cyl(lx, 0.5 + KERB_H, lz, 0.22, 0.8, low, 8, 0, 0, 0, 0.75);
    }
    const [tx, tz] = P(0, 0);
    b.box(tx, 1.04 + KERB_H, tz, 0.24, 0.42, 0.4, shirt, 0, face);
    for (const s of [-1, 1]) {
      const [ax, az] = P(0, s * 0.24);
      b.box(ax, 0.98 + KERB_H, az, 0.09, 0.5, 0.09, skin, 0, face);
    }
    b.ball(tx, 1.38 + KERB_H, tz, 0.12, 0.13, 0.12, skin, 8);
    b.dome(tx - 0.01, 1.41 + KERB_H, tz, 0.125, 0.09, 0.125, '#1a1210', 8);
  }

  // A parked rickshaw (no rider), nose along +x turned by rot.
  function parkedRickshaw(b, x, y, z, rot, r) {
    const hood = RICKSHAW_HOODS[Math.floor(r() * RICKSHAW_HOODS.length)];
    const frame = ['#12b5a5', '#2a9d4b', '#d62828', '#f4b400', '#2b7de9'][Math.floor(r() * 5)];
    const cs = Math.cos(rot), sn = Math.sin(rot);
    const P = (dx, dy, dz) => [x + dx * cs + dz * sn, y + dy, z - dx * sn + dz * cs];
    const box = (dx, dy, dz, w, h, d, c) => {
      const p = P(dx, dy, dz);
      b.box(p[0], p[1], p[2], w, h, d, c, 0, rot);
    };
    box(-0.89, 0.86, 0, 0.84, 0.33, 1.1, '#1d2f6f');
    box(-0.88, 1.09, 0, 0.92, 0.14, 1.12, '#ef3e6d');
    box(-1.32, 1.4, 0, 0.09, 0.5, 1.08, '#ef3e6d');
    box(-0.22, 0.56, 0, 0.58, 0.05, 0.84, '#ffd23f');
    // hood: half a drum over the seat
    const hp = P(-1.0, 1.15, 0);
    b.add(new T.CylinderGeometry(0.62, 0.62, 1.16, 10, 1, true, 0, Math.PI), tf(hp[0], hp[1], hp[2], Math.PI / 2, rot + Math.PI / 2, 0, 1, 1, 1), hood);
    for (const s of [-1, 1]) {
      const w = P(-0.87, 0.345, s * 0.6);
      b.ring(w[0], w[1], w[2], 0.33, 0.03, '#1c1922', 14, 0, rot);
    }
    const f = P(1.16, 0.345, 0);
    b.ring(f[0], f[1], f[2], 0.33, 0.03, '#1c1922', 14, 0, rot);
    b.rod(P(0.07, 0.556, 0), P(1.03, 1.0, 0), 0.032, frame);
    b.rod(P(1.03, 0.98, 0), P(1.16, 0.345, 0), 0.02, '#cfd6df');
    b.rod(P(0.38, 0.44, 0), P(0.3, 1.12, 0), 0.026, frame);
    b.rod(P(0.32, 1.02, 0), P(0.98, 1.22, 0), 0.022, frame);
    const s = P(0.31, 1.16, 0);
    b.ball(s[0], s[1], s[2], 0.15, 0.04, 0.1, '#3a2a22', 8);
    b.rod(P(0.74, 1.4, -0.28), P(0.74, 1.4, 0.28), 0.015, '#cfd6df');
  }

  function tree(b, x, z, r, flame, lights) {
    const h = 4.2 + r() * 1.8;
    b.cyl(x, KERB_H + h / 2, z, 0.16, h, '#6b4a2f', 7, 0, 0, 0, 0.75);
    b.cyl(x, KERB_H + 0.45, z, 0.17, 0.9, '#f1f1ec', 7); // whitewashed trunk
    const n = 5 + Math.floor(r() * 3);
    const greens = ['#3f8f3a', '#2f7a33', '#4fa046', '#367f38'];
    const reds = ['#e8461f', '#ff6a2b', '#d93a1a', '#ff8c42'];
    for (let i = 0; i < n; i++) {
      const a = (i / n) * TAU + r(), d = i ? 1.2 + r() * 1.3 : 0;
      const cx = x + Math.cos(a) * d, cz = z + Math.sin(a) * d * 0.9, cy = KERB_H + h + (i ? 0.3 + r() * 0.9 : 1.2);
      const rad = 1.3 + r() * 0.8;
      const c = flame && r() < 0.75 ? reds[Math.floor(r() * 4)] : greens[Math.floor(r() * 4)];
      b.add(new T.IcosahedronGeometry(1, 0), tf(cx, cy, cz, r() * 3, r() * 3, 0, rad, rad * 0.62, rad), c, true);
    }
  }

  function teaStall(b, x, z, side, r, out) {
    const y = KERB_H, d = -side; // d points from the stall toward the road
    for (const [px, pz] of [[-0.9, -1.0], [-0.9, 1.0], [0.9, -1.0], [0.9, 1.0]]) b.box(x + px, y + 1.15, z + pz, 0.08, 2.3, 0.08, '#5b3a21');
    b.box(x, y + 2.35, z, 2.3, 0.06, 2.6, '#7d8a99', 0, 0, d * 0.1);
    b.box(x + d * 0.35, y + 0.55, z, 0.9, 1.1, 2.0, '#9c6b3c');
    for (let j = 0; j < 3; j++) {
      b.cyl(x + d * 0.5, y + 1.25, z - 0.6 + j * 0.6, 0.13, 0.28, ['#e9c46a', '#f4a261', '#e76f51'][j], 8);
    }
    b.box(x + d * 0.3, y + 1.22, z + 0.85, 0.3, 0.22, 0.25, '#b8c0c8');
    b.box(x + d * 1.5, y + 0.42, z, 0.35, 0.06, 1.8, '#7a5434'); // bench
    for (const pz of [-0.7, 0.7]) b.box(x + d * 1.5, y + 0.2, z + pz, 0.3, 0.4, 0.06, '#7a5434');
    // a banana bunch hanging from the roof
    for (let k = 0; k < 4; k++) b.ball(x + d * 0.8, y + 2.0 - k * 0.07, z - 0.8 + (k % 2) * 0.08, 0.05, 0.13, 0.05, '#f4d03f', 6);
    out.bulbs.push([x + d * 0.6, y + 2.1, z, 'tea']);
    return [x + d * 1.5, z];
  }

  function fruitCart(b, x, z, side, r, out) {
    const y = KERB_H;
    b.box(x, y + 0.75, z, 1.2, 0.1, 2.2, '#8d5524');
    for (const pz of [-0.7, 0.7]) b.ring(x, y + 0.36, z + pz, 0.34, 0.035, '#1c1922', 12, 0, Math.PI / 2);
    const fruits = ['#ff9f1c', '#9bd36a', '#e63946', '#f4d03f'];
    for (let i = 0; i < 18; i++) {
      const c = fruits[i % 4];
      b.ball(x - 0.4 + (i % 3) * 0.4, y + 0.88 + Math.floor(i / 9) * 0.12, z - 0.8 + (Math.floor(i / 3) % 3) * 0.55, 0.12, 0.11, 0.12, c, 6);
    }
    b.rod([x - 0.55, y + 0.8, z - 1.0], [x - 0.55, y + 1.9, z - 1.0], 0.025, '#5b3a21');
    b.ball(x - 0.55, y + 1.98, z - 1.0, 0.06, 0.08, 0.06, '#ffd98a', 6);
    out.bulbs.push([x - 0.55, y + 1.98, z - 1.0, 'lantern']);
  }

  // Concrete electric pole with crossarms, insulators, sometimes a transformer, a street lamp
  // on an arm over the road and a nest of tangled cable.
  function pole(b, x, z, side, r, lamp, out) {
    const h = 8.6;
    b.cyl(x, h / 2, z, 0.13, h, '#9a9c9f', 6, 0, 0, 0, 0.7, true);
    for (const y of [h - 0.3, h - 0.9]) b.box(x, y, z, 1.5, 0.1, 0.12, '#6d6f75', 0, 0, 0);
    for (const dx of [-0.6, -0.2, 0.2, 0.6]) b.cyl(x + dx, h - 0.2, z, 0.035, 0.12, '#e8e2d6', 6);
    if (r() > 0.65) b.box(x - side * 0.35, 5.6, z, 0.45, 0.8, 0.5, '#7a828c');
    if (r() > 0.3) {
      // the famous tangle
      for (let k = 0; k < 5; k++) {
        b.ring(x + (r() - 0.5) * 0.4, 6.0 + r() * 1.5, z + (r() - 0.5) * 0.3, 0.25 + r() * 0.35, 0.015, '#1c1820', 10, r() * 3, r() * 3, r() * 3);
      }
    }
    if (r() > 0.55) b.box(x - side * 0.14, 2.6, z, 0.02, 0.6, 0.4, ['#d62828', '#ffd23f', '#2a9d4b', '#ffffff'][Math.floor(r() * 4)]);
    if (lamp) {
      const ax = x - side * 1.9; // over the kerb lane
      b.path([[x, 7.2, z], [x - side * 0.8, 7.75, z], [ax, 7.7, z]], 0.045, '#5d6068', 6);
      b.box(ax - side * 0.15, 7.62, z, 0.6, 0.14, 0.28, '#4b4f57');
      b.box(ax - side * 0.15, 7.54, z, 0.45, 0.03, 0.2, '#fff1c1');
      out.lamps.push([ax - side * 0.15, 7.5, z, 'sodium']);
    }
  }

  // ------------------------------------------------------------------ buildings

  // One building whose front faces the road on `side` (-1 left, 1 right), between s and s + w.
  // levels: how many storeys the real building has (from OpenStreetMap), or 0 to make it up.
  function building(ctx, side, s, w, r, levels = 0) {
    const { b, win, sign, ad, shop, glass, out, th, L } = ctx;
    const xb = side < 0 ? L.buildL : L.buildR; // front face
    const dir = -side; // toward the road
    const zc = -(s + w / 2);
    const made = th.floors[0] + Math.floor(r() * (th.floors[1] - th.floors[0] + 1));
    const tower = levels ? levels >= 10 && r() < 0.8 : r() < th.glass;
    const floors = levels ? Math.max(1, Math.min(26, levels - 1)) : made + (tower ? 3 : 0);
    const GF = 3.4, FH = 3.0;
    const H = GF + floors * FH;
    const depth = 10 + r() * 4;
    const pal = tower ? TOWER : th.palette;
    const col = pal[Math.floor(r() * pal.length)];
    const dark = new T.Color(col).multiplyScalar(0.78);
    const roof = new T.Color(col).lerp(new T.Color('#9a958c'), 0.6);
    const top = H - 1.6;
    b.add(window.BT.k3.BOX(), tf(xb - dir * depth / 2, H / 2, zc, 0, 0, 0, depth, H, w), (p, n) => (n.y > 0.5 ? roof : p.y > top ? dark : col));
    // floor bands and the ground-floor surround
    b.box(xb + dir * 0.06, GF, zc, 0.14, 0.18, w, new T.Color(col).multiplyScalar(0.85));
    if (!tower) for (let f = 1; f < floors; f++) b.box(xb + dir * 0.03, GF + f * FH, zc, 0.08, 0.1, w, new T.Color(col).multiplyScalar(0.9));
    // parapet
    b.box(xb + dir * 0.04, H + 0.4, zc, 0.18, 0.8, w, col);
    // ---- ground floor: one or two shops with signboards
    const nShops = w > 7.5 ? 2 : 1;
    const sw = w / nShops;
    for (let k = 0; k < nShops; k++) {
      const z = -(s + sw * (k + 0.5));
      const kind = Math.floor(r() * X.SHOP_KINDS.length);
      shop.quad([xb + dir * 0.02, KERB_H + 1.3, z], [0, 0, (side * (sw - 0.5)) / 2], [0, 1.3, 0], X.shopCell(kind));
      b.box(xb + dir * 0.12, 3.15, z, 0.2, 0.72, sw - 0.3, '#2a2326');
      sign.quad([xb + dir * 0.23, 3.15, z], [0, 0, (side * (sw - 0.42)) / 2], [0, 0.3, 0], X.signCell(Math.floor(r() * X.SIGN_ROWS)));
      if (r() < 0.4) {
        // a sloping tin awning over the shop
        b.box(xb + dir * 0.55, 2.8, z, 1.1, 0.04, sw - 0.4, ['#7d8a99', '#2a6f97', '#c1121f'][Math.floor(r() * 3)], 0, 0, side * 0.18);
      }
      const open = X.SHOP_KINDS[kind].indexOf('shutter') < 0;
      if (open) out.spills.push([xb + dir * 1.2, -0.0, z, sw * 0.6]);
    }
    // ---- upper floors
    if (tower) {
      glass.quad([xb + dir * 0.03, GF + (floors * FH) / 2 + 0.2, zc], [0, 0, (side * (w - 0.6)) / 2], [0, (floors * FH - 0.6) / 2, 0], [0, 0, (w - 0.6) / 2.4, (floors * FH - 0.6) / 3]);
    } else {
      const cols = Math.max(1, Math.floor((w - 0.6) / 1.9));
      const sp = w / cols;
      const balconyFloors = new Set();
      for (let f = 0; f < floors; f++) if (r() < (th.old ? 0.55 : 0.35)) balconyFloors.add(f);
      for (let f = 0; f < floors; f++) {
        const y = GF + f * FH + 1.5;
        for (let c = 0; c < cols; c++) {
          const z = -(s + sp * (c + 0.5));
          const lv = r();
          const light = lv < 0.42 ? 0 : lv < 0.72 ? 1 : lv < 0.9 ? 2 : 3;
          const style = Math.floor(r() * 4);
          win.quad([xb + dir * 0.03, y, z], [0, 0, side * 0.56], [0, 0.66, 0], cell(4, 4, light, style, 0.004));
          if (r() < 0.12 && !balconyFloors.has(f)) b.box(xb + dir * 0.25, y - 0.85, z + 0.4, 0.45, 0.35, 0.7, '#eef0f2'); // AC unit
        }
        if (balconyFloors.has(f)) {
          // balcony: slab, a low wall, plants and the laundry line
          const by = GF + f * FH + 0.08;
          const bw = w * (0.6 + r() * 0.3);
          const bz = -(s + w / 2 + (r() - 0.5) * (w - bw) * 0.5);
          b.box(xb + dir * 0.45, by, bz, 0.9, 0.14, bw, dark);
          b.box(xb + dir * 0.86, by + 0.5, bz, 0.08, 0.86, bw, th.old ? '#3a3036' : col);
          if (th.old) for (let k = 0; k < bw / 0.3; k++) b.box(xb + dir * 0.86, by + 0.5, bz - bw / 2 + k * 0.3, 0.1, 0.9, 0.03, '#2a2228');
          for (let k = 0; k < 2; k++) b.ball(xb + dir * 0.86, by + 1.05, bz - bw / 3 + k * bw * 0.5, 0.16, 0.18, 0.16, '#3a8f3a', 6);
          if (r() < 0.65) {
            for (let k = 0; k < 4; k++) {
              const lz = bz - bw / 2 + 0.4 + k * ((bw - 0.8) / 3);
              b.box(xb + dir * 0.86, by + 0.75, lz, 0.03, 0.5 + r() * 0.25, 0.32, LAUNDRY[Math.floor(r() * LAUNDRY.length)]);
            }
          }
        }
      }
    }
    // ---- roof: water tanks, a stair room, sometimes a billboard facing the oncoming traffic
    const rx = xb - dir * (depth * 0.5);
    for (let k = 0, n = 1 + Math.floor(r() * 2); k < n; k++) {
      const tz = -(s + 1 + r() * (w - 2));
      b.cyl(rx + (r() - 0.5) * 3, H + 0.65, tz, 0.55, 1.3, '#1e1e24', 10);
    }
    if (r() < 0.5) b.box(rx - dir * 1.5, H + 1.3, -(s + w * 0.6), 2.4, 2.6, Math.min(2.6, w * 0.4), new T.Color(col).multiplyScalar(0.92));
    if (r() < 0.1) b.add(window.BT.k3.DOME(10), tf(rx, H + 1.4, -(s + w * 0.3), 1.2, 0, 0, 0.7, 0.35, 0.7), '#e8e8e8');
    if (r() < (tower ? 0.15 : 0.32) && w > 5) {
      const bz = -(s + 0.6);
      const bx = xb - dir * 2.6, bwid = Math.min(5.4, w - 0.4), bh = bwid / 2;
      for (const sx of [-1, 1]) b.box(bx + sx * bwid * 0.35, H + 0.9, bz - 0.3, 0.12, 1.8 + bh, 0.12, '#4a4f57');
      b.box(bx, H + 1.8 + bh / 2, bz - 0.05, bwid + 0.2, bh + 0.2, 0.08, '#e8e8e8');
      ad.quad([bx, H + 1.8 + bh / 2, bz + 0.0], [bwid / 2, 0, 0], [0, bh / 2, 0], X.adCell(Math.floor(r() * X.ADS.length)));
      for (const sx of [-1, 1]) out.lamps.push([bx + sx * bwid * 0.3, H + 2.3 + bh, bz + 0.5, 'flood']);
    }
    // a blade sign sticking out over the footpath, readable down the road
    if (r() < 0.35 && floors > 1) {
      const by = GF + FH * (0.6 + Math.floor(r() * Math.min(2, floors - 1)));
      const bz = -(s + 0.5 + r() * (w - 1));
      const bx = xb + dir * 1.0;
      b.box(xb + dir * 0.5, by + 0.55, bz, 1.0, 0.05, 0.05, '#4a4f57');
      b.box(bx, by, bz, 1.7, 0.85, 0.06, '#e8e8e8');
      const cellUv = X.adCell(Math.floor(r() * X.ADS.length));
      ad.quad([bx, by, bz + 0.035], [0.8, 0, 0], [0, 0.4, 0], cellUv);
      ad.quad([bx, by, bz - 0.035], [-0.8, 0, 0], [0, 0.4, 0], cellUv);
    }
  }

  // ------------------------------------------------------------------ real places

  const ASPHALT = { avenue: '#5c6068', gulshan: '#53565d', puran: '#6a6865', night: '#4d5058' };
  const BOX = () => window.BT.k3.BOX();
  const _rot45 = new T.Matrix4().makeRotationY(Math.PI / 4);
  const _q1 = new T.Quaternion(), _q2 = new T.Quaternion(), _ax = new T.Vector3();

  // A four-sided roof: a pyramid stretched over w (across) × d (along the road), its base at y.
  function roof4(b, x, y, z, w, h, d, c) {
    b.add(window.BT.k3.CYL(4, 0), tf(x, y + h / 2, z, 0, 0, 0, w / Math.SQRT2, h, d / Math.SQRT2).multiply(_rot45), c, true);
  }

  // Domed roof on a drum, with a gold finial.
  function domeAt(b, x, y, z, r, c) {
    b.cyl(x, y + r * 0.2, z, r * 0.95, r * 0.4, new T.Color(c).multiplyScalar(0.9), 16);
    b.dome(x, y + r * 0.4, z, r, r * 1.05, r, c, 16);
    b.cyl(x, y + r * 1.5, z, 0.05, r * 0.4, '#ffd23f', 6);
    b.ball(x, y + r * 1.72, z, 0.12, 0.12, 0.12, '#ffd23f', 6);
  }

  // A petal (a flattened ball) round a centre, at angle a, leaning out by tilt.
  function petal(b, x, y, z, a, tilt, w, h, t, c) {
    _q1.setFromAxisAngle(_ax.set(0, 1, 0), Math.PI / 2 - a);
    _q2.setFromAxisAngle(_ax.set(-Math.sin(a), 0, Math.cos(a)), -tilt).multiply(_q1);
    b.add(window.BT.k3.BALL(10), new T.Matrix4().compose(new T.Vector3(x, y, z), _q2, new T.Vector3(w, h, t)), c);
  }

  // A board with a real name on it, from the route's name atlas. Along the facade of the
  // building on `side`, facing the road, or with across, facing the traffic coming down the
  // road (painted on both faces, in a dark frame).
  function nameBoard(ctx, idx, x, y, z, w, across, side) {
    if (idx == null || !ctx.names) return;
    const uv = ctx.names.cell(idx), h = w / 10;
    if (across) {
      ctx.name.quad([x, y, z + 0.035], [w / 2, 0, 0], [0, h / 2, 0], uv);
      ctx.name.quad([x, y, z - 0.035], [-w / 2, 0, 0], [0, h / 2, 0], uv);
      ctx.b.box(x, y, z, w + 0.12, h + 0.12, 0.06, '#2b2b31');
    } else {
      ctx.name.quad([x, y, z], [0, 0, (side * w) / 2], [0, h / 2, 0], uv);
    }
  }

  // Open ground where OpenStreetMap has no building: a boundary wall with trees behind it.
  function openPlot(ctx, side, it, s, w, r) {
    const { b, L, th } = ctx;
    const xb = side < 0 ? L.buildL : L.buildR, dir = -side;
    const wall = ['#d9d4c7', '#c98a4b', '#e6e2d6', '#b5533c'][Math.floor(hash(Math.round(it.a * 10) + side) * 4)];
    b.box(xb - dir * 0.15, KERB_H + 1.0, -(s + w / 2), 0.3, 2.0, w, wall);
    b.box(xb - dir * 0.15, KERB_H + 2.05, -(s + w / 2), 0.4, 0.12, w, new T.Color(wall).multiplyScalar(0.8));
    b.box(xb - dir * 10, 0.1, -(s + w / 2), 20, 0.2, w, '#6b8f4a');
    for (let k = 0; k < Math.max(1, Math.floor(w / 7)); k++) tree(b, xb - dir * (3 + r() * 7), -(s + 1.5 + r() * Math.max(0.1, w - 3)), r, r() < th.flame);
  }

  // A lake by the road (Gulshan and Banani have them): water behind a railing.
  function waterSide(ctx, side, s, w) {
    const { b, L } = ctx;
    const xb = side < 0 ? L.buildL : L.buildR, dir = -side;
    b.box(xb - dir * 20, 0.02, -(s + w / 2), 40, 0.04, w, '#3f6f8a');
    b.box(xb - dir * 0.1, KERB_H + 0.9, -(s + w / 2), 0.08, 0.06, w, '#d0d4da');
    for (let k = 0; k < w; k += 2) b.box(xb - dir * 0.1, KERB_H + 0.45, -(s + k + 1), 0.06, 0.9, 0.06, '#d0d4da');
  }

  // A side street joining the road: a gap in the buildings with the street running off between
  // blocks, its name on a green sign at the corner, and a zebra crossing where a big one joins.
  function sideStreet(ctx, side, it, r) {
    const { b, L, th } = ctx;
    const { s, w } = it;
    const xb = side < 0 ? L.buildL : L.buildR, dir = -side;
    b.box(xb - dir * 18, 0.01, -s, 36, 0.02, w, ASPHALT[th.road] || ASPHALT.avenue);
    for (let k = 3; k < 34; k += 4) b.box(xb - dir * k, 0.025, -s, 1.6, 0.01, 0.12, '#e8e8e0');
    for (const e of [-1, 1]) {
      const h = 9 + r() * 12;
      b.box(xb - dir * 24, h / 2, -(s + e * (w / 2 + 5)), 24, h, 10, th.palette[Math.floor(r() * th.palette.length)]);
    }
    b.box(xb - dir * 39, 8, -s, 6, 16, w + 2, th.palette[Math.floor(r() * th.palette.length)]);
    if (it.idx != null) {
      const px = side < 0 ? L.kerbL - 0.6 : L.kerbR + KERB + 0.6, pz = -(s - w / 2 - 0.6);
      b.cyl(px, KERB_H + 1.6, pz, 0.05, 3.2, '#5d6068', 6);
      nameBoard(ctx, it.idx, px, KERB_H + 3.2, pz, 2.6, true);
    }
    if (it.zebra) for (let x = -ROAD + 0.7; x < ROAD; x += 1.4) ctx.decal.quad([x, 0.012, -(s - w / 2 - 2.5)], [0.7, 0, 0], [0, 0, -2], X.decalCell(0));
  }

  // A bus stop shelter (যাত্রী ছাউনি) on the footpath, its name along the roof edge.
  function busStop(ctx, side, st, r) {
    const { b, L, th } = ctx;
    const fw = side < 0 ? th.footL : th.footR;
    const x = side < 0 ? L.kerbL - Math.min(1.1, fw / 2) : L.kerbR + KERB + Math.min(1.1, fw / 2);
    const s = st.s;
    b.box(x, KERB_H + 2.5, -s, 1.8, 0.12, 4.2, '#e63946');
    for (const dz of [-1.9, 1.9]) b.box(x + side * 0.7, KERB_H + 1.25, -s + dz, 0.1, 2.5, 0.1, '#9aa1a8');
    b.box(x + side * 0.75, KERB_H + 1.3, -s, 0.05, 1.6, 4.0, '#c9d1da');
    b.box(x + side * 0.4, KERB_H + 0.45, -s, 0.4, 0.08, 3.4, '#7a5434');
    nameBoard(ctx, st.idx, x - side * 0.92, KERB_H + 2.72, -s, 3.6, false, side);
    nameBoard(ctx, st.idx, x, KERB_H + 2.85, -(s - 2.15), 1.7, true);
    for (let q = 0; q < 2; q++) bystander(b, x - side * 0.3, -s - 1 + q * 1.6, r, side < 0 ? 0 : Math.PI);
  }

  // A traffic police box at the kerb.
  function booth(ctx, side, st) {
    const { b, L, th } = ctx;
    const fw = side < 0 ? th.footL : th.footR;
    const x = side < 0 ? L.kerbL - Math.min(1.0, fw / 2) : L.kerbR + KERB + Math.min(1.0, fw / 2);
    const s = st.s;
    b.box(x, KERB_H + 1.2, -s, 1.6, 2.4, 1.6, '#f4f1ea');
    b.box(x, KERB_H + 1.55, -s, 1.66, 0.8, 1.66, '#4f7da0');
    b.box(x, KERB_H + 2.55, -s, 2.0, 0.3, 2.0, '#1d4e89');
    b.cyl(x, KERB_H + 2.85, -s, 0.12, 0.3, '#d62828', 8);
    nameBoard(ctx, st.idx, x, KERB_H + 2.1, -(s - 0.86), 1.5, true);
    ctx.out.bulbs.push([x, KERB_H + 3.0, -s, 'led']);
  }

  // Monuments, by what they are: the water lily of শাপলা চত্বর, a fountain, a শহীদ মিনার, or a column.
  function monument(b, x, z, name) {
    b.cyl(x, 0.2, z, 5.5, 0.4, '#d9d4c7', 24);
    if (/শাপলা|shapla/i.test(name)) {
      b.cyl(x, 0.45, z, 4.8, 0.3, '#3f7f9a', 24);
      b.cyl(x, 1.4, z, 0.9, 2.0, '#e8e4dc', 12);
      for (let ring = 0; ring < 2; ring++) {
        for (let k = 0; k < 8; k++) {
          const a = (k / 8) * TAU + ring * 0.4, d = ring ? 0.9 : 1.7;
          petal(b, x + Math.cos(a) * d, 3.2 + ring * 0.45, z + Math.sin(a) * d, a, ring ? 0.35 : 0.8, 0.6, 1.6 - ring * 0.35, 0.22, ring ? '#fff3f6' : '#f8f6f0');
        }
      }
      b.ball(x, 3.5, z, 0.55, 0.45, 0.55, '#ffd23f', 10);
      return;
    }
    if (/ফোয়ারা|fountain/i.test(name)) {
      b.cyl(x, 0.45, z, 4.8, 0.3, '#3f7f9a', 24);
      for (let k = 0; k < 3; k++) {
        b.cyl(x, 1.2 + k * 1.6, z, 0.35, 1.6, '#e8e4dc', 10);
        b.cyl(x, 2.0 + k * 1.6, z, 2.6 - k * 0.8, 0.25, '#d9d4c7', 20, 0, 0, 0, 1.15);
        b.cyl(x, 2.2 + k * 1.6, z, 2.4 - k * 0.8, 0.06, '#7fb3d5', 20);
      }
      b.ball(x, 6.1, z, 0.3, 0.6, 0.3, '#cfe0f2', 8);
      return;
    }
    if (/মিনার|minar/i.test(name)) {
      // tall white frames, the middle one bowing forward, and the red sun behind them
      b.box(x, 0.9, z, 7, 1.0, 9, '#e8e4dc');
      b.cyl(x - 1.6, 6.0, z, 2.6, 0.2, '#d62828', 24, 0, 0, Math.PI / 2);
      const frame = (dz, h, bow) => {
        for (const dw of [-0.55, 0.55]) b.box(x - 0.6, 1.4 + h / 2, z + dz + dw, 0.25, h, 0.25, '#f8f6f0');
        b.box(x - 0.6, 1.4 + h, z + dz, 0.25, 0.25, 1.35, '#f8f6f0');
        if (bow) b.box(x + 0.1, 1.4 + h + 0.45, z + dz, 1.5, 0.25, 1.35, '#f8f6f0', 0, 0, -0.6);
      };
      frame(0, 7.5, true);
      for (const dz of [-1.8, 1.8]) frame(dz, 5.5, false);
      for (const dz of [-3.3, 3.3]) frame(dz, 4.2, false);
      return;
    }
    b.cyl(x, 4.5, z, 0.7, 8, '#d9d4c7', 8, 0, 0, 0, 0.55);
    b.cyl(x, 0.9, z, 1.5, 1.0, '#b9b4ab', 8);
  }

  // A landmark from OpenStreetMap: a building of its kind with its real name on it, over the
  // stretch it.s ± it.len / 2 of its side of the road.
  function landmark(ctx, side, it, r) {
    const { b, out, L } = ctx;
    const { s, len, kind, idx } = it;
    const name = it.name.normalize('NFC'); // য় and ড় come both ways in the map data
    const xb = side < 0 ? L.buildL : L.buildR, dir = -side;
    const s0 = s - len / 2, z = -s;
    const board = (y, w, back = 0) => nameBoard(ctx, idx, xb - dir * (back - 0.06), y, z, Math.min(len - 2, w || 9), false, side);
    const blade = (y) => {
      b.box(xb + dir * 0.8, y + 0.42, -(s0 + 0.8), 1.6, 0.05, 0.05, '#4a4f57');
      nameBoard(ctx, idx, xb + dir * 1.7, y, -(s0 + 0.8), 3.2, true);
    };
    const block = (h, depth, col, roof, back = 0) => b.add(BOX(), tf(xb - dir * (back + depth / 2), h / 2, z, 0, 0, 0, depth, h, len), (p, n) => (n.y > 0.5 ? roof || '#9a958c' : col));
    // a grid of windows (lit at night like the other buildings)
    const windows = (y0, h, back = 0, from = 0) => {
      for (let y = y0; y < h - 1.2; y += 3) {
        for (let k = 1 + from; k < len / 2.2 - from; k++) {
          const v = r();
          ctx.win.quad([xb - dir * (back - 0.03), y, -(s0 + k * 2.2)], [0, 0, side * 0.56], [0, 0.66, 0], cell(4, 4, v < 0.45 ? 0 : 1 + Math.floor(r() * 3), Math.floor(r() * 4), 0.004));
        }
      }
    };
    // a boundary wall along the building line with a gate in the middle, the name over the gate
    const gateWall = (col) => {
      for (const e of [-1, 1]) b.box(xb - dir * 0.15, KERB_H + 1.0, -(s + e * (len / 4 + 1.2)), 0.3, 2.0, len / 2 - 2.4, col);
      for (const e of [-1, 1]) b.box(xb - dir * 0.15, KERB_H + 1.6, -(s + e * 2.2), 0.5, 3.2, 0.5, col);
      b.box(xb - dir * 0.15, KERB_H + 3.25, z, 0.4, 0.3, 4.9, col);
      nameBoard(ctx, idx, xb + dir * 0.08, KERB_H + 3.7, z, 4.6, false, side);
    };
    switch (kind) {
      case 'mosque': {
        block(7.5, 13, '#f1ead8', '#d9d0bc');
        for (let k = 1; k < len / 2.6; k++) {
          b.box(xb + dir * 0.03, 3.4, -(s0 + k * 2.6), 0.06, 2.6, 1.2, '#2b5e3b');
          b.dome(xb + dir * 0.03, 4.7, -(s0 + k * 2.6), 0.06, 0.5, 0.6, '#2b5e3b', 8);
        }
        b.box(xb + dir * 0.05, 7.2, z, 0.12, 0.5, len, '#2a9d4b');
        domeAt(b, xb - dir * 6.5, 7.5, z, 3.6, '#2a9d4b');
        domeAt(b, xb - dir * 2.5, 7.5, z - len / 2 + 2.5, 1.3, '#f1ead8');
        // the minaret at the corner nearest the traffic
        const mx = xb - dir * 1.2, mz = -(s0 + 1.2);
        b.cyl(mx, 10, mz, 0.75, 20, '#f1ead8', 10);
        for (const y of [9, 15]) b.cyl(mx, y, mz, 1.05, 0.35, '#2a9d4b', 10);
        domeAt(b, mx, 20, mz, 0.8, '#2a9d4b');
        board(5.9);
        out.bulbs.push([mx, 21.3, mz, 'led']);
        break;
      }
      case 'temple':
        block(6, 10, '#f4a261', '#c1121f');
        for (let k = 0; k < 4; k++) b.cyl(xb - dir * 5, 7.1 + k * 2.2, z, 3.2 - k * 0.7, 2.2, k % 2 ? '#e76f51' : '#f4a261', 4, 0, Math.PI / 4, 0, 0.8);
        b.cyl(xb - dir * 5, 15.6, z, 0.25, 1.4, '#ffd23f', 6, 0, 0, 0, 0.2);
        board(4.4);
        break;
      case 'church': {
        block(8, 14, '#f4f1ea', '#8c1239');
        roof4(b, xb - dir * 7, 8, z, 14, 3.4, len, '#8c1239');
        for (let k = 1; k < len / 2.5; k++) {
          b.box(xb + dir * 0.03, 4, -(s0 + 1.5 + k * 2.5), 0.06, 3.0, 0.8, '#5b6d8f');
          b.dome(xb + dir * 0.03, 5.5, -(s0 + 1.5 + k * 2.5), 0.06, 0.4, 0.4, '#5b6d8f', 8);
        }
        const tx = xb - dir * 1.8, tz = -(s0 + 2);
        b.box(tx, 8, tz, 3, 16, 3, '#f4f1ea');
        roof4(b, tx, 16, tz, 3.2, 3.4, 3.2, '#8c1239');
        b.box(tx, 20.1, tz, 0.12, 1.4, 0.12, '#ffd23f');
        b.box(tx, 20.3, tz, 0.8, 0.12, 0.12, '#ffd23f');
        board(6.6);
        break;
      }
      case 'heritage':
        if (/কাটরা|katra/i.test(name)) {
          // an old caravanserai gateway: two towers and the arch between
          for (const e of [-1, 1]) b.box(xb - dir * 4, 7, z + e * 3.4, 7, 14, 3.6, '#b5533c');
          for (const e of [-1, 1]) for (let y = 3; y < 13; y += 3.2) b.box(xb + dir * 0.03, y, z + e * 3.4, 0.06, 1.4, 0.8, '#3b3438');
          b.box(xb - dir * 4, 11.6, z, 7, 4.8, 3.2, '#b5533c');
          b.box(xb + dir * 0.03, 4.8, z, 0.08, 7.2, 2.6, '#3b3438');
          b.dome(xb + dir * 0.03, 8.4, z, 0.08, 1.2, 1.3, '#3b3438', 10);
          for (let k = 0; k < len / 2.6; k++) if (Math.abs(s0 + 1.3 + k * 2.6 - s) > 5.5) b.box(xb - dir * 5, 4, -(s0 + 1.3 + k * 2.6), 10, 8, 2.4, '#a7745a');
          board(13.2, 6);
        } else if (/আহসান|ahsan|মঞ্জিল|manzil/i.test(name)) {
          // the pink palace with its great dome, set back behind a lawn and railings
          b.box(xb - dir * 3, 0.06, z, 6, 0.12, len, '#6b9b4a');
          for (let k = 0; k <= len; k += 1.5) b.box(xb - dir * 0.1, KERB_H + 0.6, -(s0 + k), 0.06, 1.2, 0.06, '#3b3438');
          b.box(xb - dir * 0.1, KERB_H + 1.15, z, 0.06, 0.06, len, '#3b3438');
          block(12, 16, '#e48b9b', '#c9677a', 6);
          for (let y = 4.6; y < 11; y += 3.6) for (let k = 1; k < len / 2.4; k++) b.box(xb - dir * 5.97, y, -(s0 + k * 2.4), 0.06, 1.8, 1.0, '#f8f2ea');
          b.box(xb - dir * 13, 16, z, 8, 8, 8, '#e48b9b');
          domeAt(b, xb - dir * 13, 20, z, 4.2, '#b8606f');
          for (let k = 0; k < 6; k++) b.cyl(xb - dir * 5.4, 4.2, z + (k - 2.5) * 1.6, 0.3, 8.4, '#f8f2ea', 10);
          b.box(xb - dir * 5.4, 8.7, z, 1.2, 0.6, 9.6, '#f8f2ea');
          roof4(b, xb - dir * 5.4, 9.0, z, 1.4, 1.6, 9.6, '#f8f2ea');
          board(KERB_H + 1.9, 9, 0);
        } else {
          // an old colonial building: red brick, white arches and a balustrade
          block(11, 14, '#b5533c', '#8f3f2c');
          for (let y = 1.6; y < 10; y += 4.2) {
            for (let k = 1; k < len / 2.6; k++) {
              b.box(xb + dir * 0.03, y + 1.2, -(s0 + k * 2.6), 0.06, 2.4, 1.6, '#f4efe1');
              b.box(xb + dir * 0.05, y + 1.1, -(s0 + k * 2.6), 0.06, 2.0, 1.1, '#3b3438');
            }
          }
          b.box(xb + dir * 0.1, 11.4, z, 0.3, 0.8, len, '#f4efe1');
          board(6.5, 10);
        }
        break;
      case 'market':
        block(14 + Math.floor(r() * 3) * 3, 16, ['#f4efe1', '#e9c46a', '#cdb4db'][Math.floor(r() * 3)]);
        windows(5.9, 16);
        for (let k = 0; k < len / 4.5 - 1; k++) {
          const sz = -(s0 + 2.25 + k * 4.5);
          ctx.shop.quad([xb + dir * 0.02, KERB_H + 1.3, sz], [0, 0, side * 2], [0, 1.3, 0], X.shopCell(Math.floor(r() * X.SHOP_KINDS.length)));
          ctx.sign.quad([xb + dir * 0.1, 3.1, sz], [0, 0, side * 2], [0, 0.3, 0], X.signCell(Math.floor(r() * X.SIGN_ROWS)));
        }
        board(4.4, 12);
        blade(9);
        break;
      case 'hospital':
        block(18, 16, '#f8f8f6', '#c9d1da');
        windows(5.9, 18);
        board(4.4, 10);
        blade(10);
        b.box(xb + dir * 0.04, 15.5, -(s0 + 2), 0.06, 1.6, 0.5, '#d62828');
        b.box(xb + dir * 0.04, 15.5, -(s0 + 2), 0.06, 0.5, 1.6, '#d62828');
        break;
      case 'school':
        gateWall('#f4efe1');
        block(12, 14, '#b5533c', '#8f3f2c', 4);
        windows(4.6, 12, 4);
        break;
      case 'cinema':
        block(13, 16, '#2b2b31', '#1b1b1f');
        ctx.ad.quad([xb + dir * 0.06, 8.5, z], [0, 0, side * Math.min(5.5, len / 2 - 1)], [0, 2.75, 0], X.adCell(Math.floor(r() * X.ADS.length)));
        board(4.4, 10);
        blade(12);
        out.lamps.push([xb + dir * 1, 12, z, 'flood']);
        break;
      case 'terminal':
        // a long shed with a blue roof (a ghat or a bus terminal); at a ghat, a launch moored behind
        for (let k = 0; k <= len; k += 4) b.box(xb - dir * 1, 2.5, -(s0 + k), 0.2, 5, 0.2, '#9aa1a8');
        for (let k = 0; k <= len; k += 4) b.box(xb - dir * 9, 2.5, -(s0 + k), 0.2, 5, 0.2, '#9aa1a8');
        b.box(xb - dir * 5, 5.1, z, 10.4, 0.3, len, '#1d4e89');
        b.box(xb - dir * 5, 0.1, z, 10, 0.2, len, '#b9b4ab');
        if (/ঘাট|ghat|সদর|launch|লঞ্চ/i.test(name)) {
          for (let d = 0; d < 3; d++) b.box(xb - dir * 17, 1.5 + d * 2.2, z, 7 - d, 2.2, len - 2 - d * 3, d % 2 ? '#f4efe1' : '#2a9d8f');
          b.cyl(xb - dir * 17, 8.4, -(s0 + len * 0.35), 0.4, 2, '#d62828', 8);
          b.box(xb - dir * 26, 0.02, z, 26, 0.04, len + 20, '#5d7f8f');
        } else {
          for (let k = 0; k < 2; k++) b.box(xb - dir * (4 + k * 3.2), 1.7, z + (k - 0.5) * 6, 2.6, 3.2, 10, ['#d62839', '#2a9d4b'][k]);
        }
        board(6.0, 12);
        blade(6.5);
        break;
      case 'rail':
        // Kamalapur's famous roof: rows of concrete umbrellas
        for (let row = 0; row < 2; row++) {
          for (let k = 0; k < len / 9; k++) {
            const ux = xb - dir * (5 + row * 9), uz = -(s0 + 4.5 + k * 9);
            b.cyl(ux, 3.8, uz, 0.45, 7.6, '#d9d4c7', 10);
            b.cyl(ux, 8.4, uz, 0.6, 1.8, '#e8e4dc', 16, 0, 0, 0, 8);
          }
        }
        b.box(xb - dir * 12, 2, z, 18, 4, len, '#c9c4ba');
        board(4.6, 14);
        blade(7);
        break;
      case 'civic': {
        block(14, 14, '#f4f1ea', '#c9c4ba');
        windows(5.9, 14);
        for (let k = 0; k < len / 3; k++) b.cyl(xb + dir * 1.2, 2.9, -(s0 + 1.5 + k * 3), 0.25, 5.8, '#ffffff', 8);
        b.box(xb + dir * 1.2, 5.95, z, 0.9, 0.3, len, '#ffffff');
        // the national flag, on the footpath however narrow it is
        const fx = xb + dir * Math.min(2.5, (side < 0 ? ctx.th.footL : ctx.th.footR) - 0.4);
        b.cyl(fx, KERB_H + 4.5, -(s0 + 1), 0.05, 9, '#c9d1da', 6);
        b.box(fx, KERB_H + 8.2, -(s0 + 1.95), 0.04, 1.2, 1.9, '#006a4e');
        b.cyl(fx, KERB_H + 8.2, -(s0 + 1.8), 0.4, 0.08, '#f42a41', 16, 0, 0, Math.PI / 2);
        board(4.4, 10);
        break;
      }
      case 'park':
        b.box(xb - dir * 10, 0.12, z, 20, 0.24, len, '#5f8f3e');
        for (let k = 0; k <= len; k += 2) b.box(xb - dir * 0.1, KERB_H + 0.45, -(s0 + k), 0.06, 0.9, 0.06, '#2a9d4b');
        b.box(xb - dir * 0.1, KERB_H + 0.85, z, 0.06, 0.06, len, '#2a9d4b');
        for (let k = 0; k < len / 6; k++) tree(b, xb - dir * (3 + r() * 10), -(s0 + 3 + k * 6), r, r() < 0.4);
        b.cyl(xb + dir * 0.3, KERB_H + 1.3, -(s0 + 2), 0.05, 2.6, '#5d6068', 6);
        nameBoard(ctx, idx, xb + dir * 0.3, KERB_H + 2.7, -(s0 + 2), 3.4, true);
        break;
      case 'monument':
        monument(b, xb - dir * 7, z, name);
        b.box(xb + dir * 0.4, KERB_H + 0.75, -(s0 + 1.5), 0.15, 1.5, 0.15, '#5d6068');
        nameBoard(ctx, idx, xb + dir * 0.4, KERB_H + 1.7, -(s0 + 1.5), 3.4, true);
        break;
    }
  }

  // An elevated metro station over the road at s: the concourse spans the street, the platform
  // hall sits on the viaduct, and the station's name faces the traffic both ways.
  function metroStation(ctx, st) {
    const { b, out, L, th } = ctx;
    const s = st.s, len = 40, mx = (L.median0 != null ? L.median0 : ROAD) + 0.6 + 0.6;
    const x0 = L.kerbL - 1.4, x1 = th.median ? L.kerbR + KERB + 1.4 : L.buildR - 0.6, cx = (x0 + x1) / 2, w = x1 - x0;
    b.box(cx, 9.4, -s, w, 2.8, len * 0.6, '#e4e1da');
    b.box(cx, 9.6, -s, w + 0.1, 1.1, len * 0.6 - 1, '#4f7da0');
    b.box(mx, 15.4, -s, 14, 5.6, len, '#e4e1da');
    b.box(mx, 15.6, -s, 14.1, 2.2, len - 1.5, '#4f7da0');
    b.box(mx, 18.45, -s, 15, 0.5, len + 1, '#c9c6bf');
    for (const px of [x0 + 0.7, mx, x1 - 0.7]) for (const e of [-1, 1]) b.cyl(px, 4.0, -s + e * (len * 0.3 - 1.5), 0.55, 8, '#c9c6bf', 10);
    for (const e of [-1, 1]) {
      nameBoard(ctx, st.idx, mx, 17.3, -s + e * (len / 2 + 0.06), 9, true);
      nameBoard(ctx, st.idx, cx, 9.6, -s + e * (len * 0.3 + 0.06), Math.min(9, w - 1), true);
    }
    // stairs down to the left footpath
    b.box(L.kerbL - 1.6, 4.0, -(s - len * 0.3 - 4.2), 1.6, 0.3, 10.5, '#c9c6bf', Math.atan2(8, 10), 0, 0);
    out.lamps.push([cx - w / 3, 7.9, -s, 'led'], [cx + w / 3, 7.9, -s, 'led']);
  }

  // An overhead sign with the name of the street the race has turned onto.
  function gantry(ctx, g) {
    const { b, L, th } = ctx;
    const x0 = L.kerbL - 0.5, x1 = th.median ? L.median0 + 0.6 : L.kerbR + KERB + 0.5;
    for (const x of [x0, x1]) b.cyl(x, 3.5, -g.s, 0.12, 7, '#7d8187', 8);
    b.box((x0 + x1) / 2, 6.85, -g.s, x1 - x0 + 0.3, 0.2, 0.2, '#7d8187');
    for (const x of [-2.6, 2.6]) b.box(x, 6.62, -g.s, 0.06, 0.3, 0.06, '#7d8187');
    nameBoard(ctx, g.idx, 0, 6.05, -g.s, 7.6, true);
  }

  // ------------------------------------------------------------------ the route's plan

  const MARK_LEN = { mosque: 16, temple: 12, church: 14, heritage: 22, market: 18, hospital: 16, school: 18, cinema: 14, civic: 16, park: 22, terminal: 22, monument: 16, rail: 30 };
  const MARK_RANK = ['rail', 'heritage', 'terminal', 'monument', 'mosque', 'temple', 'church', 'hospital', 'civic', 'park', 'market', 'school', 'cinema'];

  /* Where the real places go along the route: side streets, landmarks, lakes and open ground
   * take their stretch of each side (items, sorted), so the made-up buildings fill only what
   * is left; side street mouths and bus stops keep their bit of footpath clear (foot); the
   * median opens at big crossings (gaps). len is the race length in metres. */
  function makePlan(osm, len) {
    const P = { items: { '-1': [], 1: [] }, foot: { '-1': [], 1: [] }, mouths: { '-1': [], 1: [] }, gaps: [], stops: [], booths: [], stations: [], gantries: [], bridges: [], metro: [], entries: [] };
    const atlas = new Map();
    const nameOf = (kind, text) => {
      if (!text) return null;
      const key = kind + '|' + text;
      if (!atlas.has(key)) {
        if (P.entries.length >= X.NAMES_MAX) return null;
        atlas.set(key, P.entries.length);
        P.entries.push([kind, text]);
      }
      return atlas.get(key);
    };
    const sides = (c) => (c === 'B' ? [-1, 1] : [c === 'L' ? -1 : 1]);
    const clear = (side, a, b) => P.items[side].every((it) => it.b <= a || it.a >= b);
    // the streets the route runs along, named on overhead signs as the race turns onto them
    for (const [s, name] of osm.streets) P.gantries.push({ s: s < 1 ? 30 : s + 14, idx: nameOf('street', name) });
    // side streets are where they are
    for (const [s, sd, cls, name] of osm.cross) {
      const w = cls >= 4 ? 10 : 8, idx = nameOf('street', name);
      sides(sd).forEach((side, k) => {
        P.items[side].push({ type: 'cross', a: s - w / 2 - 0.5, b: s + w / 2 + 0.5, s, w, cls, idx, zebra: k === 0 && cls >= 3 });
        P.foot[side].push([s - w / 2, s + w / 2]);
        P.mouths[side].push([s - w / 2, s + w / 2]);
      });
      if (sd === 'B' && cls >= 3) P.gaps.push([s - w / 2, s + w / 2]);
    }
    for (const [a, b, sd] of osm.water) for (const side of sides(sd)) P.items[side].push({ type: 'water', a, b });
    // landmarks, the grandest first, each as near its real spot as the street allows
    const done = [];
    const marks = osm.marks.slice().sort((p, q) => MARK_RANK.indexOf(p[2]) - MARK_RANK.indexOf(q[2]));
    for (const [s, sd, kind, name] of marks) {
      const side = sd === 'L' ? -1 : 1;
      // the same station or terminal mapped twice; for the rest, two of a kind side by side
      const far = kind === 'metro' || kind === 'rail' || kind === 'terminal' ? 60 : 10;
      if (done.some((m) => m.kind === kind && (far > 10 || m.side === side) && Math.abs(m.s - s) < far)) continue;
      const footClear = (a, b) => P.foot[side].every(([p, q]) => q <= a || p >= b);
      if (kind === 'metro') {
        P.stations.push({ s, idx: nameOf('metro', name) });
      } else if (kind === 'busstop' || (kind === 'civic' && /box|বক্স/i.test(name))) {
        if (!footClear(s - 3, s + 3)) continue;
        (kind === 'busstop' ? P.stops : P.booths).push({ s, side, idx: nameOf(kind === 'busstop' ? 'busstop' : 'civic', name) });
        P.foot[side].push([s - 2.6, s + 2.6]);
      } else {
        // full size if there is room near the real spot, else a smaller version
        const full = MARK_LEN[kind] || 16;
        let at = null, l = full;
        for (const f of [1, 0.75, 0.6]) {
          l = Math.round(full * f);
          for (let d = 0; d <= full && at == null; d += 2) for (const e of d ? [1, -1] : [1]) if (at == null && clear(side, s + e * d - l / 2, s + e * d + l / 2)) at = s + e * d;
          if (at != null) break;
        }
        if (at == null) continue;
        P.items[side].push({ type: 'mark', a: at - l / 2, b: at + l / 2, s: at, len: l, kind, name, idx: nameOf(kind, name) });
      }
      done.push({ kind, s, side });
    }
    // open ground (no building on the map for 8 m or more) in what is still free
    for (const side of [-1, 1]) {
      for (const [a, b, lv] of osm[side < 0 ? 'left' : 'right']) {
        if (lv !== -1 || b - a < 8) continue;
        let pieces = [[a, b]];
        for (const it of P.items[side]) pieces = pieces.flatMap(([p, q]) => (it.b <= p || it.a >= q ? [[p, q]] : [[p, it.a], [it.b, q]].filter(([u, v]) => v - u > 0.5)));
        for (const [p, q] of pieces) if (q - p >= 6) P.items[side].push({ type: 'open', a: p, b: q });
      }
      P.items[side].sort((p, q) => p.a - q.a);
      P.foot[side].sort((p, q) => p[0] - q[0]);
      P.mouths[side].sort((p, q) => p[0] - q[0]);
    }
    // the metro: viaduct stretches, carried on past the ends of the race and through each station
    for (const [a, b] of osm.metro) P.metro.push([a < 40 ? -400 : a, b > len - 40 ? len + 600 : b]);
    for (const st of P.stations) {
      const near = P.metro.find(([a, b]) => st.s > a - 60 && st.s < b + 60);
      if (near) {
        near[0] = Math.min(near[0], st.s - 22);
        near[1] = Math.max(near[1], st.s + 22);
      } else P.metro.push([st.s - 22, st.s + 22]);
    }
    // footbridges, clear of the stations and the overhead signs
    for (const s of osm.bridges) if (!P.stations.some((st) => Math.abs(st.s - s) < 26)) P.bridges.push(s);
    for (const g of P.gantries) if (P.bridges.some((s) => Math.abs(s - g.s) < 8) || P.stations.some((st) => Math.abs(st.s - g.s) < 26)) g.s += 16;
    return P;
  }

  // Storeys of the real building at s on a side (0 when the map doesn't say).
  function levelsAt(osm, side, s) {
    if (!osm) return 0;
    for (const [a, b, lv] of osm[side < 0 ? 'left' : 'right']) if (s >= a && s < b) return lv > 0 ? lv : 0;
    return 0;
  }

  // ------------------------------------------------------------------ bending

  /* Cuts a builder's triangles across the road at the path's cut marks (closer together where
   * the road bends), so that bending curves long faces instead of turning them into chords
   * that windows and signs would sink behind. Triangles that cross no mark are kept whole. */
  function slice(b, cuts) {
    if (!cuts || !cuts.length || !b.count) return;
    const P = b.p, N = b.n, C = b.c, O = b.o, U = b.u;
    const nc = cuts.length;
    // index of the first cut above s
    const above = (s) => {
      let lo = 0, hi = nc;
      while (lo < hi) {
        const m = (lo + hi) >> 1;
        if (cuts[m] <= s) lo = m + 1;
        else hi = m;
      }
      return lo;
    };
    let any = false;
    for (let t = 0; t < P.length && !any; t += 9) {
      const s0 = -Math.max(P[t + 2], P[t + 5], P[t + 8]), s1 = -Math.min(P[t + 2], P[t + 5], P[t + 8]);
      const i = above(s0);
      any = i < nc && cuts[i] < s1;
    }
    if (!any) return;
    const p = [], n = [], c = [], o = [], u = U ? [] : null;
    const copy = (i) => {
      p.push(P[i * 3], P[i * 3 + 1], P[i * 3 + 2]);
      n.push(N[i * 3], N[i * 3 + 1], N[i * 3 + 2]);
      c.push(C[i * 3], C[i * 3 + 1], C[i * 3 + 2]);
      o.push(O[i]);
      if (u) u.push(U[i * 2], U[i * 2 + 1]);
    };
    const V = (i) => [P[i * 3], P[i * 3 + 1], P[i * 3 + 2], N[i * 3], N[i * 3 + 1], N[i * 3 + 2], C[i * 3], C[i * 3 + 1], C[i * 3 + 2], O[i], U ? U[i * 2] : 0, U ? U[i * 2 + 1] : 0];
    const emit = (v) => {
      p.push(v[0], v[1], v[2]);
      n.push(v[3], v[4], v[5]);
      c.push(v[6], v[7], v[8]);
      o.push(v[9]);
      if (u) u.push(v[10], v[11]);
    };
    const mixV = (a, q, k) => a.map((x, j) => x + (q[j] - x) * k);
    // the part of a polygon on one side of the cut at s (keep: +1 for s ≥ cut, -1 for s ≤ cut)
    const clip = (poly, cut, keep) => {
      const res = [];
      for (let k = 0; k < poly.length; k++) {
        const a = poly[k], q = poly[(k + 1) % poly.length];
        const da = keep * (-a[2] - cut), dq = keep * (-q[2] - cut);
        if (da >= 0) res.push(a);
        if ((da >= 0) !== (dq >= 0)) res.push(mixV(a, q, da / (da - dq)));
      }
      return res;
    };
    for (let t = 0; t < P.length / 3; t += 3) {
      const z0 = P[t * 3 + 2], z1 = P[t * 3 + 5], z2 = P[t * 3 + 8];
      const s0 = -Math.max(z0, z1, z2), s1 = -Math.min(z0, z1, z2);
      let i = above(s0);
      if (!(i < nc && cuts[i] < s1)) {
        copy(t);
        copy(t + 1);
        copy(t + 2);
        continue;
      }
      let rest = [V(t), V(t + 1), V(t + 2)];
      for (; i < nc && cuts[i] < s1; i++) {
        const piece = clip(rest, cuts[i], -1);
        rest = clip(rest, cuts[i], 1);
        for (let k = 1; k + 1 < piece.length; k++) {
          emit(piece[0]);
          emit(piece[k]);
          emit(piece[k + 1]);
        }
      }
      for (let k = 1; k + 1 < rest.length; k++) {
        emit(rest[0]);
        emit(rest[k]);
        emit(rest[k + 1]);
      }
    }
    b.p = p;
    b.n = n;
    b.c = c;
    b.o = o;
    if (u) b.u = u;
  }

  // ------------------------------------------------------------------ chunks

  function wiresBetween(pos, side, x, sA, sB, idA) {
    const n = 8 + Math.floor(hash(idA * 3 + 1) * 6);
    for (let k = 0; k < n; k++) {
      const hA = 6.4 + hash(idA * 41 + k) * 1.9, hB = 6.4 + hash((idA + 1) * 41 + k) * 1.9;
      const xA = x + (hash(idA * 17 + k) - 0.5) * 1.3, xB = x + (hash((idA + 1) * 17 + k) - 0.5) * 1.3;
      const sag = 0.3 + hash(idA * 59 + k) * 1.1;
      let px = xA, py = hA, pz = -sA;
      for (let i = 1; i <= 8; i++) {
        const t = i / 8;
        const nx = xA + (xB - xA) * t, ny = hA + (hB - hA) * t - sag * 4 * t * (1 - t), nz = -(sA + (sB - sA) * t);
        pos.push(px, py, pz, nx, ny, nz);
        px = nx;
        py = ny;
        pz = nz;
      }
    }
  }

  // The parts of [a, b] not covered by the (sorted) intervals.
  function without(a, b, cuts) {
    const out = [];
    let s = a;
    for (const [p, q] of cuts) {
      if (q <= s) continue;
      if (p >= b) break;
      if (p > s) out.push([s, p]);
      s = Math.max(s, q);
    }
    if (s < b) out.push([s, b]);
    return out;
  }
  const inside = (s, list, pad = 0) => list.some(([a, b]) => s > a - pad && s < b + pad);

  // Buildings down one side of [a, b]: made-up widths, and the real building's height where the
  // map knows it.
  function fillRun(ctx, side, a, c, r) {
    const { th, L, osm } = ctx;
    let s = a;
    while (s < c - 0.3) {
      if (c - s < 2.2 || (r() < th.alley && c - s > 6)) {
        // a narrow alley: dark gap with a glimpse of the next building back
        const aw = c - s < 2.2 ? c - s : 1.0 + r() * 0.6;
        const xb = side < 0 ? L.buildL : L.buildR;
        ctx.b.box(xb + side * 6, 3, -(s + aw / 2), 0.4, 6, aw, '#3b3438');
        s += aw;
        continue;
      }
      let w = th.bw[0] + r() * (th.bw[1] - th.bw[0]);
      if (s + w > c - 2.5) w = c - s;
      building(ctx, side, s, w, r, levelsAt(osm, side, s + w / 2));
      s += w;
    }
  }

  // The ground of [s0, s1]: the road (and the oncoming lanes), the footpaths and kerbs (cut open
  // where side streets join), the median (open at big crossings), all tiled by distance so the
  // textures run on from chunk to chunk.
  function ground(ctx, s0, s1, plan) {
    const { th, L, b } = ctx;
    const strip = (bld, x0, x1, y, a, c, uw, ul) => bld.quad([(x0 + x1) / 2, y, -(a + c) / 2], [(x1 - x0) / 2, 0, 0], [0, 0, -(c - a) / 2], [0, a / ul, uw, c / ul]);
    const asphalt = ASPHALT[th.road] || ASPHALT.avenue;
    strip(ctx.road, -ROAD, ROAD, 0, s0, s1, 1, 16.8);
    if (th.median) strip(ctx.road, L.median1, L.kerbR, 0, s0, s1, th.oncoming / 8.4, 16.8);
    // a kerb: top and the face toward the road (fx: +1 faces +x), and end caps where it stops
    const kerbAt = (x0, x1, h, fx, a, c) => {
      ctx.kerb.quad([(x0 + x1) / 2, h, -(a + c) / 2], [(x1 - x0) / 2, 0, 0], [0, 0, -(c - a) / 2], [0, a, 1, c]);
      ctx.kerb.quad([fx > 0 ? x1 : x0, h / 2, -(a + c) / 2], [0, 0, (-fx * (c - a)) / 2], [0, h / 2, 0], [a, 0, c, 1]);
    };
    const cap = (x0, x1, h, s, dir, col) => b.quad([(x0 + x1) / 2, h / 2, -s], [(dir * (x1 - x0)) / 2, 0, 0], [0, h / 2, 0], null, col);
    for (const side of [-1, 1]) {
      const mouths = plan ? plan.mouths[side] : [];
      const fx0 = side < 0 ? L.buildL - 0.5 : L.kerbR + KERB, fx1 = side < 0 ? L.kerbL : L.buildR + 0.5;
      const kx0 = side < 0 ? L.kerbL : L.kerbR, kx1 = kx0 + KERB;
      for (const [a, c] of without(s0, s1, mouths)) {
        strip(ctx.foot, fx0, fx1, KERB_H, a, c, (fx1 - fx0) / 2, 2);
        kerbAt(kx0, kx1, KERB_H, -side, a, c);
      }
      for (const [a, c] of mouths) {
        if (c <= s0 || a >= s1) continue;
        const p = Math.max(a, s0), q = Math.min(c, s1);
        const xr = side < 0 ? -ROAD : L.kerbR, xo = side < 0 ? L.buildL - 0.5 : L.buildR + 0.5;
        b.quad([(xr + xo) / 2, 0.004, -(p + q) / 2], [(xo - xr) / 2, 0, 0], [0, 0, -(q - p) / 2], null, asphalt);
        if (a >= s0) cap(Math.min(xr, xo), Math.max(xr, xo), KERB_H, a, -1, '#b9b4ab');
        if (c <= s1) cap(Math.min(xr, xo), Math.max(xr, xo), KERB_H, c, 1, '#b9b4ab');
      }
    }
    if (th.median) {
      const gaps = plan ? plan.gaps : [];
      for (const [a, c] of without(s0, s1, gaps)) {
        kerbAt(L.median0, L.median0 + 0.2, 0.3, -1, a, c);
        kerbAt(L.median1 - 0.2, L.median1, 0.3, 1, a, c);
        b.quad([(L.median0 + L.median1) / 2, 0.28, -(a + c) / 2], [(L.median1 - L.median0) / 2 - 0.2, 0, 0], [0, 0, -(c - a) / 2], null, '#5f8f3e');
      }
      for (const [a, c] of gaps) {
        if (c <= s0 || a >= s1) continue;
        const p = Math.max(a, s0), q = Math.min(c, s1);
        b.quad([(L.median0 + L.median1) / 2, 0.004, -(p + q) / 2], [(L.median1 - L.median0) / 2, 0, 0], [0, 0, -(q - p) / 2], null, asphalt);
        if (a >= s0) cap(L.median0, L.median1, 0.3, a, -1, '#b9b4ab');
        if (c <= s1) cap(L.median0, L.median1, 0.3, c, 1, '#b9b4ab');
      }
    }
  }

  function buildChunk(i, city) {
    const { th, L, plan, osm, path } = city;
    materials();
    const seed = i * 7919 + city.key.length * 131;
    let k = 0;
    const r = () => hash(seed + (k++) * 104729);
    const s0 = i * CH, s1 = s0 + CH;
    const out = { lamps: [], bulbs: [], spills: [], train: null };
    const ctx = {
      b: new Builder(),
      win: new Builder({ uv: true }),
      sign: new Builder({ uv: true }),
      ad: new Builder({ uv: true }),
      shop: new Builder({ uv: true }),
      glass: new Builder({ uv: true }),
      decal: new Builder({ uv: true }),
      name: new Builder({ uv: true }),
      road: new Builder({ uv: true }),
      foot: new Builder({ uv: true }),
      kerb: new Builder({ uv: true }),
      names: city.names,
      out, th, L, osm,
    };
    const { b, decal } = ctx;
    const foot = (side) => (plan ? plan.foot[side] : []);
    // the real places on each side, then buildings along what is left
    for (const side of [-1, 1]) {
      const items = plan ? plan.items[side] : [];
      let s = s0;
      for (const it of items) {
        if (it.b <= s0) continue;
        if (it.a >= s1) break;
        if (it.a > s) fillRun(ctx, side, s, it.a, r);
        s = Math.max(s, it.b);
        const p = Math.max(it.a, s0), q = Math.min(it.b, s1);
        if (it.type === 'open') openPlot(ctx, side, it, p, q - p, r);
        else if (it.type === 'water') waterSide(ctx, side, p, q - p);
        else if (it.s >= s0 && it.s < s1) (it.type === 'cross' ? sideStreet : landmark)(ctx, side, it, r);
      }
      if (s < s1) fillRun(ctx, side, s, s1, r);
    }
    if (plan) {
      for (const st of plan.stops) if (st.s >= s0 && st.s < s1) busStop(ctx, st.side, st, r);
      for (const st of plan.booths) if (st.s >= s0 && st.s < s1) booth(ctx, st.side, st);
      for (const st of plan.stations) if (st.s >= s0 && st.s < s1) metroStation(ctx, st);
      for (const g of plan.gantries) if (g.s >= s0 && g.s < s1) gantry(ctx, g);
    }
    // electric poles every 16 m on the left (and the right footpath of avenues), with wires
    const wires = [];
    for (let p = 0; p < 2; p++) {
      const sp = s0 + 8 + p * 16;
      const id = Math.round(sp / 16);
      const free = (side, s) => !inside(s, foot(side), 0.6);
      if (free(-1, sp)) {
        pole(b, L.poleL, -sp, -1, r, true, out);
        if (free(-1, sp + 16)) wiresBetween(wires, -1, L.poleL, sp, sp + 16, id);
      }
      if ((th.median || th.old) && free(1, sp)) {
        pole(b, L.poleR, -sp, 1, r, !th.median, out);
        if (free(1, sp + 16)) wiresBetween(wires, 1, L.poleR, sp, sp + 16, id + 5000);
      }
      if (r() < 0.45) {
        // a cable slung across the road
        const xa = L.poleL, xb2 = th.median ? L.poleR : L.buildR;
        const y0 = 7.0 + r(), y1 = 7.0 + r() * 1.5, zz = -sp, z2 = -sp - (r() - 0.5) * 6;
        let px = xa, py = y0, pz = zz;
        for (let j = 1; j <= 12; j++) {
          const t = j / 12;
          const nx = xa + (xb2 - xa) * t, ny = y0 + (y1 - y0) * t - 1.0 * 4 * t * (1 - t), nz = zz + (z2 - zz) * t;
          wires.push(px, py, pz, nx, ny, nz);
          px = nx;
          py = ny;
          pz = nz;
        }
      }
    }
    // footpath life: trees, tea stalls, fruit carts, parked rickshaws, people
    for (const side of [-1, 1]) {
      if (side > 0 && !th.median && !th.old) continue;
      const foot0 = side < 0 ? L.kerbL : L.kerbR + KERB;
      const fw = side < 0 ? th.footL : th.footR;
      const mid = foot0 + side * fw * 0.5;
      const busy = (s) => inside(s, foot(side), 2);
      for (let slot = 0; slot < 2; slot++) {
        const sz = s0 + 2.5 + slot * 16 + r() * 9;
        const v = r();
        if (busy(sz)) {
          r();
        } else if (v < th.trees) {
          tree(b, foot0 + side * Math.min(fw - 0.6, 1.0), -sz, r, r() < th.flame, out);
        } else if (v < th.trees + th.stalls * 0.5 && fw > 2.5) {
          const [bx, bz] = teaStall(b, mid + side * 0.4, -sz, side, r, out);
          for (let q = 0; q < 2; q++) bystander(b, bx + side * 0.2, bz - 0.5 + q, r, side < 0 ? 0 : Math.PI);
        } else if (v < th.trees + th.stalls && fw > 2.5) {
          fruitCart(b, mid, -sz, side, r, out);
          bystander(b, mid + side * 1.0, -sz + 1.4, r, side < 0 ? Math.PI / 2 : -Math.PI / 2);
        } else if (fw > 2.5) {
          parkedRickshaw(b, mid + side * 0.2, KERB_H, -sz, Math.PI / 2 + (r() - 0.5) * 0.4, r);
        }
        const ps = s0 + r() * CH;
        if (r() < 0.7 && !busy(ps)) bystander(b, foot0 + side * (0.6 + r() * (fw - 1.2)), -ps, r, side < 0 ? Math.PI / 2 + r() : -Math.PI / 2 + r());
      }
      // dustbin
      const ds = s0 + r() * CH;
      if (r() < 0.3 && !busy(ds)) b.box(foot0 + side * (fw - 0.5), KERB_H + 0.4, -ds, 0.5, 0.8, 0.5, '#2a9d4b');
    }
    // median: shrubs and a double lamp post
    if (th.median) {
      const gaps = plan ? plan.gaps : [];
      const mx = (L.median0 + L.median1) / 2;
      for (let s = s0 + 1.5; s < s1; s += 3) {
        const shrub = [r(), r(), r()];
        if (!inside(s, gaps, 1)) b.add(new T.IcosahedronGeometry(1, 0), tf(mx, 0.55, -s, shrub[0], shrub[1], 0, 0.45, 0.4, 0.45), ['#3f8f3a', '#2f7a33', '#4fa046'][Math.floor(shrub[2] * 3)], true);
      }
      if (!inside(s0 + 16, gaps, 1.5)) {
        const lz = -(s0 + 16);
        b.cyl(mx, 4.6, lz, 0.12, 9.2, '#9aa1a8', 8, 0, 0, 0, 0.6);
        for (const sd of [-1, 1]) {
          b.path([[mx, 8.8, lz], [mx + sd * 0.8, 9.2, lz], [mx + sd * 1.7, 9.15, lz]], 0.05, '#9aa1a8', 6);
          b.box(mx + sd * 1.85, 9.08, lz, 0.6, 0.12, 0.25, '#4b4f57');
          out.lamps.push([mx + sd * 1.85, 8.98, lz, 'led']);
        }
      }
    }
    // the metro overhead: piers on the median and the deck, where the line runs
    const metro = city.metro;
    if (metro.length) {
      const mx = (L.median0 != null ? L.median0 : ROAD) + 0.6;
      const deck = (a, c) => {
        const zc = -(a + c) / 2, l = c - a;
        b.box(mx + 0.6, 13.3, zc, 8.0, 1.6, l, '#d2cec6');
        b.box(mx + 0.6, 12.45, zc, 7.0, 0.1, l, '#8f8b84');
        for (const sd of [-1, 1]) b.box(mx + 0.6 + sd * 3.9, 14.6, zc, 0.2, 1.2, l, '#e4e1da');
        for (const dx of [-1.6, 1.6]) b.box(mx + 0.6 + dx, 14.15, zc, 0.12, 0.1, l, '#6d6f75');
      };
      const pier = (s) => {
        const pz = -s;
        b.cyl(mx, 5.8, pz, 0.62, 11.6, '#c9c6bf', 12);
        b.box(mx + 0.6, 12.0, pz, 8.4, 1.2, 1.9, '#bdb9b1');
        for (const sd of [-1, 1]) {
          b.box(mx + 0.6 + sd * 3.6, 16.0, pz, 0.15, 3.0, 0.15, '#7d8187');
          b.box(mx + 0.6 + sd * 2.0, 17.3, pz, 3.4, 0.1, 0.1, '#7d8187');
        }
      };
      for (const [a, c] of metro) {
        if (c <= s0 || a >= s1) continue;
        deck(Math.max(a, s0), Math.min(c, s1));
        if (s0 + 4 > a && s0 + 4 < c) pier(s0 + 4);
        for (const e of [a, c]) if (e >= s0 && e < s1 && Math.abs(e - (s0 + 4)) > 3) pier(e);
      }
    }
    // a footbridge across the road, with adverts facing the traffic
    const bridges = plan ? plan.bridges.filter((s) => s >= s0 && s < s1) : hash(i * 13 + 7) < th.overpass ? [s0 + 20] : [];
    for (const bs of bridges) {
      const bz = -bs;
      const x0 = L.buildL + 1.4, x1 = L.buildR - 1.4;
      const span = x1 - x0, cx = (x0 + x1) / 2;
      b.box(cx, 5.9, bz, span, 0.3, 2.4, '#b9b4ab');
      for (const sd of [-1, 1]) b.box(cx, 6.6, bz + sd * 1.15, span, 1.1, 0.1, '#d8d3c9');
      b.box(cx, 7.4, bz, span, 0.08, 2.6, '#7d8a99');
      for (const sx of [x0 + 0.6, x1 - 0.6]) for (const sd of [-1, 1]) b.box(sx, 2.95, bz + sd * 1.0, 0.3, 5.9, 0.3, '#9a958c');
      // stairs down to the footpaths
      for (const sx of [x0 + 0.7, x1 - 0.7]) b.box(sx, 3.0, bz - 4.2, 1.4, 0.25, 7.6, '#b9b4ab', Math.atan2(5.7, 7.6), 0, 0);
      const n = Math.max(1, Math.floor(span / 5));
      for (let a = 0; a < n; a++) {
        const ax = x0 + (span / n) * (a + 0.5);
        const uv = X.adCell(Math.floor(r() * X.ADS.length));
        ctx.ad.quad([ax, 6.6, bz + 1.22], [Math.min(2.3, span / n / 2 - 0.1), 0, 0], [0, 0.55, 0], uv);
        ctx.ad.quad([ax, 6.6, bz - 1.22], [-Math.min(2.3, span / n / 2 - 0.1), 0, 0], [0, 0.55, 0], uv);
      }
      out.lamps.push([cx - span * 0.3, 5.6, bz, 'led'], [cx + span * 0.3, 5.6, bz, 'led']);
      for (let x = -ROAD + 0.7; x < ROAD; x += 1.4) decal.quad([x, 0.012, -bs], [0.7, 0, 0], [0, 0, -2], X.decalCell(0));
    }
    // road markings and odds and ends on the main road
    const D = (c, x, s, w, l, rot = 0) => {
      const cs = Math.cos(rot), sn = Math.sin(rot);
      decal.quad([x, 0.012, -s], [(w / 2) * cs, 0, (w / 2) * -sn], [(l / 2) * -sn, 0, (-l / 2) * cs], X.decalCell(c));
    };
    if (!plan && !bridges.length && hash(i * 31 + 3) < 0.16) {
      const zs = s0 + 10 + r() * 12;
      for (let x = -ROAD + 0.7; x < ROAD; x += 1.4) D(0, x, zs, 1.4, 4.0, 0);
    }
    for (let m = 0; m < 2; m++) if (r() < 0.6) D(1, -ROAD + 0.8 + r() * (ROAD * 2 - 1.6), s0 + r() * CH, 0.9, 0.9, r() * 3);
    for (let m = 0; m < 3; m++) if (r() < 0.5) D(2 + Math.floor(r() * 2), -ROAD + 1 + r() * (ROAD * 2 - 2), s0 + r() * CH, 1.2 + r() * 1.5, 1.2 + r() * 2, r() * 3);
    if (r() < 0.3) D(r() < 0.6 ? 4 : 5, [-2.8, 0, 2.8][Math.floor(r() * 3)], s0 + 6 + r() * 20, 2.2, 3.6);
    if (r() < 0.5) D(8, -ROAD + 0.5, s0 + r() * CH, 1.0, 1.0, r() * 3);
    for (let m = 0; m < 2; m++) D(9, -ROAD + 0.35, s0 + 4 + m * 16 + r() * 4, 0.5, 0.7);
    if (r() < 0.4) D(10, -ROAD + 1 + r() * (ROAD * 2 - 2), s0 + r() * CH, 1.2, 0.9, r() * 3);
    ground(ctx, s0, s1, plan);

    // onto the route's path: cut long faces at the bends, bend everything, and turn the lights'
    // places into world points (keeping their road distance and side for the night pass)
    const builders = [b, ctx.win, ctx.shop, ctx.sign, ctx.ad, ctx.glass, decal, ctx.name, ctx.road, ctx.foot, ctx.kerb];
    if (path.curved) {
      for (const bld of builders) {
        slice(bld, path.cuts);
        bend(path, bld);
      }
      bendArrays(path, wires);
    }
    const w = new T.Vector3();
    for (const list of [out.lamps, out.bulbs, out.spills]) {
      for (const l of list) {
        const lat = l[0], s = -l[2];
        path.pos(s, lat, l[1], w);
        l[0] = w.x;
        l[2] = w.z;
        l.push(s, lat);
      }
    }

    // meshes
    const group = new T.Group();
    const add = (bld, mat) => {
      if (!bld.count) return null;
      const m = new T.Mesh(bld.build(), mat);
      m.matrixAutoUpdate = false;
      group.add(m);
      return m;
    };
    add(ctx.road, roadMat(th.road));
    add(ctx.foot, footMat(th.road));
    add(ctx.kerb, M.kerb);
    add(b, M.solid);
    add(ctx.win, M.windows);
    add(ctx.shop, M.shops);
    add(ctx.sign, M.signs);
    add(ctx.ad, M.ads);
    add(ctx.glass, M.glass);
    if (city.nameMat) add(ctx.name, city.nameMat);
    const dm = add(decal, M.decals);
    if (dm) dm.renderOrder = -1;
    if (wires.length) {
      const g = new T.BufferGeometry();
      g.setAttribute('position', new T.Float32BufferAttribute(wires, 3));
      const lines = new T.LineSegments(g, M.wires);
      lines.matrixAutoUpdate = false;
      group.add(lines);
    }
    group.userData = { index: i, out };
    return group;
  }

  // ------------------------------------------------------------------ the city

  /* new City(scene, routeId, len): the street of a route (len: its race length in metres). Call
   * update(s) every frame with the camera's distance down the road. lights() lists the lamps,
   * bulbs and shop spills of the built chunks, for the night pass, as world points with their
   * road distance and side: [x, y, z, kind or width, s, lateral]. path maps road coordinates
   * to the world; metro lists where the metro runs ([s0, s1] stretches). */
  class City {
    constructor(scene, routeId, len = 400) {
      this.osm = (window.BT.osm && window.BT.osm[routeId]) || null;
      this.key = this.osm ? routeId : ROUTE_THEME[routeId] || 'avenue';
      this.theme = ROUTE_THEME[routeId] || 'avenue';
      this.th = Object.assign({}, THEMES[this.theme]);
      if (this.osm) {
        this.th.median = this.osm.median;
        this.th.metro = false;
      }
      this.L = layout(this.th);
      this.path = new RoadPath(this.osm);
      this.plan = this.osm ? makePlan(this.osm, len) : null;
      this.metro = this.plan ? this.plan.metro : this.th.metro ? [[-1e9, 1e9]] : [];
      this.names = this.plan && this.plan.entries.length ? X.names(routeId, this.plan.entries) : null;
      materials();
      this.nameMat = this.names ? nameMaterial(this.names.tex) : null;
      this.scene = scene;
      this.chunks = new Map();
      this.root = new T.Group();
      scene.add(this.root);
      this.ahead = 150;
    }

    metroAt(s) {
      return this.metro.some(([a, b]) => s > a && s < b);
    }

    update(s, budget = 1) {
      const i0 = Math.floor((s - 24) / CH), i1 = Math.floor((s + this.ahead) / CH);
      for (const [i, g] of this.chunks) {
        if (i < i0 - 1 || i > i1 + 1) {
          this.root.remove(g);
          g.traverse((o) => o.geometry && o.geometry.dispose());
          this.chunks.delete(i);
        }
      }
      // build the nearest missing chunks first; budget limits how many per frame
      for (let i = i0; i <= i1 && budget > 0; i++) {
        if (this.chunks.has(i)) continue;
        const g = buildChunk(i, this);
        this.chunks.set(i, g);
        this.root.add(g);
        budget--;
      }
    }

    // every lamp, bulb and shop spill in the built chunks
    lights() {
      const all = { lamps: [], bulbs: [], spills: [] };
      for (const g of this.chunks.values()) {
        const o = g.userData.out;
        all.lamps.push(...o.lamps);
        all.bulbs.push(...o.bulbs);
        all.spills.push(...o.spills);
      }
      return all;
    }

    dispose() {
      this.scene.remove(this.root);
      this.root.traverse((o) => o.geometry && o.geometry.dispose());
      this.chunks.clear();
      if (this.nameMat) {
        nameMats.delete(this.nameMat);
        this.nameMat.dispose();
      }
    }
  }

  window.BT.city3 = { City, THEMES, ROUTE_THEME, layout, setNight, materials, RoadPath, bendArrays, CH, ROAD, KERB, KERB_H };
})();
