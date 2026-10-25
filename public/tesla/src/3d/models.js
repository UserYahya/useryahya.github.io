/* বাংলা টেসলা 3D — the models: rickshaws (with their riders), private cars, local buses,
 * CNGs, people, pickups and road works.
 *
 * Each animated model is one SkinnedMesh: wheels, cranks, limbs and tassels are bones, so a
 * whole rickshaw with its rider is a single draw call (plus its ink outline). Geometry is
 * built once per look and shared; every instance gets its own bones.
 *
 * Models face +x with +y up and +z on their right, in metres, sized like the 2D art (90 px
 * a metre): a rickshaw is 2.9 m long, a car 4 m, a bus 6.6 m. pose() takes the animation
 * state; lights() lists where the lamps are, for the glow pass. */
(function () {
  'use strict';

  const { T, Builder, MAT, outline, extrude, qbez, tf } = window.BT.k3;
  const X = window.BT.tex3;
  const A = window.BT.art;
  const HAIR = '#1a1210';
  const INK = '#1d1428';
  const TAU = Math.PI * 2;
  const DOWN = new T.Vector3(0, -1, 0);
  const shade = (hex, amt) => {
    const c = new T.Color(hex);
    return amt >= 0 ? c.lerp(new T.Color(1, 1, 1), amt) : c.multiplyScalar(1 + amt);
  };

  // ------------------------------------------------------------------ shared helpers

  const mats = new Map();
  function atlasMat(tex, opts) {
    const key = tex.uuid + (opts ? JSON.stringify(Object.keys(opts)) : '');
    let m = mats.get(key);
    if (!m) mats.set(key, (m = MAT.toon(Object.assign({ map: tex, vertexColors: true }, opts))));
    return m;
  }

  const geos = new Map();
  function cached(key, make) {
    let g = geos.get(key);
    if (!g) geos.set(key, (g = make()));
    return g;
  }

  /* Bones from [name, parent, x, y, z] rows, positions absolute in the bind pose. */
  function makeBones(spec) {
    const bones = [];
    spec.forEach(([name, parent, x, y, z]) => {
      const b = new T.Bone();
      b.name = name;
      if (parent >= 0) {
        const p = spec[parent];
        b.position.set(x - p[2], y - p[3], z - p[4]);
        bones[parent].add(b);
      } else {
        b.position.set(x, y, z);
      }
      bones.push(b);
    });
    return bones;
  }

  // An instance of a skinned look: shared geometry, its own skeleton, an ink outline.
  function instance(geo, spec, mat, ink = 0.014) {
    const bones = makeBones(spec);
    const mesh = new T.SkinnedMesh(geo, mat);
    for (const b of bones) if (!b.parent) mesh.add(b);
    mesh.updateMatrixWorld(true);
    mesh.bind(new T.Skeleton(bones));
    if (ink) outline(mesh, ink);
    const rest = bones.map((b) => b.position.clone());
    return { mesh, bones, rest };
  }

  const _d = new T.Vector3(), _p = new T.Vector3();
  // Two-bone IK: the middle joint for a limb from a to b (lengths l1, l2), bending toward pole.
  function ik(a, b, l1, l2, pole, out) {
    _d.subVectors(b, a);
    let L = _d.length();
    if (L < 1e-6) {
      _d.set(0, -1, 0);
      L = 1e-6;
    } else {
      _d.multiplyScalar(1 / L);
    }
    L = Math.max(Math.abs(l1 - l2) + 1e-3, Math.min(l1 + l2 - 1e-3, L));
    const x = (l1 * l1 - l2 * l2 + L * L) / (2 * L);
    const h = Math.sqrt(Math.max(0, l1 * l1 - x * x));
    _p.copy(pole).addScaledVector(_d, -pole.dot(_d));
    if (_p.lengthSq() < 1e-9) _p.set(1, 0, 0);
    _p.normalize();
    return out.copy(a).addScaledVector(_d, x).addScaledVector(_p, h);
  }

  // World rotation turning "hanging down" toward from → to.
  const _v = new T.Vector3();
  function aim(from, to, out) {
    _v.subVectors(to, from);
    if (_v.lengthSq() < 1e-10) return out.identity();
    return out.setFromUnitVectors(DOWN, _v.normalize());
  }

  // ------------------------------------------------------------------ wheels

  // Bicycle wheel with spokes, axle along z. beads: coloured beads on the spokes; motor: hub motor.
  function spokeWheel(b, x, y, z, R, beads, motor) {
    const ow = b.ow;
    b.ow = 0.6;
    b.ring(x, y, z, R - 0.03, 0.03, '#1c1922', 22);
    b.ow = 0;
    b.ring(x, y, z, R - 0.066, 0.009, '#d7dee7', 22);
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * TAU;
      const side = i % 2 ? 0.024 : -0.024;
      b.rod([x + Math.cos(a) * 0.04, y + Math.sin(a) * 0.04, z + side], [x + Math.cos(a + 0.35) * (R - 0.07), y + Math.sin(a + 0.35) * (R - 0.07), z], 0.0045, '#e4e9f0', 4);
    }
    b.cyl(x, y, z, motor ? 0.085 : 0.035, motor ? 0.09 : 0.1, motor ? '#2b2f38' : '#b9c2cc', 10, Math.PI / 2);
    if (beads) {
      for (let i = 0; i < 6; i++) {
        const a = (i / 6) * TAU + 0.2;
        b.ball(x + Math.cos(a) * R * 0.6, y + Math.sin(a) * R * 0.6, z, 0.017, 0.017, 0.017, beads[i % beads.length], 6);
      }
    }
    b.ow = ow;
  }

  // Car wheel, axle along z: tyre and hubcap.
  function carWheel(b, x, y, z, R, w, rim) {
    b.cyl(x, y, z, R, w, '#1b1a20', 14, Math.PI / 2);
    b.ow = 0;
    b.cyl(x, y, z + Math.sign(z) * 0.004, R * 0.6, w + 0.006, rim, 12, Math.PI / 2);
    for (let i = 0; i < 5; i++) {
      const a = (i / 5) * TAU;
      b.box(x + Math.cos(a) * R * 0.32, y + Math.sin(a) * R * 0.32, z + Math.sign(z) * (w / 2 + 0.006), 0.05, 0.05, 0.004, '#6f7983');
    }
    b.ow = 1;
  }

  // ------------------------------------------------------------------ rickshaw

  const RK = {
    R: 0.345, RX: -0.87, FX: 1.16, TR: 0.6,
    BB: [0.378, 0.444], HIP: [0.29, 1.19],
    PIV: [-0.93, 1.09],
  };
  const HC = [RK.HIP[0] + 0.03, RK.HIP[1] + 0.71]; // head centre in the bind pose
  const TASSELS = ['#ff4fa3', '#ffd23f', '#35d07f', '#4cc3ff', '#ff9f1c', '#f1f5f9'];

  const RICKSHAW_BONES = [
    ['root', -1, 0, 0, 0],
    ['wheelR', 0, RK.RX, RK.R, 0],
    ['wheelF', 0, RK.FX, RK.R, 0],
    ['crank', 0, RK.BB[0], RK.BB[1], 0],
    ['hips', 0, RK.HIP[0], RK.HIP[1], 0],
    ['spine', 4, RK.HIP[0], RK.HIP[1], 0],
    ['head', 5, RK.HIP[0], RK.HIP[1] + 0.58, 0],
    ['mouth', 6, HC[0] + 0.118, HC[1] - 0.075, 0],
    ['gamchha', 6, HC[0] - 0.13, HC[1] + 0.05, 0],
    ['armL', 5, RK.HIP[0], RK.HIP[1] + 0.47, -0.17],
    ['foreL', 9, RK.HIP[0], RK.HIP[1] + 0.47 - 0.233, -0.17],
    ['armR', 5, RK.HIP[0], RK.HIP[1] + 0.47, 0.17],
    ['foreR', 11, RK.HIP[0], RK.HIP[1] + 0.47 - 0.233, 0.17],
    ['thighL', 4, RK.HIP[0], RK.HIP[1] - 0.02, -0.09],
    ['shinL', 13, RK.HIP[0], RK.HIP[1] - 0.44, -0.09],
    ['footL', 14, RK.HIP[0], RK.HIP[1] - 0.91, -0.09],
    ['thighR', 4, RK.HIP[0], RK.HIP[1] - 0.02, 0.09],
    ['shinR', 16, RK.HIP[0], RK.HIP[1] - 0.44, 0.09],
    ['footR', 17, RK.HIP[0], RK.HIP[1] - 0.91, 0.09],
    ['tasselL', 0, 0.74, 1.38, -0.28],
    ['tasselR', 0, 0.74, 1.38, 0.28],
  ];

  function rickshawGeometry(k, atlas) {
    const { R, RX, FX, TR, BB, HIP, PIV } = RK;
    const b = new Builder({ uv: true, skin: true, white: atlas.white });
    const F = k.frame, TRIM = k.trim, CHROME = '#cfd6df';

    // ---- carriage (bone 0)
    b.bone = 0;
    b.box(-0.89, 0.855, 0, 0.84, 0.33, 1.1, k.panel);
    b.box(-0.89, 0.705, 0, 0.87, 0.045, 1.13, TRIM);
    b.box(-0.89, 1.01, 0, 0.87, 0.03, 1.13, TRIM);
    b.box(-0.875, 1.09, 0, 0.92, 0.14, 1.12, k.seat);
    for (let i = 0; i < 5; i++) b.ball(-1.2 + i * 0.16, 1.16, 0, 0.02, 0.012, 0.02, shade(k.seat, -0.4), 5);
    b.box(-1.31, 1.4, 0, 0.09, 0.5, 1.08, k.seat, 0, 0, 0.12);
    b.box(-1.3, 1.66, 0, 0.12, 0.05, 1.1, TRIM, 0, 0, 0.12);
    b.box(-0.22, 0.555, 0, 0.58, 0.05, 0.84, TRIM);
    b.box(-0.5, 0.63, 0, 0.12, 0.1, 0.7, shade(k.panel, -0.3));
    b.ow = 0.7;
    b.rod([0.07, 0.556, 0], [-0.5, 0.63, 0], 0.03, F);
    b.rod([RX, R, -TR - 0.05], [RX, R, TR + 0.05], 0.022, '#5b6068');
    for (const s of [-1, 1]) b.rod([RX, R, s * 0.47], [RX - 0.05, 0.7, s * 0.47], 0.02, F);
    b.ow = 1;
    // the painted back plate, in a trim frame
    b.quad([-1.338, 0.815, 0], [0, 0, 0.48], [0, 0.245, 0], atlas.back);
    b.ow = 0.5;
    for (const s of [-1, 1]) {
      b.box(-1.335, 0.815, s * 0.49, 0.025, 0.52, 0.025, TRIM);
      b.box(-1.335, 0.815 + s * 0.255, 0, 0.025, 0.025, 1.0, TRIM);
    }
    b.ow = 1;
    if (k.battery) {
      // the battery pack that makes it a Tesla
      b.box(-0.27, 0.43, 0, 0.44, 0.17, 0.5, '#262a33');
      for (const s of [-1, 1]) b.box(-0.27, 0.44, s * 0.252, 0.24, 0.09, 0.006, TRIM);
      b.ow = 0;
      b.path([[-0.49, 0.43, 0.15], [-0.66, 0.37, 0.4], [RX, R, TR - 0.05]], 0.008, '#111111', 4);
      b.box(-1.338, 0.6, -0.38, 0.02, 0.05, 0.12, '#ff3b3b');
      b.box(-1.338, 0.6, 0.38, 0.02, 0.05, 0.12, '#ff3b3b');
      b.ow = 1;
    } else {
      // hurricane lantern under the seat (pedal rickshaws have no headlight)
      const lx = -0.5, lz = -0.47;
      b.ow = 0.4;
      b.rod([lx, 0.69, lz], [lx, 0.61, lz], 0.004, '#3a3640', 4);
      b.cyl(lx, 0.6, lz, 0.035, 0.02, '#3a3640', 8);
      b.ball(lx, 0.53, lz, 0.045, 0.06, 0.045, '#ffd98a', 8);
      b.cyl(lx, 0.47, lz, 0.05, 0.03, '#3a3640', 8);
      b.ow = 1;
    }
    // mudguards and reflectors
    for (const s of [-1, 1]) {
      b.ring(RX, R, s * TR, R + 0.06, 0.03, k.mud, 14, 0, 0, 0.35, 2.45);
      b.cyl(RX - R - 0.04, R + 0.12, s * TR, 0.03, 0.012, '#ff3b3b', 8, 0, 0, Math.PI / 2);
    }
    b.ring(FX, R, 0, R + 0.055, 0.028, k.mud, 14, 0, 0, 0.45, 2.2);

    // ---- the bicycle in front
    b.ow = 0.7;
    b.rod([0.067, 0.556, 0], [1.03, 1.0, 0], 0.032, F);
    b.rod([0.067, 0.556, 0], [BB[0], BB[1], 0], 0.026, F);
    b.rod([BB[0], BB[1], 0], [0.3, 1.12, 0], 0.026, F);
    b.rod([0.32, 1.02, 0], [0.98, 1.22, 0], 0.022, F);
    b.rod([1.03, 0.98, 0], [0.98, 1.29, 0], 0.036, F);
    b.rod([0.25, 0.86, 0], [0.75, 1.07, 0], 0.01, TRIM, 4);
    for (const s of [-1, 1]) b.rod([1.03, 0.98, s * 0.05], [FX, R, s * 0.05], 0.014, CHROME);
    b.rod([FX, R, -0.07], [FX, R, 0.07], 0.012, CHROME);
    b.rod([0.63, 0.68, -0.21], [0.63, 0.68, 0.21], 0.012, CHROME);
    b.rod([0.63, 0.68, 0], [0.63, 0.816, 0], 0.012, CHROME);
    b.rod([0.3, 1.12, 0], [0.31, 1.15, 0], 0.016, CHROME);
    b.ball(0.31, 1.165, 0, 0.15, 0.04, 0.1, '#3a2a22', 10);
    b.cyl(BB[0], BB[1], 0, 0.045, 0.12, '#9aa3ae', 10, Math.PI / 2);
    b.ow = 0;
    b.rod([BB[0], BB[1] - 0.08, 0.07], [RX, R - 0.05, 0.07], 0.009, '#2a2a30', 4);
    b.rod([BB[0], BB[1] + 0.08, 0.07], [RX, R + 0.05, 0.07], 0.009, '#2a2a30', 4);
    b.ow = 0.7;
    b.rod([0.98, 1.29, 0], [0.92, 1.37, 0], 0.02, CHROME);
    b.path([[0.74, 1.4, -0.28], [0.86, 1.385, -0.16], [0.92, 1.37, 0], [0.86, 1.385, 0.16], [0.74, 1.4, 0.28]], 0.015, CHROME);
    for (const s of [-1, 1]) b.rod([0.74, 1.4, s * 0.2], [0.74, 1.4, s * 0.29], 0.022, '#26222b');
    b.dome(0.86, 1.4, 0.12, 0.036, 0.032, 0.036, '#e9eef5', 10);
    b.rod([1.03, 1.12, 0], [1.07, 1.2, 0], 0.012, CHROME);
    b.box(1.08, 1.2, 0, 0.08, 0.1, 0.1, CHROME);
    b.ow = 0.4;
    b.cyl(1.125, 1.2, 0, 0.045, 0.02, k.battery ? '#fffbe0' : '#ffe58a', 10, 0, 0, Math.PI / 2);
    b.ow = 1;

    // ---- folding hood: canvas over the top, painted side fans, trim and studs
    const W = X.HOOD.w;
    const edge = X.hoodEdge(20);
    const n = edge.length - 1;
    const ro = atlas.roof, si = atlas.side, U = X.HOOD_UV;
    const pt = (e, z, sc = 1) => [PIV[0] + e[0] * sc, PIV[1] + e[1] * sc, z];
    const ruv = (i, z) => [ro[0] + (i / n) * (ro[2] - ro[0]), ro[1] + ((z + W) / (2 * W)) * (ro[3] - ro[1])];
    for (let i = 0; i < n; i++) {
      const e0 = edge[i], e1 = edge[i + 1];
      // outside, then the inside a little smaller and facing in
      b.tris([pt(e0, -W), pt(e1, -W), pt(e1, W), pt(e0, -W), pt(e1, W), pt(e0, W)], '#ffffff',
        [ruv(i, -W), ruv(i + 1, -W), ruv(i + 1, W), ruv(i, -W), ruv(i + 1, W), ruv(i, W)]);
      const s = 0.985;
      b.tris([pt(e0, -W, s), pt(e1, W, s), pt(e1, -W, s), pt(e0, -W, s), pt(e0, W, s), pt(e1, W, s)], shade(k.hood, -0.35));
    }
    const suv = (e) => [si[0] + ((e[0] - U.x0) / U.w) * (si[2] - si[0]), si[1] + ((e[1] - U.y0) / U.h) * (si[3] - si[1])];
    const piv = [0, 0];
    for (const sd of [-1, 1]) {
      const z = sd * (W + 0.002), zi = sd * (W - 0.006);
      for (let i = 0; i < n; i++) {
        const e0 = edge[i], e1 = edge[i + 1];
        const out = sd > 0 ? [pt(piv, z), pt(e0, z), pt(e1, z)] : [pt(piv, z), pt(e1, z), pt(e0, z)];
        const uvs = sd > 0 ? [suv(piv), suv(e0), suv(e1)] : [suv(piv), suv(e1), suv(e0)];
        b.tris(out, '#ffffff', uvs);
        b.tris(sd > 0 ? [pt(piv, zi), pt(e1, zi), pt(e0, zi)] : [pt(piv, zi), pt(e0, zi), pt(e1, zi)], shade(k.hood, -0.35));
      }
    }
    b.ow = 0.8;
    for (const sd of [-1, 1]) b.path(edge.map((e) => pt(e, sd * (W + 0.008))), 0.02, TRIM, 5, false);
    b.rod(pt(edge[0], -W - 0.01), pt(edge[0], W + 0.01), 0.02, TRIM);
    b.rod(pt(edge[n], -W - 0.01), pt(edge[n], W + 0.01), 0.016, TRIM);
    b.ow = 0;
    for (const sd of [-1, 1]) {
      for (let i = 1; i < n; i += 2) {
        const p = pt(edge[i], sd * (W + 0.03));
        b.ball(p[0], p[1], p[2], 0.012, 0.012, 0.012, '#eef2f7', 5);
      }
      b.cyl(PIV[0], PIV[1], sd * (W + 0.012), 0.035, 0.02, CHROME, 10, Math.PI / 2);
    }
    b.ow = 1;

    // ---- rider: hips and lungi (4), torso (5), head (6), mouth (7), gamchha tails (8)
    b.bone = 4;
    b.uvr = atlas.lungi;
    b.ecyl(HIP[0], HIP[1] + 0.03, 0, 0.15, 0.2, 0.17, '#ffffff', 10, 0, 0, 0, 0.88);
    b.uvr = null;
    b.bone = 5;
    b.ecyl(HIP[0], HIP[1] + 0.3, 0, 0.12, 0.175, 0.42, k.shirt, 10, 0, 0, 0, 1.12);
    for (const s of [-1, 1]) b.ball(HIP[0], HIP[1] + 0.47, s * 0.17, 0.065, 0.065, 0.065, k.sleeve ? k.shirt : k.skin, 8);
    b.cyl(HIP[0] + 0.01, HIP[1] + 0.54, 0, 0.05, 0.1, k.skin, 8);
    if (!k.sleeve) b.ball(HIP[0] + 0.1, HIP[1] + 0.48, 0, 0.035, 0.05, 0.08, k.skin, 8);
    b.bone = 6;
    const [hx, hy] = HC;
    b.ball(hx, hy, 0, 0.125, 0.13, 0.12, k.skin, 12);
    b.dome(hx - 0.015, hy + 0.03, 0, 0.13, 0.11, 0.125, HAIR, 12, 0, 0, 0.35);
    for (const s of [-1, 1]) b.ball(hx - 0.005, hy, s * 0.12, 0.02, 0.035, 0.015, k.skin, 6);
    b.ball(hx + 0.125, hy - 0.01, 0, 0.022, 0.03, 0.02, shade(k.skin, -0.15), 6);
    if (k.shades) {
      b.box(hx + 0.105, hy + 0.025, 0, 0.04, 0.045, 0.2, '#101018');
      b.box(hx + 0.126, hy + 0.035, 0.05, 0.004, 0.012, 0.045, '#78dcff');
      for (const s of [-1, 1]) b.box(hx + 0.02, hy + 0.03, s * 0.112, 0.2, 0.012, 0.01, '#101018');
    } else {
      for (const s of [-1, 1]) {
        b.ball(hx + 0.11, hy + 0.025, s * 0.045, 0.012, 0.016, 0.012, INK, 6);
        b.box(hx + 0.115, hy + 0.062, s * 0.045, 0.01, 0.01, 0.045, HAIR);
      }
    }
    b.box(hx + 0.12, hy - 0.045, 0, 0.02, 0.018, 0.08, HAIR);
    b.uvr = atlas.gamchha;
    b.ring(hx - 0.005, hy + 0.05, 0, 0.128, 0.026, '#ffffff', 16, Math.PI / 2);
    b.ball(hx - 0.13, hy + 0.05, 0, 0.04, 0.035, 0.05, '#ffffff', 8);
    b.uvr = null;
    b.bone = 7;
    b.ow = 0;
    b.box(hx + 0.118, hy - 0.075, 0, 0.014, 0.016, 0.05, '#5a1a1a');
    b.bone = 8;
    b.ow = 0.5;
    b.uvr = atlas.gamchha;
    for (const s of [-1, 1]) b.box(hx - 0.22, hy + 0.04, s * 0.03, 0.17, 0.05, 0.012, '#ffffff', 0, s * 0.2, 0);
    b.uvr = null;
    b.ow = 1;

    // ---- arms (9-12), legs (13-18)
    for (const s of [-1, 1]) {
      const sx = HIP[0], sy = HIP[1] + 0.47, sz = s * 0.17;
      const up = s < 0 ? 9 : 11;
      b.bone = up;
      if (k.sleeve) {
        b.cyl(sx, sy - 0.07, sz, 0.052, 0.14, k.shirt, 8);
        b.cyl(sx, sy - 0.18, sz, 0.04, 0.11, k.skin, 8);
      } else {
        b.cyl(sx, sy - 0.1165, sz, 0.042, 0.233, k.skin, 8, 0, 0, 0, 0.9);
      }
      b.bone = up + 1;
      b.ball(sx, sy - 0.233, sz, 0.038, 0.038, 0.038, k.skin, 8);
      b.cyl(sx, sy - 0.233 - 0.11, sz, 0.036, 0.22, k.skin, 8, 0, 0, 0, 1.1);
      b.ball(sx, sy - 0.466 - 0.02, sz, 0.042, 0.048, 0.04, k.skin, 8);
    }
    for (const s of [-1, 1]) {
      const lx = HIP[0], ly = HIP[1] - 0.02, lz = s * 0.09;
      const th = s < 0 ? 13 : 16;
      b.bone = th;
      b.uvr = atlas.lungi;
      b.ecyl(lx, ly - 0.2, lz, 0.075, 0.075, 0.42, '#ffffff', 8, 0, 0, 0, 1.2);
      b.uvr = null;
      b.bone = th + 1;
      b.ball(lx, ly - 0.42, lz, 0.05, 0.05, 0.05, k.skin, 8);
      b.cyl(lx, ly - 0.42 - 0.235, lz, 0.044, 0.47, k.skin, 8, 0, 0, 0, 1.15);
      b.bone = th + 2;
      b.box(lx + 0.06, ly - 0.89 - 0.03, lz, 0.2, 0.04, 0.09, '#4a3426');
      b.box(lx + 0.04, ly - 0.89, lz, 0.13, 0.04, 0.07, k.skin);
    }

    // ---- crank (3), wheels (1, 2), tassels (19, 20)
    b.bone = 3;
    b.ow = 0.5;
    b.ring(BB[0], BB[1], 0.07, 0.09, 0.008, '#9aa3ae', 16);
    b.rod([BB[0], BB[1], 0.09], [BB[0] + 0.145, BB[1], 0.09], 0.012, '#c3cbd5');
    b.rod([BB[0], BB[1], -0.09], [BB[0] - 0.145, BB[1], -0.09], 0.012, '#c3cbd5');
    b.box(BB[0] + 0.145, BB[1], 0.13, 0.08, 0.02, 0.09, '#2a2a30');
    b.box(BB[0] - 0.145, BB[1], -0.13, 0.08, 0.02, 0.09, '#2a2a30');
    b.bone = 1;
    spokeWheel(b, RX, R, -TR, R, k.bands, false);
    spokeWheel(b, RX, R, TR, R, k.bands, !!k.battery);
    b.bone = 2;
    spokeWheel(b, FX, R, 0, R, k.bands, false);
    b.ow = 0;
    for (const s of [-1, 1]) {
      b.bone = s < 0 ? 19 : 20;
      for (let i = 0; i < 6; i++) {
        const len = 0.17 + (i % 3) * 0.045;
        b.box(0.74 + (i - 2.5) * 0.012, 1.38 - len / 2, s * 0.28 + ((i % 2) - 0.5) * 0.012, 0.012, len, 0.012, TASSELS[i]);
      }
    }
    return b.build();
  }

  const _q1 = new T.Quaternion(), _q2 = new T.Quaternion(), _q3 = new T.Quaternion(), _qs = new T.Quaternion(), _qi = new T.Quaternion(), _qI = new T.Quaternion();
  const _e = new T.Euler();
  const _S = new T.Vector3(), _H = new T.Vector3(), _E = new T.Vector3(), _J = new T.Vector3(), _F = new T.Vector3(), _K = new T.Vector3(), _end = new T.Vector3();
  const _hips = new T.Vector3(), _pole = new T.Vector3(), _off = new T.Vector3(), _head = new T.Vector3();

  // Points a two-bone limb (bones i and i + 1) from root a at target b, bending toward pole;
  // qParent is the parent bone's rotation in the model's frame.
  function reach(B, i, a, b, l1, l2, pole, qParent) {
    ik(a, b, l1, l2, pole, _E);
    aim(a, _E, _q1);
    _end.subVectors(b, _E).normalize().multiplyScalar(l2).add(_E);
    aim(_E, _end, _q2);
    B[i].quaternion.copy(_qi.copy(qParent).invert().multiply(_q1));
    B[i + 1].quaternion.copy(_qi.copy(_q1).invert().multiply(_q2));
    return _q2;
  }

  /* A rickshaw with its rider. pose(s) takes:
   *   wheel, crank (radians), pedal (feet on the pedals, else up on the rest), pose ('sorry' |
   *   'scratch' | 'win' | null), talk, sway (0..1, wind on tassels and gamchha), boost, t */
  function makeRickshaw(skin) {
    const k = skin || A.SKINS.tesla;
    const atlas = X.rickshaw(k);
    const geo = cached('rickshaw:' + k.name + k.frame + k.hood, () => rickshawGeometry(k, atlas));
    const { mesh, bones } = instance(geo, RICKSHAW_BONES, atlasMat(atlas.tex), 0.013);
    const B = bones;
    const HIP = RK.HIP, BB = RK.BB;
    const edge = X.hoodEdge(14);
    const W = X.HOOD.w;
    const led = [];
    for (const sd of [-1, 1]) for (const e of edge) led.push([RK.PIV[0] + e[0], RK.PIV[1] + e[1], sd * (W + 0.03)]);
    for (let i = 1; i < 8; i++) led.push([RK.PIV[0] + edge[0][0], RK.PIV[1] + edge[0][1], -W + (i / 8) * 2 * W]);
    const lights = {
      head: k.battery ? [1.135, 1.2, 0] : null,
      tail: k.battery ? [[-1.35, 0.6, -0.38], [-1.35, 0.6, 0.38]] : [],
      lantern: k.battery ? null : [-0.5, 0.53, -0.47],
      battery: k.battery ? [-0.04, 0.48, 0.255] : null,
      led: k.led ? led : null,
      bell: [0.86, 1.44, 0.12],
    };

    function pose(s) {
      const t = s.t || 0;
      B[1].rotation.z = -(s.wheel || 0);
      B[2].rotation.z = -(s.wheel || 0);
      const pedal = !!s.pedal;
      const crank = pedal ? s.crank || 0 : 0.5;
      B[3].rotation.z = -crank;
      // torso: leans forward, rocks a little with each pedal stroke
      const lean = 0.25 + (pedal ? 0.07 : 0) + (s.boost ? 0.1 : 0) + (s.pose === 'win' ? -0.15 : 0);
      const roll = pedal ? Math.sin(crank) * 0.05 : 0;
      _hips.set(HIP[0], HIP[1] + (pedal ? Math.abs(Math.sin(crank)) * 0.015 : 0), 0);
      B[4].position.copy(_hips);
      _qs.setFromEuler(_e.set(roll, 0, -lean));
      B[5].quaternion.copy(_qs);
      // head: keeps looking ahead; bows for "sorry", tilts while scratching
      const nod = s.pose === 'sorry' ? -0.25 : s.pose === 'win' ? 0.2 : 0;
      B[6].quaternion.setFromEuler(_e.set(s.pose === 'scratch' ? 0.25 : -roll, 0, lean * 0.7 + nod));
      B[7].scale.y = s.talk ? 1 + Math.abs(Math.sin(t * 16)) * 2.2 : 1;
      const sway = s.sway == null ? 0.5 : s.sway;
      // gamchha ends: hang down when still, stream back in the wind
      B[8].rotation.set(Math.sin(t * 13) * 0.25 * sway, 0, 1.15 - 0.95 * sway + Math.sin(t * 10) * 0.14 * (0.3 + sway));
      for (const i of [19, 20]) B[i].rotation.set(Math.sin(t * 9 + i) * 0.12 * (0.3 + sway), 0, -0.6 * sway + Math.sin(t * 8 + i * 2) * 0.1);
      // head centre, for hand targets
      _head.set(0.03, 0.71, 0).applyQuaternion(_qs).add(_hips);
      // arms
      for (const sd of [-1, 1]) {
        const up = sd < 0 ? 9 : 11;
        _S.set(0, 0.47, sd * 0.17).applyQuaternion(_qs).add(_hips);
        if (s.pose === 'sorry') {
          // holding his ears: the Bangladeshi way of saying sorry
          _H.set(_head.x - 0.03, _head.y - 0.05, sd * 0.15);
          _pole.set(0.7, -0.8, sd * 0.45);
        } else if (s.pose === 'scratch' && sd > 0) {
          _H.set(_head.x - 0.02, _head.y + 0.16, 0.05);
          _pole.set(0.3, 0.2, 1);
        } else if (s.pose === 'win') {
          _H.set(_S.x + 0.05, _S.y + 0.45, sd * 0.42);
          _pole.set(0, 0, sd);
        } else {
          _H.set(0.74, 1.4, sd * 0.25);
          _pole.set(-0.3, -1, sd * 0.6);
        }
        reach(B, up, _S, _H, 0.233, 0.233, _pole, _qs);
      }
      // legs: feet on the pedals, or up on the rest bar while the battery drives
      for (const sd of [-1, 1]) {
        const th = sd < 0 ? 13 : 16;
        _J.set(HIP[0], _hips.y - 0.02, sd * 0.09);
        if (pedal) {
          const a = -crank + (sd < 0 ? Math.PI : 0);
          _F.set(BB[0] + Math.cos(a) * 0.145, BB[1] + Math.sin(a) * 0.145 + 0.035, sd * 0.13);
        } else {
          _F.set(0.6, 0.71, sd * 0.15);
        }
        _pole.set(1, 0.35, sd * 0.15);
        const qs = reach(B, th, _J, _F, 0.42, 0.47, _pole, _qI);
        _q3.setFromEuler(_e.set(0, 0, pedal ? -0.15 : 0.35));
        B[th + 2].quaternion.copy(_qi.copy(qs).invert().multiply(_q3));
      }
    }
    pose({});

    const group = new T.Group();
    group.add(mesh);
    return {
      group, mesh, bones, skin: k, lights, pose,
      // rider's head, in the model's own frame (for speech bubbles)
      headTop: () => _off.set(0.03, 0.88, 0).applyQuaternion(B[5].quaternion).add(B[4].position),
    };
  }

  // ------------------------------------------------------------------ private car

  // Side profile from the 2D car, in metres: lower body with wheel arches, and the cabin.
  function arch(cx, cy, r, from, to, n = 8) {
    const out = [];
    for (let i = 0; i <= n; i++) {
      const a = from + ((to - from) * i) / n;
      out.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    }
    return out;
  }
  const CAR = {
    L: 4.04, WF: 1.244, WR: -1.2, WY: 0.3, WRAD: 0.3,
    lower() {
      return [
        [-1.867, 0.244], [-1.978, 0.333], [-1.989, 0.578],
        ...qbez([-1.989, 0.578], [-1.978, 0.778], [-1.822, 0.811], 4),
        [-1.333, 0.867], [0.689, 0.9],
        ...qbez([0.689, 0.9], [1.311, 0.844], [1.733, 0.778], 5),
        ...qbez([1.733, 0.778], [1.967, 0.733], [1.989, 0.556], 4),
        [1.989, 0.344], [1.889, 0.244],
        ...arch(1.244, 0.3, 0.378, -0.15, Math.PI + 0.15, 10),
        ...arch(-1.2, 0.3, 0.378, -0.15, Math.PI + 0.15, 10),
      ];
    },
    cabin() {
      return [
        [-1.36, 0.86],
        ...qbez([-1.36, 0.86], [-1.133, 1.122], [-0.889, 1.222], 5),
        ...qbez([-0.889, 1.222], [-0.356, 1.322], [0.133, 1.278], 6),
        ...qbez([0.133, 1.278], [0.422, 1.122], [0.72, 0.89], 5),
      ];
    },
  };
  const CAR_BONES = [['body', -1, 0, 0, 0], ['wheelF', 0, CAR.WF, CAR.WY, 0], ['wheelR', 0, CAR.WR, CAR.WY, 0], ['dent', 0, -1.97, 0.55, -0.45]];

  function carGeometry(color, plate) {
    const V = X.vehicles();
    const b = new Builder({ uv: true, skin: true, white: V.white });
    const paint = color, dark = shade(color, -0.35);
    b.bone = 0;
    b.add(extrude(CAR.lower(), 1.72, 0.05), tf(), (p, n) => (n.y < -0.5 ? '#222228' : paint));
    // cabin: dark glass under a painted roof, with pillars
    b.ow = 0.6;
    const top = qbez([-0.889, 1.222], [-0.356, 1.322], [0.133, 1.278], 6);
    const roof = [[-0.95, 1.205], ...top.map((p) => [p[0], p[1] + 0.012]), [0.19, 1.255], ...top.slice().reverse().map((p) => [p[0], p[1] - 0.05])];
    b.add(extrude(roof, 1.6, 0.02), tf(), paint);
    for (const s of [-1, 1]) {
      b.rod([0.72, 0.89, s * 0.775], [0.15, 1.27, s * 0.775], 0.035, paint);
      b.rod([-1.36, 0.86, s * 0.775], [-0.9, 1.215, s * 0.775], 0.05, paint);
      b.box(-0.27, 1.08, s * 0.78, 0.08, 0.42, 0.03, paint);
      b.box(0.6, 0.97, s * 0.9, 0.08, 0.07, 0.12, dark); // mirror
      b.box(0.15, 0.78, s * 0.865, 0.1, 0.025, 0.012, dark); // door handles
      b.box(-0.6, 0.78, s * 0.865, 0.1, 0.025, 0.012, dark);
    }
    b.ow = 1;
    // inside: the chauffeur in his cap on the right, the saheb behind on the left
    b.ow = 0;
    b.box(-0.6, 0.86, 0, 0.6, 0.08, 1.4, '#3a3036');
    b.box(0.05, 1.0, 0.33, 0.24, 0.3, 0.3, '#e8e8e2');
    b.ball(0.06, 1.2, 0.33, 0.09, 0.1, 0.09, '#8a5a3c', 8);
    b.cyl(0.06, 1.27, 0.33, 0.1, 0.05, '#2b3445', 10);
    b.box(0.13, 1.25, 0.33, 0.07, 0.015, 0.16, '#1a1d24');
    b.box(-0.75, 1.0, -0.3, 0.26, 0.32, 0.36, '#4a5a72');
    b.ball(-0.73, 1.21, -0.3, 0.1, 0.11, 0.1, '#a26b49', 8);
    b.dome(-0.74, 1.24, -0.3, 0.1, 0.07, 0.1, HAIR, 8);
    b.ow = 1;
    // bumpers, lights, number plates
    b.box(-1.995, 0.38, 0, 0.1, 0.14, 1.66, '#3a3d44');
    b.box(2.0, 0.37, 0, 0.1, 0.14, 1.66, '#3a3d44');
    b.ow = 0.5;
    for (const s of [-1, 1]) {
      b.box(-1.995, 0.7, s * 0.62, 0.05, 0.11, 0.3, '#e63946');
      b.box(-1.995, 0.62, s * 0.62, 0.05, 0.04, 0.3, '#ffb703');
      b.box(1.975, 0.66, s * 0.6, 0.06, 0.1, 0.32, '#fff6c4');
      b.box(1.99, 0.56, s * 0.7, 0.05, 0.05, 0.12, '#ffb703');
    }
    b.ow = 0;
    b.quad([-2.052, 0.52, 0], [0, 0, 0.26], [0, 0.065, 0], V.plate(plate));
    b.quad([2.055, 0.47, 0], [0, 0, -0.26], [0, 0.065, 0], V.plate(plate));
    b.ow = 1;
    b.bone = 3;
    b.ow = 0;
    b.box(-1.99, 0.55, -0.45, 0.06, 0.18, 0.34, '#2a2228');
    b.ball(-1.985, 0.6, -0.4, 0.05, 0.08, 0.14, shade(color, -0.55), 6);
    b.ow = 1;
    for (const [bone, wx] of [[1, CAR.WF], [2, CAR.WR]]) {
      b.bone = bone;
      for (const s of [-1, 1]) carWheel(b, wx, CAR.WY, s * 0.77, CAR.WRAD, 0.2, '#c6ced8');
    }
    return b.build();
  }

  const glassMat = new T.MeshLambertMaterial({ color: '#2a3a4a', transparent: true, opacity: 0.62 });
  const cabinGlass = () => cached('carGlass', () => {
    const g = extrude(CAR.cabin().concat([[0.72, 0.86], [-1.36, 0.86]]), 1.56, 0.03);
    g.computeBoundingSphere();
    return g;
  });

  /* Private car. pose(s): wheel, dent (bool). lights(): head and tail lamps. */
  function makeCar(color, plate = 0) {
    const geo = cached('car:' + color + ':' + plate, () => carGeometry(color, plate));
    const { mesh, bones } = instance(geo, CAR_BONES, atlasMat(X.vehicles().tex), 0.016);
    const group = new T.Group();
    group.add(mesh);
    const glass = new T.Mesh(cabinGlass(), glassMat);
    mesh.add(glass);
    bones[3].scale.setScalar(0.001);
    return {
      group, mesh, bones,
      lights: { head: [[2.0, 0.66, -0.6], [2.0, 0.66, 0.6]], tail: [[-2.03, 0.7, -0.62], [-2.03, 0.7, 0.62]], corners: [[-2.02, 0.62, -0.75], [-2.02, 0.62, 0.75], [2.0, 0.56, -0.75], [2.0, 0.56, 0.75]] },
      pose(s) {
        bones[1].rotation.z = bones[2].rotation.z = -(s.wheel || 0);
        bones[3].scale.setScalar(s.dent ? 1 : 0.001);
      },
    };
  }

  // ------------------------------------------------------------------ local bus

  const BUS = { HL: 3.29, HW: 1.18, Y0: 0.6, Y1: 2.85, WF: 2.07, WR: -1.96, WY: 0.45, WRAD: 0.45 };
  const BUS_BONES = [['body', -1, 0, 0, 0], ['wheelF', 0, BUS.WF, BUS.WY, 0], ['wheelR', 0, BUS.WR, BUS.WY, 0], ['helper', 0, 2.9, 0.62, -1.2], ['wave', 3, 2.9, 1.5, -1.42]];

  function busGeometry(color) {
    const V = X.bus(color);
    const { HL, HW, Y0, Y1 } = BUS;
    const yc = (Y0 + Y1) / 2, hh = (Y1 - Y0) / 2;
    const b = new Builder({ uv: true, skin: true, white: V.white });
    b.bone = 0;
    // painted sides, back and front
    b.quad([0, yc, -HW], [-HL, 0, 0], [0, hh, 0], V.side);
    b.quad([0, yc, HW], [HL, 0, 0], [0, hh, 0], V.side);
    b.quad([-HL, yc, 0], [0, 0, HW], [0, hh, 0], V.back);
    b.quad([HL, yc, 0], [0, 0, -HW], [0, hh, 0], V.front);
    // roof with rounded edges, skirt, bumpers, wheel arches
    b.box(0, Y1 + 0.02, 0, HL * 2, 0.04, HW * 2 - 0.1, '#f4efe1');
    for (const s of [-1, 1]) b.cyl(0, Y1 - 0.03, s * (HW - 0.05), 0.07, HL * 2, '#f4efe1', 8, 0, 0, Math.PI / 2);
    b.box(0, Y0 - 0.12, 0, HL * 2 - 0.3, 0.24, HW * 2 - 0.2, '#26262c');
    b.box(-HL - 0.06, 0.62, 0, 0.14, 0.2, HW * 2, '#2b2b31');
    b.box(HL + 0.06, 0.62, 0, 0.14, 0.2, HW * 2, '#2b2b31');
    for (const wx of [BUS.WF, BUS.WR]) {
      for (const s of [-1, 1]) b.box(wx, Y0 + 0.02, s * (HW + 0.015), 1.15, 0.08, 0.03, shade(color, -0.4));
    }
    // ladder up the back
    b.ow = 0.5;
    for (const z of [-0.95, -0.7]) b.rod([-HL - 0.05, 0.9, z], [-HL - 0.05, Y1 + 0.05, z], 0.015, '#9aa1a8');
    for (let y = 1.0; y < Y1; y += 0.25) b.rod([-HL - 0.05, y, -0.95], [-HL - 0.05, y, -0.7], 0.01, '#9aa1a8');
    b.rod([-HL + 0.1, 0.5, 0.85], [-HL - 0.1, 0.48, 0.85], 0.04, '#3a3a40');
    b.ow = 1;
    // the helper hanging out of the front door, calling the route (bones 3 and 4)
    b.bone = 3;
    const hx = 2.9, hz = -1.2;
    b.box(hx, 0.92, hz - 0.08, 0.12, 0.6, 0.12, '#3a3f58');
    b.box(hx, 1.45, hz - 0.15, 0.2, 0.5, 0.28, '#f28482', 0.3);
    b.ball(hx, 1.82, hz - 0.24, 0.11, 0.12, 0.11, '#7a4a2e', 8);
    b.dome(hx - 0.01, 1.85, hz - 0.24, 0.115, 0.08, 0.115, HAIR, 8);
    b.rod([hx, 1.6, hz - 0.05], [hx + 0.05, 1.7, hz + 0.12], 0.035, '#7a4a2e');
    b.bone = 4;
    b.rod([hx, 1.55, hz - 0.22], [hx + 0.1, 1.75, hz - 0.5], 0.035, '#7a4a2e');
    b.rod([hx + 0.1, 1.75, hz - 0.5], [hx + 0.15, 2.05, hz - 0.55], 0.032, '#7a4a2e');
    b.ball(hx + 0.15, 2.08, hz - 0.55, 0.045, 0.05, 0.045, '#7a4a2e', 6);
    for (const [bone, wx] of [[1, BUS.WF], [2, BUS.WR]]) {
      b.bone = bone;
      for (const s of [-1, 1]) carWheel(b, wx, BUS.WY, s * (HW - 0.12), BUS.WRAD, 0.3, '#6c7480');
    }
    return b.build();
  }

  const busMats = new Map();
  function busMaterial(color) {
    let m = busMats.get(color);
    if (!m) {
      m = MAT.toon({ map: X.bus(color).tex, vertexColors: true, emissive: new T.Color('#ffffff'), emissiveMap: X.busGlow(), emissiveIntensity: 0 });
      busMats.set(color, m);
    }
    return m;
  }

  /* Local bus. pose(s): wheel, t (the helper waves). Its windows glow at night (setNight). */
  function makeBus(color) {
    const geo = cached('bus:' + color, () => busGeometry(color));
    const { mesh, bones } = instance(geo, BUS_BONES, busMaterial(color), 0.02);
    const group = new T.Group();
    group.add(mesh);
    return {
      group, mesh, bones,
      lights: { head: [[3.31, 0.95, -0.88], [3.31, 0.95, 0.88]], tail: [[-3.31, 0.95, -1.02], [-3.31, 0.95, 1.02]], exhaust: [-3.4, 0.5, 0.85] },
      pose(s) {
        bones[1].rotation.z = bones[2].rotation.z = -(s.wheel || 0);
        const t = s.t || 0;
        bones[3].rotation.set(-0.1 + Math.sin(t * 2) * 0.04, 0, 0);
        bones[4].rotation.set(Math.sin(t * 6) * 0.35, 0, 0);
      },
    };
  }
  makeBus.setNight = (on) => {
    for (const m of busMats.values()) m.emissiveIntensity = on ? 0.9 : 0;
  };

  // ------------------------------------------------------------------ CNG

  const CNG = { WF: 1.02, WR: -0.69, WY: 0.22, WRAD: 0.22 };
  const CNG_BONES = [['body', -1, 0, 0, 0], ['wheelF', 0, CNG.WF, CNG.WY, 0], ['wheelR', 0, CNG.WR, CNG.WY, 0]];

  function cngGeometry() {
    const V = X.vehicles();
    const b = new Builder({ uv: true, skin: true, white: V.white });
    const body = '#2f9e44', roof = '#1d5f2f';
    b.bone = 0;
    const tub = [
      [-1.111, 0.222], [-1.2, 0.95], [1.0, 0.956],
      ...qbez([1.0, 0.956], [1.333, 0.911], [1.378, 0.533], 5),
      [1.356, 0.222],
      ...arch(CNG.WF, 0.222, 0.27, -0.1, Math.PI + 0.1, 8),
      ...arch(CNG.WR, 0.222, 0.27, -0.1, Math.PI + 0.1, 8),
    ];
    b.add(extrude(tub, 1.3, 0.05), tf(), (p, n) => (n.y < -0.5 ? '#1b2a20' : body));
    const cab = [
      [-1.2, 0.94], [-1.2, 1.111],
      ...qbez([-1.2, 1.111], [-1.222, 1.622], [-0.733, 1.644], 5),
      [0.578, 1.644],
      ...qbez([0.578, 1.644], [0.778, 1.633], [0.822, 1.489], 3),
      [1.0, 0.95],
    ];
    b.add(extrude(cab, 1.24, 0.03), tf(), (p, n) => (n.y > 0.55 ? roof : n.x > 0.35 && p.x > 0.5 ? '#9cc3d5' : n.x < -0.4 ? body : '#13241a'));
    // the locked grille doors Dhaka CNGs are known for
    b.ow = 0;
    for (const s of [-1, 1]) {
      for (let x = -1.05; x <= 0.12; x += 0.1) b.rod([x, 0.97, s * 0.63], [x, 1.56, s * 0.63], 0.008, '#b3bbc4', 4);
      for (const y of [1.0, 1.27, 1.55]) b.rod([-1.08, y, s * 0.63], [0.15, y, s * 0.63], 0.01, '#b3bbc4', 4);
      b.rod([0.2, 0.95, s * 0.63], [0.2, 1.62, s * 0.63], 0.02, roof, 4);
    }
    // driver at the wheel
    b.box(0.45, 1.12, 0, 0.22, 0.3, 0.32, '#e9c46a');
    b.ball(0.47, 1.36, 0, 0.09, 0.1, 0.09, '#7a4a2e', 8);
    b.dome(0.46, 1.39, 0, 0.095, 0.06, 0.095, HAIR, 8);
    b.ow = 1;
    // painted back and front, lamps
    b.quad([-1.2, 0.6, 0], [0, 0, 0.6], [-0.04, 0.3, 0], V.cngBack);
    b.quad([1.4, 0.56, 0], [0, 0, -0.5], [0.0, 0.25, 0], V.cngFront);
    b.box(-0.2, 0.95, 0, 2.1, 0.03, 1.32, '#ffffff');
    b.bone = 1;
    carWheel(b, CNG.WF, CNG.WY, 0, CNG.WRAD, 0.14, '#aeb6c0');
    b.bone = 2;
    for (const s of [-1, 1]) carWheel(b, CNG.WR, CNG.WY, s * 0.55, CNG.WRAD, 0.14, '#aeb6c0');
    return b.build();
  }

  function makeCNG() {
    const geo = cached('cng', cngGeometry);
    const { mesh, bones } = instance(geo, CNG_BONES, atlasMat(X.vehicles().tex), 0.014);
    const group = new T.Group();
    group.add(mesh);
    return {
      group, mesh, bones,
      lights: { head: [[1.42, 0.72, 0]], tail: [[-1.24, 0.82, -0.5], [-1.24, 0.82, 0.5]] },
      pose(s) {
        bones[1].rotation.z = bones[2].rotation.z = -(s.wheel || 0);
      },
    };
  }

  // ------------------------------------------------------------------ people

  const PEOPLE = {
    office: { skin: '#9a6444', top: '#e9f1fb', sleeves: 'long', bottom: 'pants', pants: '#2b3445', tie: '#c1121f', hair: 'side', prop: 'phone' },
    saree: { skin: '#a26b49', top: '#ffd23f', bottom: 'saree', hair: 'long', prop: 'handbag' },
    lungi: { skin: '#7a4a2e', top: '#7fb3d5', bottom: 'lungi', lungi: 'lungiGreen', hair: 'short', prop: 'bazar', mustache: true },
    student: { skin: '#b47a55', top: '#ffffff', bottom: 'pants', pants: '#1d3557', hair: 'short', prop: 'backpack', bag: '#e63946' },
    hawker: { skin: '#6f4329', top: 'vest', bottom: 'lungi', lungi: 'lungiPurple', hair: 'short', prop: 'basket', mustache: true },
  };
  const P_SH = 1.18, P_HIP = 0.86;
  const PERSON_BONES = [
    ['hips', -1, 0, P_HIP, 0],
    ['spine', 0, 0, P_HIP, 0],
    ['head', 1, 0, 1.26, 0],
    ['armL', 1, 0, P_SH, -0.21],
    ['foreL', 3, 0, P_SH - 0.26, -0.21],
    ['armR', 1, 0, P_SH, 0.21],
    ['foreR', 5, 0, P_SH - 0.26, 0.21],
    ['thighL', 0, 0, 0.84, -0.09],
    ['shinL', 7, 0, 0.44, -0.09],
    ['thighR', 0, 0, 0.84, 0.09],
    ['shinR', 9, 0, 0.44, 0.09],
  ];

  function personGeometry(type) {
    const p = PEOPLE[type] || PEOPLE.lungi;
    const AT = X.people();
    const b = new Builder({ uv: true, skin: true, white: AT.white });
    const top = p.top === 'vest' ? '#f4f1ea' : p.top;
    const skirt = p.bottom !== 'pants';
    // hips: skirt (lungi or saree) or trousers' seat
    b.bone = 0;
    if (skirt) {
      b.uvr = p.bottom === 'saree' ? AT.saree : AT[p.lungi];
      b.ecyl(0, 0.48, 0, 0.21, 0.24, 0.82, '#ffffff', 12, 0, 0, 0, 0.72);
      b.uvr = null;
    } else {
      b.ecyl(0, 0.84, 0, 0.12, 0.19, 0.12, p.pants, 10);
      b.box(0, 0.88, 0, 0.25, 0.04, 0.4, '#1b1b1f');
    }
    // torso
    b.bone = 1;
    b.ecyl(0, 1.05, 0, 0.115, 0.19, 0.4, top, 10, 0, 0, 0, 1.08);
    for (const s of [-1, 1]) b.ball(0, P_SH, s * 0.19, 0.06, 0.06, 0.06, p.top === 'vest' ? p.skin : top, 8);
    b.cyl(0, 1.27, 0, 0.05, 0.08, p.skin, 8);
    if (p.top === 'vest') b.ball(0.09, 1.2, 0, 0.035, 0.05, 0.08, p.skin, 8);
    if (p.tie) b.box(0.118, 1.06, 0, 0.012, 0.26, 0.05, p.tie);
    if (p.prop === 'backpack') {
      b.box(-0.18, 1.04, 0, 0.16, 0.34, 0.32, shade(p.bag, -0.15));
      for (const s of [-1, 1]) b.box(0.0, 1.1, s * 0.13, 0.25, 0.04, 0.04, p.bag);
    }
    if (p.bottom === 'saree') {
      // the pallu across the chest and over the left shoulder
      b.uvr = AT.saree;
      b.box(0.02, 1.05, -0.03, 0.25, 0.46, 0.13, '#ffffff', 0.55, 0, 0);
      b.box(-0.14, 0.95, -0.15, 0.04, 0.42, 0.14, '#ffffff', 0, 0, 0.05);
      b.uvr = null;
    }
    // head
    b.bone = 2;
    b.ball(0, 1.39, 0, 0.12, 0.135, 0.12, p.skin, 12);
    for (const s of [-1, 1]) {
      b.ball(-0.005, 1.39, s * 0.12, 0.02, 0.035, 0.015, p.skin, 6);
      b.ball(0.108, 1.405, s * 0.045, 0.013, 0.017, 0.013, INK, 6);
      b.box(0.11, 1.44, s * 0.045, 0.01, 0.01, 0.045, HAIR);
    }
    b.ball(0.12, 1.38, 0, 0.02, 0.028, 0.02, shade(p.skin, -0.15), 6);
    b.box(0.112, 1.33, 0, 0.012, 0.012, 0.05, '#5a1a1a');
    if (p.mustache) b.box(0.118, 1.352, 0, 0.018, 0.016, 0.075, HAIR);
    b.dome(-0.01, 1.42, 0, 0.128, 0.1, 0.125, HAIR, 12, 0, 0, 0.3);
    if (p.hair === 'side') b.box(0.07, 1.505, 0.02, 0.1, 0.03, 0.2, HAIR, 0.3, 0, 0);
    if (p.hair === 'long') {
      b.box(-0.08, 1.2, 0, 0.1, 0.42, 0.26, HAIR);
      b.ball(-0.11, 1.42, 0, 0.06, 0.06, 0.06, HAIR, 8);
    }
    if (p.prop === 'basket') {
      b.ecyl(0, 1.57, 0, 0.27, 0.27, 0.09, '#c8963e', 12);
      const fruit = [[0.1, 0.05], [-0.1, 0.08], [0.0, -0.12], [0.14, -0.08], [-0.13, -0.06], [0, 0.03]];
      fruit.forEach(([fx, fz], i) => b.ball(fx, 1.66, fz, 0.06, 0.06, 0.06, i < 4 ? '#ff9f1c' : '#9bd36a', 6));
      b.ball(0.05, 1.7, 0.12, 0.03, 0.1, 0.03, '#f4d03f', 6, false, 0.5);
    }
    // arms
    const sleeve = p.top === 'vest' ? null : top;
    for (const s of [-1, 1]) {
      const sz = s * 0.21;
      const up = s < 0 ? 3 : 5;
      b.bone = up;
      if (sleeve) b.cyl(0, P_SH - (p.sleeves === 'long' ? 0.13 : 0.08), sz, 0.05, p.sleeves === 'long' ? 0.26 : 0.16, sleeve, 8);
      b.cyl(0, P_SH - 0.13, sz, 0.04, 0.26, p.skin, 8);
      b.bone = up + 1;
      b.ball(0, P_SH - 0.26, sz, 0.038, 0.038, 0.038, p.sleeves === 'long' ? sleeve : p.skin, 8);
      b.cyl(0, P_SH - 0.38, sz, 0.036, 0.24, p.sleeves === 'long' ? sleeve : p.skin, 8, 0, 0, 0, 1.05);
      b.ball(0, P_SH - 0.52, sz, 0.042, 0.048, 0.04, p.skin, 8);
      const hy = P_SH - 0.55;
      if (s > 0 && p.prop === 'phone') b.box(0.02, hy + 0.04, sz + 0.03, 0.04, 0.11, 0.02, '#1c1c22');
      if (s < 0 && p.prop === 'phone') {
        b.box(0, hy - 0.13, sz, 0.32, 0.22, 0.07, '#6b4423');
        b.box(0, hy - 0.01, sz, 0.1, 0.03, 0.02, '#3b2614');
      }
      if (s < 0 && p.prop === 'handbag') {
        b.box(0, hy - 0.08, sz - 0.02, 0.2, 0.16, 0.08, '#7b2cbf');
        b.rod([0, hy + 0.01, sz - 0.02], [0.08, hy - 0.02, sz - 0.02], 0.008, '#3c096c', 4);
      }
      if (s < 0 && p.prop === 'bazar') {
        b.box(0, hy - 0.14, sz, 0.24, 0.24, 0.12, '#a47148');
        for (let i = 0; i < 3; i++) b.ball(-0.06 + i * 0.05, hy - 0.0, sz, 0.025, 0.08, 0.025, '#3f9b3a', 6, false, 0, 0, -0.4 + i * 0.4);
        b.box(0.1, hy - 0.01, sz, 0.08, 0.05, 0.02, '#c9d3dc', 0, 0, 0.6);
      }
    }
    // legs
    for (const s of [-1, 1]) {
      const z = s * 0.09;
      const th = s < 0 ? 7 : 9;
      b.bone = th;
      if (!skirt) b.cyl(0, 0.64, z, 0.07, 0.4, p.pants, 8, 0, 0, 0, 1.1);
      b.bone = th + 1;
      if (!skirt) {
        b.cyl(0, 0.24, z, 0.058, 0.4, p.pants, 8, 0, 0, 0, 1.1);
        b.box(0.04, 0.03, z, 0.22, 0.06, 0.1, '#231a16');
      } else {
        b.cyl(0, 0.1, z, 0.045, 0.16, p.skin, 8);
        b.box(0.04, 0.02, z, 0.2, 0.035, 0.09, '#6b3f1d');
      }
    }
    return b.build();
  }

  /* A pedestrian. pose(s): walk (stride phase, radians), speed (0 standing, 1 walking,
   * 2 running), angry (shaking a fist), t. They face +x. */
  function makePerson(type) {
    const p = PEOPLE[type] || PEOPLE.lungi;
    const geo = cached('person:' + type, () => personGeometry(type));
    const { mesh, bones } = instance(geo, PERSON_BONES, atlasMat(X.people().tex), 0.012);
    const B = bones;
    const skirt = p.bottom !== 'pants';
    const group = new T.Group();
    group.add(mesh);
    function pose(s) {
      const t = s.t || 0;
      const sp = s.speed == null ? 1 : s.speed;
      const ph = s.walk || 0;
      const amp = (skirt ? 0.28 : 0.45) * Math.min(1.4, sp);
      const sw = Math.sin(ph);
      B[0].position.y = P_HIP + Math.abs(Math.cos(ph)) * 0.025 * Math.min(1, sp);
      B[1].rotation.set(0, sw * 0.08 * sp, sp > 1.5 ? -0.25 : 0);
      B[2].rotation.set(0, 0, sp > 1.5 ? 0.2 : 0);
      B[7].rotation.set(0, 0, sw * amp);
      B[9].rotation.set(0, 0, -sw * amp);
      B[8].rotation.set(0, 0, -Math.max(0, -Math.sin(ph + 0.7)) * amp * 1.3);
      B[10].rotation.set(0, 0, -Math.max(0, Math.sin(ph + 0.7)) * amp * 1.3);
      const arm = 0.35 * Math.min(1.5, sp);
      B[3].rotation.set(0.08, 0, -sw * arm);
      B[4].rotation.set(0, 0, 0.25 + (sp > 1.5 ? 0.9 : 0));
      B[5].rotation.set(-0.08, 0, sw * arm);
      B[6].rotation.set(0, 0, 0.25 + (sp > 1.5 ? 0.9 : 0));
      // the right arm: shaking a fist at the rickshaw, phone to the ear, or holding the basket
      let hand = null;
      if (s.angry) {
        hand = _H.set(0.16, 1.66 + Math.sin(t * 28) * 0.04, 0.3);
        _pole.set(0.2, -0.6, 1);
      } else if (p.prop === 'phone') {
        hand = _H.set(0.03, 1.37, 0.17);
        _pole.set(0.4, -1, 0.7);
      } else if (p.prop === 'basket') {
        hand = _H.set(0.04, 1.56, 0.27);
        _pole.set(0, -0.3, 1);
      }
      if (hand) {
        _S.set(0, P_SH - P_HIP, 0.21).applyQuaternion(B[1].quaternion).add(B[0].position);
        reach(B, 5, _S, hand, 0.26, 0.27, _pole, B[1].quaternion);
      }
    }
    pose({ speed: 0 });
    return { group, mesh, bones, pose, type, headY: 1.55 };
  }

  // ------------------------------------------------------------------ pickups and road works

  function bolt3(b, x, y, z, h, color, depth = 0.04, rz = 0) {
    const k = h / 20;
    const shape = [[2, 10], [-5, -1], [-0.5, -1], [-2, -10], [5, 2], [0.5, 2]].map(([px, py]) => [px * k, py * k]);
    b.add(extrude(shape, depth, 0), tf(x, y, z, 0, 0, rz), color);
  }

  const pickupGeos = {
    coin() {
      const P = X.props();
      const b = new Builder({ uv: true, white: P.white });
      b.uvr = P.coin;
      b.cyl(0, 0, 0, 0.2, 0.05, '#ffffff', 20, Math.PI / 2);
      return b.build();
    },
    battery() {
      const P = X.props();
      const b = new Builder({ uv: true, white: P.white });
      b.cyl(0, 0, 0, 0.12, 0.36, '#20242c', 14);
      b.cyl(0, 0.2, 0, 0.05, 0.05, '#c9d1da', 10);
      for (const y of [-0.12, -0.04, 0.04]) b.cyl(0, y, 0, 0.123, 0.05, '#39ff88', 14);
      bolt3(b, 0, 0.0, 0.125, 0.22, '#ffd23f', 0.02);
      bolt3(b, 0, 0.0, -0.125, 0.22, '#ffd23f', 0.02);
      return b.build();
    },
    boost() {
      // a lightning bolt in a blue ring
      const P = X.props();
      const b = new Builder({ uv: true, white: P.white });
      b.ring(0, 0, 0, 0.21, 0.045, '#4cc3ff', 20);
      b.ow = 0.6;
      b.ring(0, 0, 0, 0.21, 0.02, '#1d2f6f', 20, Math.PI / 2);
      b.ow = 1;
      bolt3(b, 0, 0, 0, 0.36, '#ffd23f', 0.07);
      return b.build();
    },
    tea() {
      // a glass of milk tea on its saucer
      const P = X.props();
      const b = new Builder({ uv: true, white: P.white });
      b.cyl(0, -0.13, 0, 0.17, 0.025, '#f4f1ea', 16);
      b.cyl(0, -0.02, 0, 0.075, 0.2, '#c27c3e', 12, 0, 0, 0, 1.3);
      b.cyl(0, 0.083, 0, 0.098, 0.012, '#e8c79a', 12);
      b.ow = 0.5;
      b.ring(0, 0.088, 0, 0.098, 0.008, '#ffffff', 16, Math.PI / 2);
      return b.build();
    },
  };

  /* coin | battery | boost | tea: hovers and spins (the view moves it). */
  function makePickup(kind) {
    const geo = cached('pickup:' + kind, pickupGeos[kind]);
    const mesh = new T.Mesh(geo, atlasMat(X.props().tex));
    outline(mesh, 0.012);
    const group = new T.Group();
    group.add(mesh);
    return { group, mesh, kind };
  }

  // Road works blocking a lane: barrier, "সাবধান" sign, blinker and cones. Faces back down the road (-x).
  function barricadeGeometry() {
    const P = X.props();
    const b = new Builder({ uv: true, white: P.white });
    for (const s of [-1, 1]) {
      const z = s * 0.95;
      b.rod([-0.12, 0, z], [0, 0.85, z], 0.025, '#6c737b');
      b.rod([0.12, 0, z], [0, 0.85, z], 0.025, '#6c737b');
    }
    b.box(0, 0.68, 0, 0.06, 0.26, 2.2, '#ffffff');
    b.ow = 0;
    b.quad([-0.032, 0.68, 0], [0, 0, 1.1], [0, 0.13, 0], P.stripes);
    b.quad([0.032, 0.68, 0], [0, 0, -1.1], [0, 0.13, 0], P.stripes);
    b.ow = 1;
    b.rod([0, 0.81, 0], [0, 1.05, 0], 0.02, '#6c737b');
    b.box(0, 1.27, 0, 0.04, 0.46, 0.92, '#ffd23f');
    b.ow = 0;
    b.quad([-0.022, 1.27, 0], [0, 0, 0.44], [0, 0.22, 0], P.caution);
    b.quad([0.022, 1.27, 0], [0, 0, -0.44], [0, 0.22, 0], P.caution);
    b.ow = 1;
    b.rod([0, 1.5, 0], [0, 1.6, 0], 0.012, '#6c737b');
    b.ball(0, 1.64, 0, 0.05, 0.05, 0.05, '#c1121f', 8);
    for (const s of [-1, 1]) {
      const z = s * 1.25;
      b.box(0, 0.02, z, 0.34, 0.04, 0.34, '#ff7a00');
      b.cyl(0, 0.3, z, 0.13, 0.56, '#ff7a00', 10, 0, 0, 0, 0.18);
      b.cyl(0, 0.33, z, 0.1, 0.1, '#ffffff', 10, 0, 0, 0, 0.75);
    }
    return b.build();
  }

  function makeBarricade() {
    const mesh = new T.Mesh(cached('barricade', barricadeGeometry), atlasMat(X.props().tex));
    outline(mesh, 0.014);
    const group = new T.Group();
    group.add(mesh);
    return { group, mesh, lights: { blink: [0, 1.64, 0] } };
  }

  window.BT.models3 = {
    RK, makeRickshaw, makeCar, makeBus, makeCNG, makePerson, makePickup, makeBarricade,
    PEOPLE, atlasMat, cached, ik, aim,
  };
})();
