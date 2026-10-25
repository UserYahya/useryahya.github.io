/* বাংলা টেসলা 3D — the 3D view of a race. It owns the WebGL renderer, the scene and the
 * camera, keeps a model for everything in the race (the race itself stays the same as in
 * 2D) and draws the effects: shadows, headlights and street lamps at night, the hood LEDs,
 * boost sparks, splashes, bus smoke and the monsoon rain.
 *
 *   const view = new BT.View3D(canvas, { touch })
 *   view.render(race, dt)              every frame
 *   view.project(x, gy, h)             race point → overlay screen point (for bubbles and bursts)
 *   view.snapshot(skin, canvas2d)      garage preview of a rickshaw skin
 *
 * The race runs along a straight line; the city's road path bends it onto the real streets.
 * Everything is placed in road coordinates (s metres down the road, lateral metres across it,
 * height) and turned into world points by the path, the camera included. */
(function () {
  'use strict';

  const { T, K, LW, Batch, setAniso, outlineMaterial, MAT } = window.BT.k3;
  const X = window.BT.tex3;
  const M3 = window.BT.models3;
  const C3 = window.BT.city3;
  const A = window.BT.art;
  const S = window.BT.scenery;
  const hash = A.hash;

  const laneX = (y) => ((y - 603) / 95) * LW; // race ground y → metres across the road
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const lerp = (a, b, k) => a + (b - a) * k;
  const smooth = (p) => p * p * (3 - 2 * p);

  const DAY = {
    zenith: '#5fb0e4', mid: '#b9dcec', horizon: '#eadfca', fog: '#e4dac6', fogNear: 30, fogFar: 150,
    hemiSky: '#eef6ff', hemiGround: '#a08f74', hemi: 0.58, sun: '#fff1d6', sunI: 0.62,
  };
  const NIGHT = {
    zenith: '#060a22', mid: '#151c46', horizon: '#3a2f55', fog: '#24223f', fogNear: 18, fogFar: 115,
    hemiSky: '#7b86c9', hemiGround: '#2a2238', hemi: 0.5, sun: '#9fb3ff', sunI: 0.22,
  };

  const LAMP = { sodium: '#ffc47a', led: '#e8f1ff', flood: '#fff2c4', tea: '#ffcf80', lantern: '#ffb347' };
  const C = (c) => new T.Color(c);
  const COL = {
    head: C('#fff4d0'), tail: C('#ff3a3a'), amber: C('#ffb703'), green: C('#39ff88'), blue: C('#4cc3ff'),
    gold: C('#ffd23f'), warm: C('#ffb347'), red: C('#ff3b3b'), white: C('#ffffff'),
    sodium: C(LAMP.sodium), led: C(LAMP.led), flood: C(LAMP.flood), tea: C(LAMP.tea), lantern: C(LAMP.lantern),
    smoke: C('#56545e'), steam: C('#f2f2f2'), splash: C('#cfe0f2'), dust: C('#b9a58e'),
    led1: C('#ff4fa3'), led2: C('#4cc3ff'), led3: C('#ffd23f'),
  };

  // ------------------------------------------------------------------ sky

  function skyline(night) {
    // hazy far-off towers all round the horizon, painted once for day and once for night
    return window.BT.k3.canvasTex(2048, 256, (c) => {
      const cols = night ? ['#1d2347', '#232a54', '#1a1f40'] : ['#b2bccb', '#a5b2c4', '#bcc6d4'];
      for (let i = 0; i < 90; i++) {
        const w = 18 + hash(i * 3 + 1) * 34, h = 30 + hash(i * 7 + 2) * 150;
        const x = hash(i * 11 + 5) * 2048;
        c.fillStyle = cols[i % 3];
        c.fillRect(x, 256 - h, w, h);
        if (hash(i * 5) > 0.9) {
          c.beginPath();
          c.arc(x + w / 2, 256 - h, w * 0.3, Math.PI, 0);
          c.fill();
          c.fillRect(x + w - 4, 256 - h - 40, 3, 40);
        }
        for (let k = 0; k < (h * w) / 90; k++) {
          const v = hash(i * 977 + k);
          if (v > (night ? 0.55 : 0.6)) {
            c.fillStyle = night ? (v > 0.9 ? 'rgba(200,235,255,0.8)' : 'rgba(255,210,140,0.85)') : 'rgba(255,255,255,0.25)';
            c.fillRect(x + 3 + (k % Math.max(1, Math.floor(w / 6))) * 6, 256 - h + 5 + Math.floor(k / Math.max(1, Math.floor(w / 6))) * 8, 2.5, 3);
          }
        }
      }
      const g = c.createLinearGradient(0, 0, 0, 256);
      g.addColorStop(0, night ? 'rgba(58,47,85,0)' : 'rgba(234,223,202,0)');
      g.addColorStop(1, night ? 'rgba(58,47,85,0.55)' : 'rgba(234,223,202,0.75)');
      c.fillStyle = g;
      c.fillRect(0, 0, 2048, 256);
    }, { mips: false });
  }

  // ------------------------------------------------------------------ the view

  class View3D {
    constructor(canvas, opts = {}) {
      this.touch = !!opts.touch;
      const renderer = new T.WebGLRenderer({ canvas, antialias: !this.touch, powerPreference: 'high-performance', preserveDrawingBuffer: !!opts.capture });
      this.renderer = renderer;
      renderer.setClearColor('#e4dac6');
      setAniso(Math.min(4, renderer.capabilities.getMaxAnisotropy()));
      this.maxDpr = Math.min(window.devicePixelRatio || 1, this.touch ? 1.5 : 1.75);
      this.dpr = this.touch ? Math.min(this.maxDpr, 1.25) : this.maxDpr;
      this.W = 1280;
      this.H = 720;

      const scene = (this.scene = new T.Scene());
      scene.fog = new T.Fog(DAY.fog, DAY.fogNear, DAY.fogFar);
      this.hemi = new T.HemisphereLight(DAY.hemiSky, DAY.hemiGround, DAY.hemi);
      this.sun = new T.DirectionalLight(DAY.sun, DAY.sunI);
      this.sun.position.set(-25, 50, 35);
      scene.add(this.hemi, this.sun);
      this.spot = new T.SpotLight('#fff2c4', 0, 42, 0.5, 0.65, 1);
      scene.add(this.spot, this.spot.target);
      this.camera = new T.PerspectiveCamera(58, 16 / 9, 0.1, 700);

      this.buildSky();
      this.buildBatches();
      this.buildRain();
      this.city = null;
      this.theme = null;
      this.race = null;
      this.night = null;
      this.live = new Map();
      this.pools = new Map();
      this.oncoming = [];
      // the camera and the point it looks at, in road coordinates (lateral, height, s)
      this.camR = new T.Vector3(0, 2.5, -6);
      this.lookR = new T.Vector3(0, 1, 8);
      this.camLook = new T.Vector3();
      this.camS = 0;
      this.camX = 0;
      this.boostK = 0;
      this.t = 0;
      this.frameMs = 16;
      this.slow = 0;
      this.fast = 0;
      this.v = new T.Vector3();
      this.v2 = new T.Vector3();
      this.v3 = new T.Vector3();
    }

    // ---------------------------------------------------------------- setup

    buildSky() {
      const g = new T.SphereGeometry(500, 24, 12);
      g.setAttribute('color', new T.Float32BufferAttribute(new Float32Array(g.attributes.position.count * 3), 3));
      this.sky = new T.Mesh(g, new T.MeshBasicMaterial({ vertexColors: true, side: T.BackSide, fog: false, depthWrite: false }));
      this.sky.renderOrder = -10;
      this.sky.frustumCulled = false;
      this.scene.add(this.sky);
      this.skyTex = { day: skyline(false), night: skyline(true) };
      for (const t of Object.values(this.skyTex)) {
        t.wrapS = T.RepeatWrapping;
        t.repeat.set(3, 1);
      }
      const cg = new T.CylinderGeometry(430, 430, 110, 48, 1, true);
      this.far = new T.Mesh(cg, new T.MeshBasicMaterial({ map: this.skyTex.day, transparent: true, fog: false, depthWrite: false, side: T.BackSide }));
      this.far.renderOrder = -9;
      this.far.frustumCulled = false;
      this.scene.add(this.far);
      // stars
      const sp = [];
      for (let i = 0; i < 420; i++) {
        const a = hash(i * 3) * Math.PI * 2, e = 0.08 + hash(i * 7) * 1.4;
        sp.push(Math.cos(a) * Math.cos(e) * 470, Math.sin(e) * 470, Math.sin(a) * Math.cos(e) * 470);
      }
      const sg = new T.BufferGeometry();
      sg.setAttribute('position', new T.Float32BufferAttribute(sp, 3));
      this.stars = new T.Points(sg, new T.PointsMaterial({ color: '#fffbe8', size: 1.6, sizeAttenuation: false, fog: false, transparent: true, opacity: 0.85, depthWrite: false }));
      this.stars.frustumCulled = false;
      this.stars.renderOrder = -8;
      this.scene.add(this.stars);
      // kites over the rooftops
      this.kites = [];
      const kc = [['#ff4fa3', '#ffd23f'], ['#35d07f', '#ff9f1c'], ['#4cc3ff', '#ffffff']];
      for (const [c1, c2] of kc) {
        const b = new window.BT.k3.Builder();
        b.tris([[0, 0.7, 0], [-0.5, 0, 0], [0, -0.7, 0], [0, 0.7, 0], [0, -0.7, 0], [0.5, 0, 0]], c1);
        b.tris([[0, 0.7, 0], [0, -0.7, 0], [-0.5, 0, 0], [0, 0.7, 0], [0.5, 0, 0], [0, -0.7, 0]], c2);
        for (let k = 0; k < 6; k++) b.box(Math.sin(k) * 0.08, -0.8 - k * 0.22, 0, 0.06, 0.2, 0.02, c1);
        const m = b.mesh(MAT.vcDouble);
        this.scene.add(m);
        this.kites.push(m);
      }
    }

    buildBatches() {
      const add = (map, blending, ground, order, max = 800) => {
        const mat = new T.MeshBasicMaterial({ map, transparent: true, depthWrite: false, blending, vertexColors: true, fog: false });
        const b = new Batch(max, mat, ground);
        b.mesh.renderOrder = order;
        this.scene.add(b.mesh);
        return b;
      };
      this.decals = add(X.decals(), T.NormalBlending, true, 1, 120);
      this.decals.mesh.material.polygonOffset = true;
      this.decals.mesh.material.polygonOffsetFactor = -3;
      this.decals.mesh.material.polygonOffsetUnits = -3;
      this.shadows = add(X.blob(), T.NormalBlending, true, 2, 200);
      this.lightPools = add(X.glow(), T.AdditiveBlending, true, 3, 300);
      this.beams = add(X.beam(), T.AdditiveBlending, true, 3, 120);
      this.puffs = add(X.puff(), T.NormalBlending, false, 5, 300);
      this.glows = add(X.glow(), T.AdditiveBlending, false, 6, 900);
      this.dots = add(X.dot(), T.AdditiveBlending, false, 7, 300);
      this.sparks = add(X.sparkle(), T.AdditiveBlending, false, 8, 200);
      this.batches = [this.decals, this.shadows, this.lightPools, this.beams, this.puffs, this.glows, this.dots, this.sparks];
      this.parts = []; // short-lived particles: { kind, x, y, z, vx, vy, vz, t, life, size, color }
    }

    buildRain() {
      const N = 900;
      this.rainN = N;
      this.rainPos = new Float32Array(N * 6);
      this.rainSeed = [];
      for (let i = 0; i < N; i++) this.rainSeed.push([hash(i * 3 + 1), hash(i * 7 + 2), hash(i * 11 + 3), 0.5 + hash(i * 13 + 4) * 0.5]);
      const g = new T.BufferGeometry();
      this.rainAttr = new T.BufferAttribute(this.rainPos, 3).setUsage(T.DynamicDrawUsage);
      g.setAttribute('position', this.rainAttr);
      this.rain = new T.LineSegments(g, new T.LineBasicMaterial({ color: '#c8d6ee', transparent: true, opacity: 0.45, fog: false, depthWrite: false }));
      this.rain.frustumCulled = false;
      this.rain.renderOrder = 9;
      this.rain.visible = false;
      this.scene.add(this.rain);
    }

    setSize(w, h, logicalW) {
      this.W = logicalW || Math.round((720 * w) / h);
      this.renderer.setPixelRatio(this.dpr);
      this.renderer.setSize(w, h, false);
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
      this.cssW = w;
      this.cssH = h;
    }

    setNight(on) {
      if (this.night === on) return;
      this.night = on;
      const P = on ? NIGHT : DAY;
      this.scene.fog.color.set(P.fog);
      this.scene.fog.near = P.fogNear;
      this.scene.fog.far = P.fogFar;
      this.renderer.setClearColor(P.fog);
      this.hemi.color.set(P.hemiSky);
      this.hemi.groundColor.set(P.hemiGround);
      this.hemi.intensity = P.hemi;
      this.sun.color.set(P.sun);
      this.sun.intensity = P.sunI;
      const g = this.sky.geometry, pos = g.attributes.position, colAttr = g.attributes.color;
      const z = C(P.zenith), m = C(P.mid), hz = C(P.horizon), c = new T.Color();
      for (let i = 0; i < pos.count; i++) {
        const e = pos.getY(i) / 500;
        if (e > 0.25) c.copy(m).lerp(z, smooth(clamp((e - 0.25) / 0.75, 0, 1)));
        else c.copy(hz).lerp(m, smooth(clamp(e / 0.25, 0, 1)));
        colAttr.setXYZ(i, c.r, c.g, c.b);
      }
      colAttr.needsUpdate = true;
      this.far.material.map = on ? this.skyTex.night : this.skyTex.day;
      this.far.material.needsUpdate = true;
      this.stars.visible = on;
      for (const k of this.kites) k.visible = !on;
      C3.setNight(on);
      M3.makeBus.setNight(on);
      this.spot.intensity = on ? 1.6 : 0;
    }

    setRace(race) {
      this.race = race;
      const id = race.route.id;
      // a real route has its own street; the made-up ones share one per look
      const key = window.BT.osm && window.BT.osm[id] ? id : C3.ROUTE_THEME[id] || 'avenue';
      if (!this.city || this.cityKey !== key) {
        if (this.city) this.city.dispose();
        this.city = new C3.City(this.scene, id, race.len / K);
        this.cityKey = key;
        this.L = this.city.L;
        this.path = this.city.path;
      }
      // drop the last race's models back into their pools
      for (const [o, e] of this.live) this.release(e);
      this.live.clear();
      for (const e of this.oncoming) this.release(e);
      this.oncoming = [];
      if (this.hero) {
        this.scene.remove(this.hero.group);
        this.hero.mesh.skeleton.dispose();
      }
      this.hero = M3.makeRickshaw(race.skin);
      this.scene.add(this.hero.group);
      this.parts = [];
      this.trainT = 4 + Math.random() * 6;
      this.train = null;
      // start and finish gates
      for (const g of this.gates || []) {
        this.scene.remove(g);
        g.traverse((o) => o.geometry && o.geometry.dispose());
      }
      this.gates = [];
      if (!race.demo && !race.route.endless) {
        this.gates.push(this.gate(race.route.from, false, 14));
        this.gates.push(this.gate(race.route.to, true, race.len / K));
      }
      this.finishS = race.route.endless || race.demo ? null : race.len / K;
      this.camX = laneX(race.hero.y);
      this.snapCam = true;
      this.city.update(race.hero.x / K, 99);
    }

    gate(label, finish, s) {
      const L = this.L;
      const x0 = -C3.ROAD - 0.6, x1 = this.L.median0 != null ? L.median0 + 0.6 : C3.ROAD + 0.6;
      const b = new window.BT.k3.Builder({ uv: true });
      const w = x1 - x0, cx = (x0 + x1) / 2;
      // built across the road at its own origin, then stood at s
      for (const x of [x0, x1]) b.box(x, 2.9, 0, 0.22, 5.8, 0.22, '#d0d4da');
      b.box(cx, 4.9, 0, w + 0.2, w / 4 + 0.1, 0.08, '#d62828');
      b.quad([cx, 4.9, 0.05], [w / 2, 0, 0], [0, w / 8, 0], [0, 0, 1, 1]);
      b.quad([cx, 4.9, -0.05], [-w / 2, 0, 0], [0, w / 8, 0], [0, 0, 1, 1]);
      const mat = MAT.toon({ map: X.banner(label, finish), vertexColors: true });
      const mesh = b.mesh(mat);
      // bunting from the banner down to the footpath
      const bb = new window.BT.k3.Builder();
      const flags = ['#ff4fa3', '#ffd23f', '#35d07f', '#4cc3ff'];
      for (const [ax, bx] of [[x0, x0 - 2.5], [x1, x1 + 2.5]]) {
        for (let i = 0; i < 8; i++) {
          const t0 = i / 8, t1 = (i + 0.5) / 8;
          const p0 = [lerp(ax, bx, t0), lerp(5.6, 3.2, t0) - Math.sin(t0 * Math.PI) * 0.4, 0];
          const p1 = [lerp(ax, bx, t1), lerp(5.6, 3.2, t1) - Math.sin(t1 * Math.PI) * 0.4, 0];
          const mid = [(p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2 - 0.3, 0];
          bb.tris([p0, p1, mid, p0, mid, p1], flags[i % 4]);
        }
      }
      mesh.add(bb.mesh(MAT.vcDouble));
      this.path.pos(s, 0, 0, mesh.position);
      mesh.rotation.y = this.groundRot(s);
      this.scene.add(mesh);
      return mesh;
    }

    // ---------------------------------------------------------------- pools

    take(key, make) {
      const list = this.pools.get(key);
      const e = list && list.length ? list.pop() : { key, m: make() };
      this.scene.add(e.m.group);
      return e;
    }

    release(e) {
      this.scene.remove(e.m.group);
      let list = this.pools.get(e.key);
      if (!list) this.pools.set(e.key, (list = []));
      list.push(e);
    }

    modelFor(o) {
      switch (o.kind) {
        case 'car': {
          const plate = Math.floor(hash(Math.round(o.x)) * 4);
          return this.take('car' + o.color + plate, () => M3.makeCar(o.color, plate));
        }
        case 'bus':
          return this.take('bus' + o.color, () => M3.makeBus(o.color));
        case 'cng':
          return this.take('cng', () => M3.makeCNG());
        case 'rival':
          return this.take('rival' + o.skin.name, () => M3.makeRickshaw(o.skin));
        case 'person':
          return this.take('person' + o.type, () => M3.makePerson(o.type));
        case 'barricade':
          return this.take('barricade', () => M3.makeBarricade());
        case 'coin':
        case 'battery':
        case 'boost':
        case 'tea':
          return this.take(o.kind, () => M3.makePickup(o.kind));
      }
      return null;
    }

    // ---------------------------------------------------------------- per frame

    render(race, dt) {
      dt = Math.min(dt || 0.016, 0.05);
      this.t += dt;
      if (race !== this.race) this.setRace(race);
      this.setNight(!!race.night);
      this.rain.visible = !!race.route.rain;
      const t = race.t;
      this.updateCamera(race, dt);
      for (const b of this.batches) b.begin(this.camera);
      this.syncHero(race, dt);
      this.syncObjects(race, dt);
      const camS = this.camS;
      this.city.update(camS, this.touch ? 1 : 2);
      this.updateOncoming(race, dt, camS);
      this.updateTrain(dt, camS);
      this.drawWorldLights(race, camS);
      this.updateParts(dt);
      this.updateRain(dt);
      this.updateSky(t);
      if (this.finishS != null) {
        // the chequered finish line across the road
        const rot = this.groundRot(this.finishS);
        for (let x = -C3.ROAD + 0.5; x < C3.ROAD; x += 1) {
          const p = this.path.pos(this.finishS, x, 0.013, this.v3);
          this.decals.add(p.x, 0.013, p.z, 1, 0.5, COL.white, 1, rot, X.decalCell(11));
        }
      }
      for (const b of this.batches) b.end();
      this.renderer.render(this.scene, this.camera);
      this.adapt(dt);
    }

    // world position of a point given in a model's own frame
    world(group, p, out) {
      return out.set(p[0], p[1], p[2]).applyMatrix4(group.matrixWorld);
    }

    place(group, x, y, gy, yaw) {
      const s = x / K;
      this.path.pos(s, laneX(gy), y, group.position);
      group.rotation.order = 'YXZ'; // so rotation.x leans the model about its own length
      group.rotation.set(0, this.path.heading(s) + yaw, 0);
      group.updateMatrixWorld(true);
    }

    // turn of a flat ground quad (or anything built along the road) lying along the road at s
    groundRot(s) {
      return this.path.heading(s) - Math.PI / 2;
    }

    // heading change from sideways motion (lane changes)
    yawFor(o, x, gy, dt) {
      const lx = laneX(gy), s = x / K;
      if (o._lx == null || dt <= 0) {
        o._lx = lx;
        o._ls = s;
        o._yaw = 0;
        return 0;
      }
      const vx = (lx - o._lx) / dt, vs = Math.max(1.5, (s - o._ls) / dt);
      o._lx = lx;
      o._ls = s;
      const want = clamp(-Math.atan2(vx, vs), -0.45, 0.45);
      o._yaw += (want - o._yaw) * Math.min(1, dt * 12);
      return o._yaw;
    }

    syncHero(race, dt) {
      const h = race.hero, m = this.hero;
      const bob = -race.heroBob() / K;
      const yaw = this.yawFor(h, h.x, h.y, dt);
      this.place(m.group, h.x, Math.max(0, bob), h.y, yaw);
      m.group.rotation.x = -yaw * 0.25; // lean into the lane change
      m.group.updateMatrixWorld(true);
      m.group.visible = !(h.invuln > 0 && h.stun <= 0 && Math.floor(race.t * 14) % 2 === 0);
      // arms up for a podium finish; last place scratches his head
      const done = race.phase === 'finished' ? (race.finishPos <= 3 ? 'win' : 'scratch') : null;
      m.pose({
        t: race.t, wheel: h.rot, crank: h.crank, pedal: h.battery <= 0,
        pose: done || h.pose, talk: !!h.bubble, sway: Math.min(1, h.speed / 600), boost: h.boostT > 0,
      });
      const e = m.group;
      const v = this.v;
      const rot = this.groundRot(h.x / K) + yaw;
      // shadow, headlight, tail LEDs, hood LEDs at night, boost sparks
      this.shadows.add(m.group.position.x, 0.02, m.group.position.z, 1.5, 3.2, COL.white, 0.8, rot);
      if (m.lights.head) {
        this.world(e, m.lights.head, v);
        this.glows.add(v.x, v.y, v.z, this.night ? 0.9 : 0.35, this.night ? 0.9 : 0.35, COL.head, this.night ? 0.9 : 0.5);
        if (this.night) {
          this.beams.add(v.x - Math.sin(rot) * 5, 0.02, v.z - Math.cos(rot) * 5, 3.2, 10, COL.head, 0.28, rot);
          this.spot.position.copy(v);
          this.spot.target.position.set(v.x - Math.sin(rot) * 14, 0, v.z - Math.cos(rot) * 14);
          this.spot.target.updateMatrixWorld();
        }
      }
      for (const p of m.lights.tail) {
        this.world(e, p, v);
        this.glows.add(v.x, v.y, v.z, 0.35, 0.35, COL.tail, this.night ? 0.9 : 0.45);
      }
      if (m.lights.battery && Math.sin(race.t * 6) > 0) {
        this.world(e, m.lights.battery, v);
        this.dots.add(v.x, v.y, v.z, 0.05, 0.05, COL.green, 0.9);
      }
      if (m.lights.led && this.night) {
        const led = m.lights.led, cols = [COL.led1, COL.led2, COL.led3];
        for (let i = 0; i < led.length; i++) {
          this.world(e, led[i], v);
          const k = (i + Math.floor(race.t * 8)) % 3;
          this.dots.add(v.x, v.y, v.z, 0.12, 0.12, cols[k], 1);
          if (i % 3 === 0) this.glows.add(v.x, v.y, v.z, 0.35, 0.35, cols[k], 0.35);
        }
      }
      if (h.boostT > 0) this.boostSparks(e, race.t);
      if (h.puddle > 0 && Math.random() < 0.6) {
        const p = this.path.pos(h.x / K - 1.2, laneX(h.y), 0, this.v3);
        this.splash(p.x, p.z, 2);
      }
      // things that happened this frame
      for (const ev of race.events || []) this.event(race, ev);
    }

    boostSparks(e, t) {
      const v = this.v;
      const f = Math.floor(t * 24);
      for (let i = 0; i < 4; i++) {
        let px = -1.5, py = 0.35 + i * 0.12, pz = (i - 1.5) * 0.25;
        for (let j = 0; j < 5; j++) {
          px -= 0.12 + hash(f * 31 + i * 7 + j) * 0.12;
          py += (hash(f * 17 + i * 5 + j) - 0.5) * 0.18;
          this.world(e, [px, py, pz], v);
          this.sparks.add(v.x, v.y, v.z, 0.16, 0.16, i % 2 ? COL.blue : COL.gold, 0.9, j);
        }
      }
    }

    event(race, ev) {
      const p = this.path.pos(ev.x / K, laneX(ev.gy), 0, this.v3);
      const x = p.x, z = p.z;
      const ahead = this.path.pos(ev.x / K + 1.4, laneX(ev.gy), 0, this.v2);
      switch (ev.type) {
        case 'splash':
          this.splash(x, z, 18);
          break;
        case 'pothole':
          for (let i = 0; i < 6; i++) this.parts.push({ kind: 'puff', x: x + (Math.random() - 0.5), y: 0.2, z: z + Math.random(), vx: (Math.random() - 0.5) * 1.5, vy: 1 + Math.random(), vz: Math.random(), t: 0, life: 0.6, size: 0.5, color: COL.dust });
          break;
        case 'crash':
          for (let i = 0; i < 10; i++) this.parts.push({ kind: 'spark', x: ahead.x + (Math.random() - 0.5) * 0.8, y: 0.8 + Math.random() * 0.6, z: ahead.z, vx: (Math.random() - 0.5) * 4, vy: 1 + Math.random() * 3, vz: (Math.random() - 0.3) * 3, t: 0, life: 0.45, size: 0.25, color: COL.gold });
          break;
        case 'collect':
          for (let i = 0; i < 8; i++) {
            const a = (i / 8) * Math.PI * 2;
            this.parts.push({ kind: 'spark', x, y: 0.6, z, vx: Math.cos(a) * 2, vy: 1.5 + Math.random(), vz: Math.sin(a) * 2, t: 0, life: 0.5, size: 0.2, color: ev.kind === 'battery' ? COL.green : ev.kind === 'boost' ? COL.blue : COL.gold });
          }
          break;
      }
    }

    splash(x, z, n) {
      for (let i = 0; i < n; i++) {
        this.parts.push({ kind: 'drop', x: x + (Math.random() - 0.5) * 1.4, y: 0.1, z: z + (Math.random() - 0.5) * 1.2, vx: (Math.random() - 0.5) * 3, vy: 1.5 + Math.random() * 2.5, vz: (Math.random() - 0.2) * 2, t: 0, life: 0.5 + Math.random() * 0.3, size: 0.09, color: COL.splash });
      }
    }

    syncObjects(race, dt) {
      const seen = new Set();
      const t = race.t, v = this.v;
      const night = this.night;
      for (const o of race.objs) {
        if (o.gone) continue;
        if (o.kind === 'pothole' || o.kind === 'puddle') {
          const pud = o.kind === 'puddle', s = o.x / K, rot = this.groundRot(s);
          const p = this.path.pos(s, laneX(o.y), 0.014, this.v3);
          this.decals.add(p.x, 0.014, p.z, pud ? 2.3 : 1.15, pud ? 1.7 : 1.0, COL.white, 1, rot, X.decalCell(pud ? 7 : 6));
          if (pud) {
            // rain rings on the puddle
            for (let i = 0; i < 2; i++) {
              const k = (t * 0.7 + i * 0.5) % 1;
              const q = this.path.pos(s - (i - 0.5) * 0.4, laneX(o.y) + (i - 0.5) * 0.6, 0.02, this.v3);
              this.lightPools.add(q.x, 0.02, q.z, 0.4 + k * 0.9, 0.3 + k * 0.6, COL.white, 0.05 * (1 - k), rot);
            }
          }
          continue;
        }
        let e = this.live.get(o);
        if (!e) {
          e = this.modelFor(o);
          if (!e) continue;
          this.live.set(o, e);
        }
        seen.add(o);
        const m = e.m;
        switch (o.kind) {
          case 'car':
          case 'bus':
          case 'cng': {
            const yaw = this.yawFor(o, o.x, o.y, dt);
            const jolt = o.jolt ? Math.sin(o.jolt * 30) * o.jolt * 0.09 : 0;
            this.place(m.group, o.x + jolt * K, 0, o.y, yaw);
            m.pose({ wheel: o.rot, dent: o.dent, t });
            const len = o.kind === 'bus' ? 7.0 : o.kind === 'car' ? 4.4 : 2.9, wid = o.kind === 'bus' ? 2.6 : o.kind === 'car' ? 2.0 : 1.5;
            const rot = this.groundRot(o.x / K) + yaw;
            this.shadows.add(m.group.position.x, 0.02, m.group.position.z, wid, len, COL.white, 0.85, rot);
            this.vehicleLights(e, o, rot, t, night);
            break;
          }
          case 'rival': {
            const yaw = this.yawFor(o, o.x, o.y, dt);
            this.place(m.group, o.x, 0, o.y, yaw);
            m.group.rotation.x = -yaw * 0.25;
            m.group.updateMatrixWorld(true);
            m.pose({ t, wheel: o.rot, crank: o.rot * 0.55, pedal: true, sway: Math.min(1, o.vx / 600), talk: false });
            this.shadows.add(m.group.position.x, 0.02, m.group.position.z, 1.5, 3.2, COL.white, 0.8, this.groundRot(o.x / K) + yaw);
            if (night && m.lights.lantern) {
              this.world(m.group, m.lights.lantern, v);
              const fl = 0.75 + Math.sin(t * 13 + o.x) * 0.08 + Math.sin(t * 7.3) * 0.06;
              this.glows.add(v.x, v.y, v.z, 0.9, 0.9, COL.lantern, fl);
              this.lightPools.add(v.x, 0.02, v.z, 2.2, 2.2, COL.lantern, 0.22 * fl);
            }
            break;
          }
          case 'person':
            this.syncPerson(e, o, race, dt);
            break;
          case 'barricade': {
            this.place(m.group, o.x, 0, o.y, 0);
            this.shadows.add(m.group.position.x, 0.02, m.group.position.z, 2.6, 0.6, COL.white, 0.6, this.groundRot(o.x / K));
            if (Math.sin(t * 7) > 0) {
              this.world(m.group, m.lights.blink, v);
              this.glows.add(v.x, v.y, v.z, 1.2, 1.2, COL.red, 0.9);
            }
            break;
          }
          default: {
            // pickups hover and spin
            const seed = o.seed || 0;
            const hover = 0.55 + Math.sin(t * 3 + seed) * 0.07;
            this.place(m.group, o.x, hover, o.y, t * 2.6 + seed);
            this.shadows.add(m.group.position.x, 0.02, m.group.position.z, 0.5, 0.5, COL.white, 0.5);
            const c = o.kind === 'coin' ? COL.gold : o.kind === 'battery' ? COL.green : o.kind === 'boost' ? COL.blue : COL.warm;
            this.glows.add(m.group.position.x, hover, m.group.position.z, 1.1, 1.1, c, night ? 0.55 : 0.35);
            if (o.kind === 'boost') {
              for (let i = 0; i < 4; i++) {
                const a = t * 2 + (i * Math.PI) / 2;
                this.sparks.add(m.group.position.x + Math.cos(a) * 0.38, hover + Math.sin(a) * 0.38, m.group.position.z, 0.14, 0.14, COL.white, 0.9, a);
              }
            }
            if (o.kind === 'tea' && Math.random() < dt * 4) {
              this.parts.push({ kind: 'puff', x: m.group.position.x, y: hover + 0.15, z: m.group.position.z, vx: 0, vy: 0.4, vz: 0, t: 0, life: 1.2, size: 0.18, color: COL.steam });
            }
          }
        }
      }
      for (const [o, e] of this.live) {
        if (!seen.has(o)) {
          this.release(e);
          this.live.delete(o);
        }
      }
    }

    // rot: the turn of the vehicle's ground quads (the road's turn plus its own)
    vehicleLights(e, o, rot, t, night) {
      const m = e.m, L = m.lights, v = this.v;
      e = m.group;
      const blink = o.hazard > 0 && Math.sin(t * 12) > 0;
      for (const p of L.tail) {
        this.world(e, p, v);
        this.glows.add(v.x, v.y, v.z, night ? 0.7 : 0.3, night ? 0.7 : 0.3, blink ? COL.amber : COL.tail, night ? 0.85 : 0.35);
      }
      if (blink) {
        for (const p of L.corners || []) {
          this.world(e, p, v);
          this.glows.add(v.x, v.y, v.z, 0.9, 0.9, COL.amber, 0.9);
        }
      }
      if (night) {
        for (const p of L.head) {
          this.world(e, p, v);
          this.glows.add(v.x, v.y, v.z, 0.8, 0.8, COL.head, 0.85);
        }
        this.world(e, [L.head[0][0] + 5.5, 0.02, 0], v);
        this.beams.add(v.x, 0.02, v.z, o.kind === 'bus' ? 3.4 : 2.8, 11, COL.head, 0.22, rot);
      }
      if (o.kind === 'bus' && Math.random() < 0.25) {
        this.world(e, L.exhaust, v);
        this.parts.push({ kind: 'puff', x: v.x, y: v.y, z: v.z, vx: (Math.random() - 0.5) * 0.4, vy: 0.5, vz: 1.2, t: 0, life: 1.6, size: 0.5, color: COL.smoke });
      }
    }

    syncPerson(e, o, race, dt) {
      const m = e.m, t = race.t;
      const p = this.path.pos(o.x / K, laneX(o.y), 0, this.v3);
      const x = p.x, z = p.z;
      let face = o.vy > 0 ? 0 : o.vy < 0 ? Math.PI : o._face != null ? o._face : o.y < 603 ? 0 : Math.PI;
      if (o.stroll) face = o.stroll > 0 ? Math.PI / 2 : -Math.PI / 2;
      let y = 0, speed = Math.abs(o.vy) > 200 ? 2.2 : Math.abs(o.vy) > 1 || o.stroll ? 1 : 0;
      let angry = false;
      if (o.hit != null) {
        if (o.hit < 0.7) {
          const k = o.hit / 0.7;
          y = Math.sin(k * Math.PI) * 0.45;
          face = (o._face || 0) + k * Math.PI * 2 * (o.spinDir || 1);
          speed = 0;
        } else if (o.hit < 2.6) {
          face = -Math.PI / 2; // turns round to shake a fist at the rickshaw
          angry = true;
          speed = 0;
        } else {
          face = o.knock > 0 ? 0 : Math.PI;
          speed = 1;
        }
      } else {
        o._face = face;
      }
      m.group.position.set(x, y, z);
      m.group.rotation.set(0, face + this.groundRot(o.x / K), 0);
      m.group.updateMatrixWorld(true);
      m.pose({ t, walk: (o.phase || 0) + t * (speed > 1.5 ? 13 : 8), speed, angry });
      this.shadows.add(x, 0.02, z, 0.8, 0.8, COL.white, 0.7);
      if (o.hit != null && o.hit > 0.3 && o.hit < 2.6) {
        // dizzy stars round the head
        for (let i = 0; i < 3; i++) {
          const a = t * 6 + (i * Math.PI * 2) / 3;
          this.sparks.add(x + Math.cos(a) * 0.28, 1.72 + y + Math.sin(a * 2) * 0.04, z + Math.sin(a) * 0.28, 0.2, 0.2, COL.gold, 1, a);
        }
      }
      if (angry && Math.random() < dt * 5) {
        this.parts.push({ kind: 'puff', x: x + (Math.random() - 0.5) * 0.3, y: 1.65, z, vx: (Math.random() - 0.5) * 0.6, vy: 0.8, vz: 0, t: 0, life: 0.7, size: 0.2, color: COL.steam });
      }
    }

    // street lamps, stall bulbs and shop light at night; the hero's bell
    drawWorldLights(race, camS) {
      if (!this.night) return;
      const L = this.city.lights();
      const wet = !!race.route.rain;
      const near = (s) => s > camS - 8 && s < camS + 130;
      // lights come as world points with their road distance and side: [x, y, z, kind, s, lateral]
      for (const [x, y, z, kind, s, lat] of L.lamps) {
        if (!near(s)) continue;
        const c = COL[kind] || COL.sodium;
        this.glows.add(x, y, z, kind === 'flood' ? 1.4 : 1.8, kind === 'flood' ? 1.4 : 1.8, c, 0.85);
        this.dots.add(x, y - 0.03, z, 0.5, 0.25, c, 0.9);
        const gy = lat < -C3.ROAD || lat > this.L.kerbR ? C3.KERB_H + 0.01 : 0.015;
        if (kind !== 'flood' && y < 12) {
          this.lightPools.add(x, gy, z, 7.5, 7.5, c, 0.2);
          if (wet) {
            // the lamp's streak on the wet road, toward the camera
            const p = this.path.pos(s - 4, lat, 0.02, this.v3);
            this.lightPools.add(p.x, 0.02, p.z, 1.0, 9, c, 0.18, this.groundRot(s - 4));
          }
        }
      }
      for (const [x, y, z, kind, s] of L.bulbs) {
        if (!near(s)) continue;
        const c = COL[kind] || COL.tea;
        const fl = kind === 'lantern' ? 0.8 + Math.sin(race.t * 11 + s) * 0.1 : 0.9;
        this.glows.add(x, y, z, 1.1, 1.1, c, fl);
        this.lightPools.add(x, C3.KERB_H + 0.01, z, 4, 4, c, 0.2 * fl);
      }
      for (const [x, , z, w, s] of L.spills) {
        if (!near(s)) continue;
        this.lightPools.add(x, C3.KERB_H + 0.01, z, 3.2, Math.max(2.5, w * 1.2), COL.tea, 0.16, this.groundRot(s));
      }
    }

    updateParts(dt) {
      const keep = [];
      for (const p of this.parts) {
        p.t += dt;
        if (p.t >= p.life) continue;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        p.z += p.vz * dt;
        const k = p.t / p.life;
        if (p.kind === 'drop' || p.kind === 'spark') p.vy -= 9 * dt;
        if (p.kind === 'puff') {
          const sz = p.size * (1 + k * 2.2);
          this.puffs.add(p.x, p.y, p.z, sz, sz, p.color, 0.55 * (1 - k), p.t);
        } else if (p.kind === 'drop') {
          if (p.y < 0) continue;
          this.dots.add(p.x, p.y, p.z, p.size, p.size, p.color, 0.8 * (1 - k));
        } else {
          this.sparks.add(p.x, p.y, p.z, p.size, p.size, p.color, 1 - k, p.t * 6);
        }
        keep.push(p);
      }
      this.parts = keep;
    }

    updateRain(dt) {
      if (!this.rain.visible) return;
      const c = this.camera.position, P = this.rainPos, t = this.t;
      // a box of rain in front of the camera, whichever way the road has turned it
      const f = this.camera.getWorldDirection(this.v3);
      const fl = Math.hypot(f.x, f.z) || 1, fx = f.x / fl, fz = f.z / fl;
      const at = (side, ahead) => [c.x + fx * ahead - fz * side, c.z + fz * ahead + fx * side];
      for (let i = 0; i < this.rainN; i++) {
        const [a, b, d, sp] = this.rainSeed[i];
        const fall = 13 + sp * 6;
        const y = 16 - ((t * fall + b * 16) % 16);
        const [x, z] = at(-14 + a * 28 + (16 - y) * 0.12, 34 - d * 38);
        const o = i * 6;
        P[o] = x;
        P[o + 1] = y;
        P[o + 2] = z;
        P[o + 3] = x + fz * 0.06;
        P[o + 4] = y + 0.5;
        P[o + 5] = z - fx * 0.06;
      }
      this.rainAttr.needsUpdate = true;
      // splashes on the road
      for (let i = 0; i < 14; i++) {
        const ph = t * 2.2 + hash(i * 17);
        const k = ph % 1, gen = Math.floor(ph);
        const [x, z] = at(-9 + hash(i * 19 + gen * 7) * 18, 3 + hash(i * 23 + gen * 13) * 22);
        this.lightPools.add(x, 0.02, z, 0.1 + k * 0.35, 0.1 + k * 0.35, COL.white, 0.25 * (1 - k));
      }
    }

    updateSky(t) {
      const c = this.camera.position;
      this.sky.position.copy(c);
      this.stars.position.copy(c);
      this.far.position.set(c.x, c.y + 15, c.z);
      // sun or moon ahead and to the right, low over the city
      const sx = c.x + 160, sy = this.night ? 120 : 140, sz = c.z - 380;
      if (this.night) {
        this.glows.add(sx, sy, sz, 90, 90, C('#fff6d8'), 0.35);
        this.dots.add(sx, sy, sz, 22, 22, C('#fff3cf'), 1);
      } else {
        this.glows.add(sx, sy, sz, 150, 150, C('#fff7de'), 0.55);
        this.dots.add(sx, sy, sz, 26, 26, C('#fffbe8'), 1);
        // a few clouds
        for (let i = 0; i < 7; i++) {
          const cx = c.x - 300 + ((hash(i * 3) * 600 + t * 2) % 600), cz = c.z - 250 - hash(i * 7) * 150;
          for (let j = 0; j < 4; j++) this.puffs.add(cx + j * 14 - 20, 110 + hash(i * 11) * 50 + Math.sin(j) * 5, cz, 34, 22, COL.white, 0.5);
        }
      }
      // kites over the rooftops ahead
      this.kites.forEach((k, i) => {
        const s = this.camS + 85 + i * 22;
        this.path.pos(s, -16 + i * 15 + Math.sin(t * 0.5 + i) * 2.5, 19 + i * 3 + Math.cos(t * 0.7 + i * 2) * 1.2, k.position);
        k.rotation.set(0, this.groundRot(s), Math.sin(t * 0.9 + i) * 0.25);
        k.scale.setScalar(1.6);
      });
    }

    // decorative traffic coming the other way, beyond the median
    updateOncoming(race, dt, camS) {
      const L = this.L;
      if (L.median1 == null) return;
      const lanes = [L.median1 + 1.65, L.median1 + 4.95];
      while (this.oncoming.length < 6) {
        const r = Math.random();
        const kind = r < 0.45 ? 'car' : r < 0.6 ? 'bus' : r < 0.8 ? 'cng' : 'rickshaw';
        let e;
        if (kind === 'car') {
          const col = A.CAR_COLORS[Math.floor(Math.random() * A.CAR_COLORS.length)];
          e = this.take('car' + col + 1, () => M3.makeCar(col, 1));
        } else if (kind === 'bus') {
          const col = ['#d62839', '#1d4e89', '#2a9d4b', '#e09f00'][Math.floor(Math.random() * 4)];
          e = this.take('bus' + col, () => M3.makeBus(col));
        } else if (kind === 'cng') {
          e = this.take('cng', () => M3.makeCNG());
        } else {
          const sk = [A.SKINS.peacock, A.SKINS.redfairy, A.SKINS.golden][Math.floor(Math.random() * 3)];
          e = this.take('rival' + sk.name, () => M3.makeRickshaw(sk));
        }
        e.kind = kind;
        e.lane = lanes[kind === 'rickshaw' || kind === 'bus' ? 1 : Math.floor(Math.random() * 2)];
        e.s = camS + 60 + Math.random() * 120;
        e.v = kind === 'rickshaw' ? 3.5 : kind === 'bus' ? 6 : 8 + Math.random() * 3;
        e.rot = 0;
        this.oncoming.push(e);
      }
      const keep = [];
      for (const e of this.oncoming) {
        e.s -= e.v * dt;
        e.rot += (e.v * dt) / (e.kind === 'rickshaw' ? 0.345 : 0.3);
        if (e.s < camS - 15) {
          this.release(e);
          continue;
        }
        const g = e.m.group;
        this.path.pos(e.s, e.lane, 0, g.position);
        g.rotation.set(0, this.path.heading(e.s) + Math.PI, 0);
        g.updateMatrixWorld(true);
        if (e.kind === 'rickshaw') e.m.pose({ t: race.t, wheel: e.rot, crank: e.rot * 0.55, pedal: true, sway: 0.4 });
        else e.m.pose({ wheel: e.rot, t: race.t });
        if (this.night && e.m.lights && e.m.lights.head) {
          for (const p of e.m.lights.head) {
            this.world(g, p, this.v);
            this.glows.add(this.v.x, this.v.y, this.v.z, 0.9, 0.9, COL.head, 0.8);
          }
        }
        keep.push(e);
      }
      this.oncoming = keep;
    }

    // the metro rolls by overhead now and then, where the line runs along the road for a while
    updateTrain(dt, camS) {
      if (!this.trainCars) {
        const b = new window.BT.k3.Builder({ uv: true });
        b.box(0, 1.9, 0, 2.9, 3.6, 19.8, '#f2f4f5');
        b.quad([1.47, 1.9, 0], [0, 0, -9.9], [0, 1.6, 0], [0, 0, 2, 1]);
        b.quad([-1.47, 1.9, 0], [0, 0, 9.9], [0, 1.6, 0], [0, 0, 2, 1]);
        const geo = b.build(), mat = MAT.toon({ map: X.train(), vertexColors: true });
        this.trainCars = [];
        for (let i = 0; i < 6; i++) {
          const m = new T.Mesh(geo, mat);
          m.visible = false;
          this.scene.add(m);
          this.trainCars.push(m);
        }
      }
      const cars = this.trainCars;
      if (!this.train) {
        for (const m of cars) m.visible = false;
        const span = this.city.metro.find(([a, b]) => camS > a && camS < b && b - a > 150);
        if (!span) return;
        this.trainT -= dt;
        if (this.trainT <= 0) {
          const dir = Math.random() < 0.5 ? 1 : -1;
          this.train = { dir, s: dir > 0 ? camS - 130 : camS + 230, lat: this.L.median0 + 0.6 + 0.6 + (dir > 0 ? -1.6 : 1.6), span };
        }
        return;
      }
      const tr = this.train;
      tr.s += tr.dir * 19 * dt;
      cars.forEach((m, i) => {
        const s = tr.s + tr.dir * (10 + i * 20.5);
        m.visible = s > tr.span[0] + 10 && s < tr.span[1] - 10;
        if (!m.visible) return;
        this.path.pos(s, tr.lat, 14.2, m.position);
        m.rotation.y = this.groundRot(s) + (tr.dir > 0 ? 0 : Math.PI);
      });
      if ((tr.dir > 0 && tr.s > camS + 330) || (tr.dir < 0 && tr.s < camS - 160)) {
        this.train = null;
        this.trainT = 14 + Math.random() * 14;
      }
    }

    // ---------------------------------------------------------------- camera

    updateCamera(race, dt) {
      const h = race.hero;
      const hs = h.x / K, hx = laneX(h.y);
      const k = this.snapCam ? 1 : Math.min(1, dt * 4);
      this.camX += (hx * 0.75 - this.camX) * Math.min(1, dt * 3);
      this.boostK += ((h.boostT > 0 ? 1 : 0) - this.boostK) * Math.min(1, dt * 3);
      const speed = h.speed / K;
      let pos, look, fov = 58 + this.boostK * 12;
      if (race.demo) {
        // behind the menus: a raised camera (clear of every vehicle's roof) swinging slowly
        // from one rear quarter to the other
        const a = Math.PI + Math.sin(race.t * 0.09) * 0.7;
        const R = 7.2;
        pos = [clamp(hx * 0.5 + Math.sin(a) * R, -3.3, 3.3), 3.4, hs + Math.cos(a) * R];
        look = [hx * 0.6, 2.4, hs + 6];
        fov = 55;
      } else if (race.phase === 'countdown') {
        // from the rider's face round to behind as the count runs down, rising over the
        // rickshaws alongside on the way
        const p = smooth(clamp(1 - (race.countT - 0.6) / 3.0, 0, 1));
        const a = lerp(0.55, Math.PI, p), R = lerp(3.0, 5.6, p);
        // (kept over the roadway, clear of the posts on a narrow street's footpath)
        const edge = (this.L.median0 != null ? this.L.median0 : this.L.kerbR) - 0.2;
        pos = [clamp(hx + Math.sin(a) * R, -C3.ROAD + 0.3, edge), lerp(1.6, 3.3, p) + Math.sin(p * Math.PI) * 1.2, hs + Math.cos(a) * R];
        look = [lerp(hx + 0.4, hx * 0.55, p), lerp(1.75, 0.9, p), hs + lerp(0.3, 9, p)];
      } else if (race.phase === 'finished') {
        // over the top to the front, to see the rider celebrate (kept inside the road)
        const p = smooth(clamp((race.t - (race.finishAt || race.t)) * 0.4, 0, 1));
        const a = lerp(Math.PI, 0.45, p), R = lerp(5.6, 4.6, p);
        pos = [clamp(hx + Math.sin(a) * R, -3.6, 3.6), lerp(3.3, 1.9, p) + Math.sin(p * Math.PI) * 1.6, hs + Math.cos(a) * R];
        look = [hx, lerp(0.9, 1.5, p), hs + lerp(9, 0.2, p)];
      } else {
        const back = 5.4 + Math.min(1.0, speed * 0.07) + this.boostK * 0.8;
        // rise over anything that comes between the camera and the rickshaw (a rival or a car
        // following close behind, a bus in the kerb lane)
        let lift = 0;
        for (const o of race.objs) {
          if (o.kind !== 'bus' && o.kind !== 'rival' && o.kind !== 'car' && o.kind !== 'cng') continue;
          const behind = h.x - o.x;
          if (Math.abs(laneX(o.y) - this.camX) < 1.9 && behind > 60 && behind < (o.kind === 'bus' ? 1300 : 1000)) lift = Math.max(lift, o.kind === 'bus' ? 1.4 : 1);
        }
        this.lift = (this.lift || 0) + (lift - (this.lift || 0)) * Math.min(1, dt * 3);
        // high enough to see over the rickshaw's hood to whatever is just ahead in the lane
        pos = [this.camX, 3.3 + this.lift * 1.1 + (race.phase === 'over' ? Math.min(2, race.overT) : 0), hs - back + this.lift * 0.8];
        look = [hx * 0.55, 0.9, hs + 9];
      }
      // eased in road coordinates (lateral, height, s), so the camera follows the road round bends
      this.camR.lerp(this.v.set(pos[0], pos[1], pos[2]), k);
      this.lookR.lerp(this.v2.set(look[0], look[1], look[2]), k);
      this.snapCam = false;
      this.camS = this.camR.z;
      const cam = this.camera;
      this.path.pos(this.camR.z, this.camR.x, this.camR.y, cam.position);
      this.path.pos(this.lookR.z, this.lookR.x, this.lookR.y, this.camLook);
      if (race.shake > 0) {
        cam.position.x += (Math.random() - 0.5) * 0.3 * race.shake;
        cam.position.y += (Math.random() - 0.5) * 0.2 * race.shake;
      }
      cam.lookAt(this.camLook);
      if (Math.abs(cam.fov - fov) > 0.01) {
        cam.fov += (fov - cam.fov) * Math.min(1, dt * 5);
        cam.updateProjectionMatrix();
      }
      cam.updateMatrixWorld();
    }

    // race point (x, ground y, height in px) → overlay point in logical px; null if behind
    project(x, gy, hpx) {
      const v = this.path.pos(x / K, laneX(gy), (hpx || 0) / K, this.v).project(this.camera);
      if (v.z > 1) return null;
      return { x: ((v.x + 1) / 2) * this.W, y: ((1 - v.y) / 2) * 720 };
    }

    // a point in the hero model's frame → overlay point (speech bubble over the rider's head)
    projectHero(p) {
      if (!this.hero) return null;
      const v = this.v.copy(p).applyMatrix4(this.hero.group.matrixWorld).project(this.camera);
      if (v.z > 1) return null;
      return { x: ((v.x + 1) / 2) * this.W, y: ((1 - v.y) / 2) * 720 };
    }

    heroHead() {
      return this.hero ? this.projectHero(this.v2.copy(this.hero.headTop()).add(new T.Vector3(0, 0.25, 0))) : null;
    }

    bell() {
      return this.hero ? this.projectHero(this.v2.set(0.86, 1.46, 0.12)) : null;
    }

    // ---------------------------------------------------------------- quality

    // Lowers the resolution while frames are slow, and raises it again when there is room. If
    // the lowest resolution is still slow, the ink outlines go too.
    adapt(dt) {
      if (!dt) return;
      this.frameMs += (dt * 1000 - this.frameMs) * 0.05;
      if (this.frameMs > 24) this.slow += dt;
      else this.slow = 0;
      if (this.frameMs < 15) this.fast += dt;
      else this.fast = 0;
      if (this.slow > 3 && this.dpr <= 0.7 && this.outlines !== false) {
        this.setOutlines(false);
        this.slow = 0;
      } else if (this.slow > 1.5 && this.dpr > 0.7) {
        this.dpr = Math.max(0.7, this.dpr - 0.15);
        this.slow = 0;
        this.renderer.setPixelRatio(this.dpr);
        this.renderer.setSize(this.cssW, this.cssH, false);
      } else if (this.fast > 5 && this.dpr < this.maxDpr) {
        this.dpr = Math.min(this.maxDpr, this.dpr + 0.1);
        this.fast = 0;
        this.renderer.setPixelRatio(this.dpr);
        this.renderer.setSize(this.cssW, this.cssH, false);
      }
    }

    // ---------------------------------------------------------------- garage

    /* Paints a 3/4 view of a rickshaw in the given skin onto a 2D canvas (garage cards). */
    snapshot(skin, cv) {
      const w = cv.width, h = cv.height;
      if (!this.studio) {
        const sc = new T.Scene();
        sc.background = new T.Color('#fff3dc');
        sc.add(new T.HemisphereLight('#ffffff', '#c9a77f', 0.65));
        const d = new T.DirectionalLight('#fff3dc', 0.55);
        d.position.set(3, 6, 4);
        sc.add(d);
        const floor = new T.Mesh(new T.CircleGeometry(30, 32), new T.MeshLambertMaterial({ color: '#ead2ab' }));
        floor.rotation.x = -Math.PI / 2;
        sc.add(floor);
        const shadow = new T.Mesh(new T.PlaneGeometry(1.6, 3.4), new T.MeshBasicMaterial({ map: X.blob(), transparent: true, depthWrite: false }));
        shadow.rotation.set(-Math.PI / 2, 0, Math.PI / 2);
        shadow.position.y = 0.01;
        sc.add(shadow);
        // a rear three-quarter view: the painted back plate and the hood are what a skin changes
        const cam = new T.PerspectiveCamera(30, w / h, 0.1, 80);
        cam.position.set(-4.3, 2.2, 3.4);
        cam.lookAt(0.45, 0.95, 0.35);
        this.studio = { sc, cam, models: new Map() };
      }
      const st = this.studio;
      let m = st.models.get(skin.name + skin.frame);
      if (!m) {
        m = M3.makeRickshaw(skin);
        m.pose({ sway: 0.4, wheel: 0.6 });
        st.models.set(skin.name + skin.frame, m);
      }
      for (const o of st.models.values()) st.sc.remove(o.group);
      st.sc.add(m.group);
      st.cam.aspect = w / h;
      st.cam.updateProjectionMatrix();
      const rt = new T.WebGLRenderTarget(w, h, { samples: 0 });
      this.renderer.setRenderTarget(rt);
      this.renderer.render(st.sc, st.cam);
      const px = new Uint8Array(w * h * 4);
      this.renderer.readRenderTargetPixels(rt, 0, 0, w, h, px);
      this.renderer.setRenderTarget(null);
      rt.dispose();
      const ctx = cv.getContext('2d');
      const img = ctx.createImageData(w, h);
      for (let y = 0; y < h; y++) img.data.set(px.subarray((h - 1 - y) * w * 4, (h - y) * w * 4), y * w * 4);
      ctx.putImageData(img, 0, 0);
    }

    setOutlines(on) {
      this.outlines = on;
      for (const wdt of [0.012, 0.013, 0.014, 0.016, 0.02]) outlineMaterial(wdt).visible = on;
    }
  }

  // Can this browser draw the 3D game?
  View3D.supported = () => {
    try {
      const c = document.createElement('canvas');
      return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
    } catch (e) {
      return false;
    }
  };

  window.BT.View3D = View3D;
  window.BT.laneX = laneX;
})();
