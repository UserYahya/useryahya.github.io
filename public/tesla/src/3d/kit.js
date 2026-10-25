/* বাংলা টেসলা 3D — building blocks shared by the 3D models and the 3D street.
 *
 *   Builder   merges coloured primitives into one mesh, so a whole rickshaw body or a whole
 *             street chunk costs a single draw call
 *   MAT       shared toon materials (flat cartoon shading, like the 2D art)
 *   outline   the comic ink outline every 2D sprite has, as an inverted hull
 *   Batch     camera-facing glows and puffs, and flat ground quads (shadows, light pools),
 *             rebuilt every frame and drawn in one call each
 *   canvasTex textures painted with Canvas 2D; Bengali text is repainted once the fonts load
 *
 * Units are metres. Models are built facing +x with +y up and +z on their right; the view
 * turns them so +x points down the road. */
(function () {
  'use strict';

  const T = window.THREE;
  const BT = window.BT;

  const K = 90; // race px per metre
  const LW = 2.8; // lane width, metres

  // ------------------------------------------------------------------ colours and transforms

  const colorCache = new Map();
  function col(c) {
    if (c && c.isColor) return c;
    let v = colorCache.get(c);
    if (!v) colorCache.set(c, (v = new T.Color(c)));
    return v;
  }

  // Mix two colours (amt 0 → a, 1 → b), returned as a new THREE.Color.
  function mix(a, b, amt) {
    return col(a).clone().lerp(col(b), amt);
  }

  const _e = new T.Euler(), _q = new T.Quaternion(), _p = new T.Vector3(), _s = new T.Vector3();
  function tf(x = 0, y = 0, z = 0, rx = 0, ry = 0, rz = 0, sx = 1, sy = 1, sz = 1) {
    return new T.Matrix4().compose(_p.set(x, y, z), _q.setFromEuler(_e.set(rx, ry, rz)), _s.set(sx, sy, sz));
  }

  // ------------------------------------------------------------------ primitives

  const geoCache = new Map();
  function prim(key, make) {
    let g = geoCache.get(key);
    if (!g) {
      g = make();
      if (g.index) {
        const n = g.toNonIndexed();
        g.dispose();
        g = n;
      }
      geoCache.set(key, g);
    }
    return g;
  }
  const BOX = () => prim('box', () => new T.BoxGeometry(1, 1, 1));
  // unit cylinder along y, radius 1 at the bottom and `top` at the top
  const CYL = (seg, top = 1, open = false) => prim('cyl' + seg + ':' + top + open, () => new T.CylinderGeometry(top, 1, 1, seg, 1, open));
  const BALL = (seg) => prim('ball' + seg, () => new T.SphereGeometry(1, seg, Math.max(4, Math.round(seg * 0.6))));
  // half sphere (dome) on y = 0
  const DOME = (seg) => prim('dome' + seg, () => new T.SphereGeometry(1, seg, Math.max(3, Math.round(seg * 0.3)), 0, Math.PI * 2, 0, Math.PI / 2));
  // torus in the x-y plane (a wheel seen from the side), radius 1
  const RING = (tube, seg, arc = Math.PI * 2) => prim('ring' + tube + ':' + seg + ':' + arc.toFixed(3), () => new T.TorusGeometry(1, tube, 5, seg, arc));
  const UP = new T.Vector3(0, 1, 0);

  // ------------------------------------------------------------------ builder

  /* Collects parts into one non-indexed geometry. Options: uv (keep texture coordinates, for an
   * atlas: plain coloured parts point at its white spot), skin (record which bone each part
   * follows, for a SkinnedMesh). Before adding parts set: bone (bone index), ow (ink outline
   * width multiplier, 0 for none) and uvr (uv rect the part's own 0..1 uvs are squeezed into). */
  class Builder {
    constructor(opts = {}) {
      if (opts === true) opts = { uv: true };
      this.p = [];
      this.n = [];
      this.c = [];
      this.o = [];
      this.u = opts.uv ? [] : null;
      this.s = opts.skin ? [] : null;
      this.bone = 0;
      this.ow = 1;
      this.uvr = null;
      this.white = opts.white || [0.5, 0.5];
    }

    get count() {
      return this.p.length / 3;
    }

    _vert(x, y, z, nx, ny, nz, q, u, v) {
      this.p.push(x, y, z);
      this.n.push(nx, ny, nz);
      this.c.push(q.r, q.g, q.b);
      this.o.push(this.ow);
      if (this.u) this.u.push(u, v);
      if (this.s) this.s.push(this.bone);
    }

    // Adds geometry transformed by matrix m. c is a colour, or fn(position, normal) → colour.
    add(geo, m, c, flat) {
      const P = geo.attributes.position, N = geo.attributes.normal, U = geo.attributes.uv;
      const idx = geo.index;
      const nm = new T.Matrix3().getNormalMatrix(m);
      const flip = m.determinant() < 0;
      const fn = typeof c === 'function' ? c : null;
      const cc = fn ? null : col(c);
      const r = this.uvr;
      const v = new T.Vector3(), n = new T.Vector3();
      const start = this.p.length;
      const count = idx ? idx.count : P.count;
      for (let k = 0; k < count; k++) {
        // flip the winding of mirrored parts so they still face out
        let j = flip ? k - (k % 3) + [0, 2, 1][k % 3] : k;
        if (idx) j = idx.getX(j);
        v.fromBufferAttribute(P, j).applyMatrix4(m);
        n.fromBufferAttribute(N, j).applyMatrix3(nm).normalize();
        let u = this.white[0], w = this.white[1];
        if (r && U) {
          u = r[0] + U.getX(j) * (r[2] - r[0]);
          w = r[1] + U.getY(j) * (r[3] - r[1]);
        }
        this._vert(v.x, v.y, v.z, n.x, n.y, n.z, fn ? col(fn(v, n)) : cc, u, w);
      }
      if (flat) faceNormals(this.p, this.n, start);
      return this;
    }

    box(x, y, z, w, h, d, c, rx = 0, ry = 0, rz = 0) {
      return this.add(BOX(), tf(x, y, z, rx, ry, rz, w, h, d), c);
    }

    // Cylinder standing on its axis: centre (x, y, z), radius r, height h; top = top radius / r.
    cyl(x, y, z, r, h, c, seg = 10, rx = 0, ry = 0, rz = 0, top = 1, flat = false) {
      return this.add(CYL(seg, top), tf(x, y, z, rx, ry, rz, r, h, r), c, flat);
    }

    // Elliptic cylinder: radii rx (along x) and rz (along z).
    ecyl(x, y, z, rx, rz, h, c, seg = 10, ax = 0, ay = 0, az = 0, top = 1) {
      return this.add(CYL(seg, top), tf(x, y, z, ax, ay, az, rx, h, rz), c);
    }

    ball(x, y, z, rx, ry, rz, c, seg = 10, flat = false, ax = 0, ay = 0, az = 0) {
      return this.add(BALL(seg), tf(x, y, z, ax, ay, az, rx, ry, rz), c, flat);
    }

    dome(x, y, z, rx, ry, rz, c, seg = 10, ax = 0, ay = 0, az = 0) {
      return this.add(DOME(seg), tf(x, y, z, ax, ay, az, rx, ry, rz), c);
    }

    // Torus of radius r and tube t in the x-y plane, turned by (rx, ry, rz).
    ring(x, y, z, r, t, c, seg = 20, rx = 0, ry = 0, rz = 0, arc) {
      return this.add(RING(+(t / r).toFixed(3), seg, arc), tf(x, y, z, rx, ry, rz, r, r, r), c);
    }

    // A round bar from point a to point b.
    rod(a, b, r, c, seg = 6) {
      const d = new T.Vector3(b[0] - a[0], b[1] - a[1], b[2] - a[2]);
      const len = d.length();
      if (len < 1e-5) return this;
      const q = new T.Quaternion().setFromUnitVectors(UP, d.multiplyScalar(1 / len));
      const m = new T.Matrix4().compose(new T.Vector3((a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2), q, new T.Vector3(r, len, r));
      return this.add(CYL(seg), m, c);
    }

    // A bar along a polyline, with balls at the bends.
    path(pts, r, c, seg = 6, joints = true) {
      for (let i = 0; i + 1 < pts.length; i++) {
        this.rod(pts[i], pts[i + 1], r, c, seg);
        if (joints && i > 0) this.ball(pts[i][0], pts[i][1], pts[i][2], r, r, r, c, seg);
      }
      return this;
    }

    // Flat rectangle: centre o, half-extents u (texture right) and v (texture up), uv rect
    // [u0, v0, u1, v1] (default: the white spot). It faces along u × v.
    quad(o, u, v, uv, c) {
      const cc = col(c == null ? '#ffffff' : c);
      const nx = u[1] * v[2] - u[2] * v[1], ny = u[2] * v[0] - u[0] * v[2], nz = u[0] * v[1] - u[1] * v[0];
      const nl = Math.hypot(nx, ny, nz) || 1;
      const P = (su, sv) => [o[0] + u[0] * su + v[0] * sv, o[1] + u[1] * su + v[1] * sv, o[2] + u[2] * su + v[2] * sv];
      const w = this.white;
      const r = uv || [w[0], w[1], w[0], w[1]];
      const corners = [[P(-1, -1), r[0], r[1]], [P(1, -1), r[2], r[1]], [P(1, 1), r[2], r[3]], [P(-1, 1), r[0], r[3]]];
      for (const k of [0, 1, 2, 0, 2, 3]) {
        const [p, uu, vv] = corners[k];
        this._vert(p[0], p[1], p[2], nx / nl, ny / nl, nz / nl, cc, uu, vv);
      }
      return this;
    }

    // Raw triangle list: pts [[x,y,z]...], uvs [[u,v]...] (optional), one colour; flat normals.
    tris(pts, c, uvs) {
      const cc = col(c);
      const start = this.p.length;
      const w = this.white;
      pts.forEach((p, i) => this._vert(p[0], p[1], p[2], 0, 1, 0, cc, uvs ? uvs[i][0] : w[0], uvs ? uvs[i][1] : w[1]));
      faceNormals(this.p, this.n, start);
      return this;
    }

    build() {
      const g = new T.BufferGeometry();
      g.setAttribute('position', new T.Float32BufferAttribute(this.p, 3));
      g.setAttribute('normal', new T.Float32BufferAttribute(this.n, 3));
      g.setAttribute('color', new T.Float32BufferAttribute(this.c, 3));
      g.setAttribute('owidth', new T.Float32BufferAttribute(this.o, 1));
      if (this.u) g.setAttribute('uv', new T.Float32BufferAttribute(this.u, 2));
      if (this.s) {
        const n = this.s.length;
        const si = new Uint16Array(n * 4), sw = new Float32Array(n * 4);
        for (let i = 0; i < n; i++) {
          si[i * 4] = this.s[i];
          sw[i * 4] = 1;
        }
        g.setAttribute('skinIndex', new T.Uint16BufferAttribute(si, 4));
        g.setAttribute('skinWeight', new T.Float32BufferAttribute(sw, 4));
      }
      g.computeBoundingSphere();
      return g;
    }

    mesh(mat) {
      return new T.Mesh(this.build(), mat || MAT.vc);
    }

    /* A SkinnedMesh over bones (index = bone number; every bone without a parent is a root).
     * The bones must be in the bind pose (no rotation), the pose the parts were built in. */
    skinned(bones, mat) {
      const mesh = new T.SkinnedMesh(this.build(), mat || MAT.vc);
      for (const b of bones) if (!b.parent) mesh.add(b);
      mesh.updateMatrixWorld(true);
      mesh.bind(new T.Skeleton(bones));
      mesh.userData.bones = bones;
      // the parts move, so the bind-pose bounds may be too small to cull by
      mesh.geometry.boundingSphere.radius *= 1.3;
      return mesh;
    }
  }

  function faceNormals(p, n, start) {
    for (let i = start; i + 8 < p.length; i += 9) {
      const ax = p[i + 3] - p[i], ay = p[i + 4] - p[i + 1], az = p[i + 5] - p[i + 2];
      const bx = p[i + 6] - p[i], by = p[i + 7] - p[i + 1], bz = p[i + 8] - p[i + 2];
      let x = ay * bz - az * by, y = az * bx - ax * bz, z = ax * by - ay * bx;
      const l = Math.hypot(x, y, z) || 1;
      x /= l;
      y /= l;
      z /= l;
      for (let k = 0; k < 9; k += 3) {
        n[i + k] = x;
        n[i + k + 1] = y;
        n[i + k + 2] = z;
      }
    }
  }

  // Extruded 2D outline (points [[x, y]...] in the x-y plane), depth along z, centred on z = 0.
  function extrude(points, depth, bevel = 0, curveSeg = 6) {
    const shape = new T.Shape(points.map((p) => new T.Vector2(p[0], p[1])));
    const g = new T.ExtrudeGeometry(shape, {
      depth: depth - bevel * 2, bevelEnabled: bevel > 0, bevelThickness: bevel, bevelSize: bevel,
      bevelSegments: 2, curveSegments: curveSeg,
    });
    g.translate(0, 0, -(depth - bevel * 2) / 2);
    const n = g.index ? g.toNonIndexed() : g;
    if (n !== g) g.dispose();
    n.computeVertexNormals();
    return n;
  }

  // Polyline helpers for building outlines from curves: quadratic Bézier from a via c to b.
  function qbez(a, c, b, n = 8) {
    const out = [];
    for (let i = 1; i <= n; i++) {
      const t = i / n, u = 1 - t;
      out.push([u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1]]);
    }
    return out;
  }

  // ------------------------------------------------------------------ materials

  // Three-step toon ramp: lit, half-lit and shade, like the flat colours of the 2D art.
  const ramp = new T.DataTexture(new Uint8Array([120, 120, 120, 255, 190, 190, 190, 255, 255, 255, 255, 255]), 3, 1, T.RGBAFormat);
  ramp.minFilter = ramp.magFilter = T.NearestFilter;
  ramp.generateMipmaps = false;
  ramp.needsUpdate = true;

  const toon = (o) => new T.MeshToonMaterial(Object.assign({ gradientMap: ramp }, o));
  const MAT = {
    vc: toon({ vertexColors: true }),
    vcDouble: toon({ vertexColors: true, side: T.DoubleSide }),
    unlit: new T.MeshBasicMaterial({ vertexColors: true }),
    toon,
    ramp,
  };

  // ------------------------------------------------------------------ ink outline

  const INK = '#1d1428';
  const outlineMats = new Map();
  function outlineMaterial(width) {
    let m = outlineMats.get(width);
    if (m) return m;
    m = new T.ShaderMaterial({
      uniforms: T.UniformsUtils.merge([T.UniformsLib.fog, { width: { value: width }, ink: { value: new T.Color(INK) } }]),
      vertexShader: [
        'attribute vec3 onormal;',
        'attribute float owidth;',
        'uniform float width;',
        '#include <common>',
        '#include <skinning_pars_vertex>',
        '#include <fog_pars_vertex>',
        'void main() {',
        '  vec3 objectNormal = onormal;',
        '  #include <skinbase_vertex>',
        '  #include <skinnormal_vertex>',
        '  vec3 transformed = vec3(position);',
        '  #include <skinning_vertex>',
        '  vec3 n = normalize(normalMatrix * objectNormal);',
        '  vec4 mvPosition = modelViewMatrix * vec4(transformed, 1.0);',
        '  mvPosition.xyz += n * width * owidth * clamp(0.7 + 0.05 * -mvPosition.z, 0.7, 3.5);',
        '  gl_Position = projectionMatrix * mvPosition;',
        '  #include <fog_vertex>',
        '}',
      ].join('\n'),
      fragmentShader: [
        'uniform vec3 ink;',
        '#include <common>',
        '#include <fog_pars_fragment>',
        'void main() {',
        '  gl_FragColor = vec4(ink, 1.0);',
        '  #include <fog_fragment>',
        '}',
      ].join('\n'),
      side: T.BackSide,
      fog: true,
    });
    outlineMats.set(width, m);
    return m;
  }

  // Normals averaged over every vertex at the same spot, so the extruded hull has no gaps at corners.
  function smoothNormals(g) {
    const P = g.attributes.position, N = g.attributes.normal;
    const keys = new Map(), acc = [], idx = new Int32Array(P.count);
    for (let i = 0; i < P.count; i++) {
      const key = Math.round(P.getX(i) * 400) + ',' + Math.round(P.getY(i) * 400) + ',' + Math.round(P.getZ(i) * 400);
      let k = keys.get(key);
      if (k == null) {
        k = acc.length / 3;
        keys.set(key, k);
        acc.push(0, 0, 0);
      }
      acc[k * 3] += N.getX(i);
      acc[k * 3 + 1] += N.getY(i);
      acc[k * 3 + 2] += N.getZ(i);
      idx[i] = k;
    }
    const out = new Float32Array(P.count * 3);
    for (let i = 0; i < P.count; i++) {
      const k = idx[i] * 3;
      const l = Math.hypot(acc[k], acc[k + 1], acc[k + 2]) || 1;
      out[i * 3] = acc[k] / l;
      out[i * 3 + 1] = acc[k + 1] / l;
      out[i * 3 + 2] = acc[k + 2] / l;
    }
    return new T.BufferAttribute(out, 3);
  }

  const settings = { outlines: true };

  // Gives a mesh (or skinned mesh) an ink outline that follows it; width in metres.
  function outline(mesh, width = 0.016) {
    if (!settings.outlines) return null;
    const g = mesh.geometry;
    if (!g.attributes.onormal) g.setAttribute('onormal', smoothNormals(g));
    if (!g.attributes.owidth) g.setAttribute('owidth', new T.Float32BufferAttribute(new Float32Array(g.attributes.position.count).fill(1), 1));
    let o;
    if (mesh.isSkinnedMesh) {
      o = new T.SkinnedMesh(g, outlineMaterial(width));
      o.bind(mesh.skeleton, mesh.bindMatrix);
    } else {
      o = new T.Mesh(g, outlineMaterial(width));
    }
    o.matrixAutoUpdate = false;
    o.userData.outline = true;
    mesh.add(o);
    return o;
  }

  // ------------------------------------------------------------------ batches

  /* Up to `max` quads rebuilt each frame. Camera-facing (billboards) unless ground is true, in
   * which case they lie flat on the road. add() takes centre, size, colour + alpha, a rotation
   * and an optional uv rect for atlases. */
  class Batch {
    constructor(max, material, ground) {
      this.max = max;
      this.ground = !!ground;
      this.n = 0;
      this.pos = new Float32Array(max * 12);
      this.uv = new Float32Array(max * 8);
      this.col = new Float32Array(max * 16);
      const idx = new Uint16Array(max * 6);
      for (let i = 0; i < max; i++) {
        const v = i * 4, k = i * 6;
        idx.set([v, v + 1, v + 2, v, v + 2, v + 3], k);
      }
      const g = new T.BufferGeometry();
      g.setIndex(new T.BufferAttribute(idx, 1));
      this.aPos = new T.BufferAttribute(this.pos, 3).setUsage(T.DynamicDrawUsage);
      this.aUv = new T.BufferAttribute(this.uv, 2).setUsage(T.DynamicDrawUsage);
      this.aCol = new T.BufferAttribute(this.col, 4).setUsage(T.DynamicDrawUsage);
      g.setAttribute('position', this.aPos);
      g.setAttribute('uv', this.aUv);
      g.setAttribute('color', this.aCol);
      g.setDrawRange(0, 0);
      this.geo = g;
      this.mesh = new T.Mesh(g, material);
      this.mesh.frustumCulled = false;
      this.rx = new T.Vector3(1, 0, 0);
      this.ry = new T.Vector3(0, 1, 0);
    }

    begin(camera) {
      this.n = 0;
      if (camera) {
        const e = camera.matrixWorld.elements;
        this.rx.set(e[0], e[1], e[2]);
        this.ry.set(e[4], e[5], e[6]);
      }
    }

    // Size sx × sy (metres); c: THREE.Color or [r, g, b]; rot: radians (billboards spin in
    // screen space; ground quads turn about y, with rot 0 running down the road).
    add(x, y, z, sx, sy, c, a, rot = 0, uv) {
      if (this.n >= this.max || a <= 0.002) return;
      const i = this.n++;
      sx *= 0.5;
      sy *= 0.5;
      const cs = Math.cos(rot), sn = Math.sin(rot);
      let ux, uy, uz, vx, vy, vz;
      if (this.ground) {
        // u runs across, v along the length (-z when rot = 0)
        ux = cs * sx; uy = 0; uz = -sn * sx;
        vx = -sn * sy; vy = 0; vz = -cs * sy;
      } else {
        const R = this.rx, U = this.ry;
        ux = (R.x * cs + U.x * sn) * sx; uy = (R.y * cs + U.y * sn) * sx; uz = (R.z * cs + U.z * sn) * sx;
        vx = (U.x * cs - R.x * sn) * sy; vy = (U.y * cs - R.y * sn) * sy; vz = (U.z * cs - R.z * sn) * sy;
      }
      const p = this.pos, o = i * 12;
      p[o] = x - ux - vx; p[o + 1] = y - uy - vy; p[o + 2] = z - uz - vz;
      p[o + 3] = x + ux - vx; p[o + 4] = y + uy - vy; p[o + 5] = z + uz - vz;
      p[o + 6] = x + ux + vx; p[o + 7] = y + uy + vy; p[o + 8] = z + uz + vz;
      p[o + 9] = x - ux + vx; p[o + 10] = y - uy + vy; p[o + 11] = z - uz + vz;
      const r = uv || FULL;
      const t = this.uv, q = i * 8;
      t[q] = r[0]; t[q + 1] = r[1]; t[q + 2] = r[2]; t[q + 3] = r[1];
      t[q + 4] = r[2]; t[q + 5] = r[3]; t[q + 6] = r[0]; t[q + 7] = r[3];
      const cr = c.isColor ? c.r : c[0], cg = c.isColor ? c.g : c[1], cb = c.isColor ? c.b : c[2];
      const k = this.col, w = i * 16;
      for (let j = 0; j < 16; j += 4) {
        k[w + j] = cr;
        k[w + j + 1] = cg;
        k[w + j + 2] = cb;
        k[w + j + 3] = a;
      }
    }

    end() {
      const n = this.n;
      this.geo.setDrawRange(0, n * 6);
      if (!n) return;
      this.aPos.updateRange.count = n * 12;
      this.aUv.updateRange.count = n * 8;
      this.aCol.updateRange.count = n * 16;
      this.aPos.needsUpdate = this.aUv.needsUpdate = this.aCol.needsUpdate = true;
    }
  }
  const FULL = [0, 0, 1, 1];

  // ------------------------------------------------------------------ canvas textures

  let aniso = 1;
  const allTex = [];
  const textPainters = [];

  /* A texture painted by draw(ctx, w, h). opts: repeat (tile it), text (has Bengali text: repaint
   * when the fonts arrive), nearest (pixel look), mips (false to skip mipmaps). */
  function canvasTex(w, h, draw, o = {}) {
    const cv = document.createElement('canvas');
    cv.width = w;
    cv.height = h;
    const ctx = cv.getContext('2d');
    const t = new T.CanvasTexture(cv);
    if (o.repeat) t.wrapS = t.wrapT = T.RepeatWrapping;
    if (o.nearest) t.magFilter = T.NearestFilter;
    if (o.mips === false) {
      t.generateMipmaps = false;
      t.minFilter = T.LinearFilter;
    }
    t.anisotropy = aniso;
    const paint = () => {
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, w, h);
      ctx.save();
      draw(ctx, w, h);
      ctx.restore();
      t.needsUpdate = true;
    };
    paint();
    if (o.text) textPainters.push(paint);
    allTex.push(t);
    t.userData.paint = paint;
    return t;
  }

  function setAniso(n) {
    aniso = Math.max(1, Math.min(8, n || 1));
    for (const t of allTex) {
      if (t.anisotropy !== aniso) {
        t.anisotropy = aniso;
        t.needsUpdate = true;
      }
    }
  }

  // Galada and Hind Siliguri come from Google Fonts; textures painted before they arrive are
  // repainted once they do (the system Bengali font stands in until then).
  const fontsReady = (() => {
    if (!document.fonts || !document.fonts.load) return Promise.resolve();
    const loads = ['40px Galada', "700 40px 'Hind Siliguri'", "600 40px 'Hind Siliguri'"].map((f) => document.fonts.load(f).catch(() => null));
    const timeout = new Promise((res) => setTimeout(res, 6000));
    return Promise.race([Promise.all(loads), timeout]);
  })();
  fontsReady.then(() => {
    for (const p of textPainters) p();
  });

  // Atlas cell → uv rect [u0, v0, u1, v1] (v up) for a grid of cols × rows, cell (c, r) from the top left.
  function cell(cols, rows, c, r, inset = 0) {
    const du = 1 / cols, dv = 1 / rows;
    return [c * du + inset, 1 - (r + 1) * dv + inset, (c + 1) * du - inset, 1 - r * dv - inset];
  }

  BT.k3 = {
    T, K, LW, col, mix, tf,
    BOX, CYL, BALL, DOME, RING, UP,
    Builder, extrude, qbez, faceNormals,
    MAT, INK, outline, outlineMaterial, settings,
    Batch, canvasTex, setAniso, fontsReady, cell,
  };
})();
