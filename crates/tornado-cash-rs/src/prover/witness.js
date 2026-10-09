// Witness calculator for circuits compiled by circom 0.0.x (the JSON format
// the Tornado Cash Classic withdraw circuit ships in). This is a port of
// snarkjs 0.1.x `calculateWitness` and its native-BigInt `bigint.js` shim;
// the circuit's own template code does the actual work.
(function (g) {
  const P = BigInt
  const B = BigInt.prototype
  B.add = function (b) { return this + b }
  B.sub = function (b) { return this - b }
  B.mul = function (b) { return this * b }
  B.div = function (b) { return this / b }
  B.mod = function (b) { return this % b }
  B.and = function (b) { return this & b }
  B.shr = function (b) { return this >> BigInt(b) }
  B.shl = function (b) { return this << BigInt(b) }
  B.greater = function (b) { return this > b }
  B.gt = B.greater
  B.lesser = function (b) { return this < b }
  B.lt = B.lesser
  B.equals = function (b) { return this == b }
  B.eq = B.equals
  B.neq = function (b) { return this != b }
  B.modPow = function (e, m) {
    let acc = 1n, exp = this, rem = e
    while (rem) { if (rem & 1n) acc = (acc * exp) % m; exp = (exp * exp) % m; rem = rem >> 1n }
    return acc
  }
  const affine = (a, q) => { let x = a % q; if (x < 0n) x += q; return x }
  B.affine = function (q) { return affine(this, q) }
  B.inverse = function (q) {
    let t = 0n, r = q, newt = 1n, newr = affine(this, q)
    while (newr != 0n) { const k = r / newr;[t, newt] = [newt, t - k * newt];[r, newr] = [newr, r - k * newr] }
    if (t < 0n) t += q
    return t
  }
  g.bigInt = (x) => BigInt(x)
  g.__P__ = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
  g.__MASK__ = BigInt('28948022309329048855892746252171976963317496166410141009864396001978282409983')

  g.calculateWitness = function (circuit, inputs) {
    const templates = {}
    for (const t in circuit.templates) templates[t] = (0, eval)('(' + circuit.templates[t] + ')')
    const functions = {}
    for (const f in circuit.functions) functions[f] = { params: circuit.functions[f].params, func: (0, eval)('(' + circuit.functions[f].func + ')') }
    const name2idx = circuit.signalName2Idx
    const triggers = circuit.triggers
    const components = circuit.components
    const witness = new Array(circuit.nSignals)
    const notInit = components.map((c) => c.inputSignals)
    const sels = (s) => { let r = ''; for (let i = 0; i < s.length; i++) r += '[' + s[i] + ']'; return r }
    const idx = (n) => { const i = name2idx[n]; if (i === undefined) throw new Error('Invalid signal identifier: ' + n); return i }
    const ctx = {
      scopes: [{}],
      currentComponent: undefined,
      setPin(cn, cs, sn, ss, v) { this.setFull((cn == 'one' ? 'one' : this.currentComponent + '.' + cn) + sels(cs) + '.' + sn + sels(ss), v) },
      setSignal(n, s, v) { this.setFull((this.currentComponent ? this.currentComponent + '.' + n : n) + sels(s), v) },
      getPin(cn, cs, sn, ss) { return this.getFull((cn == 'one' ? 'one' : this.currentComponent + '.' + cn) + sels(cs) + '.' + sn + sels(ss)) },
      getSignal(n, s) { return this.getFull((n == 'one' ? 'one' : this.currentComponent + '.' + n) + sels(s)) },
      getFull(n) { const i = idx(n); if (witness[i] === undefined) throw new Error('Signal not initialized: ' + n); return witness[i] },
      setFull(n, v) {
        const i = idx(n)
        const first = witness[i] === undefined
        witness[i] = BigInt(v)
        const tc = triggers[i]
        if (first) for (let k = 0; k < tc.length; k++) notInit[tc[k]]--
        for (let k = 0; k < tc.length; k++) if (notInit[tc[k]] == 0) this.trigger(tc[k])
      },
      setVar(n, s, v) {
        const scope = this.scopes[this.scopes.length - 1]
        if (s.length == 0) { scope[n] = v } else {
          if (scope[n] === undefined) scope[n] = []
          let a = scope[n]
          for (let k = 0; k < s.length - 1; k++) { if (a[s[k]] === undefined) a[s[k]] = []; a = a[s[k]] }
          a[s[s.length - 1]] = v
        }
        return v
      },
      getVar(n, s) {
        for (let i = this.scopes.length - 1; i >= 0; i--) {
          let a = this.scopes[i][n]
          if (a !== undefined) { for (let k = 0; k < s.length; k++) a = a[s[k]]; return a }
        }
        throw new Error('Variable not defined: ' + n)
      },
      assert(a, b, e) {
        const x = BigInt(a), y = BigInt(b)
        if (x != y) throw new Error('Constraint doesn\'t match ' + this.currentComponent + ': ' + e + ' -> ' + x + ' != ' + y)
      },
      trigger(c) {
        notInit[c]--
        const oldC = this.currentComponent, oldS = this.scopes
        const comp = components[c]
        this.currentComponent = comp.name
        const scope = {}
        for (const p in comp.params) scope[p] = comp.params[p]
        this.scopes = [oldS[0], scope]
        templates[comp.template](this)
        this.scopes = oldS
        this.currentComponent = oldC
      },
      callFunction(name, params) {
        const f = functions[name]
        const scope = {}
        for (let p = 0; p < f.params.length; p++) scope[f.params[p]] = params[p]
        const oldS = this.scopes
        this.scopes = [oldS[0], scope]
        const r = f.func(this)
        this.scopes = oldS
        return r
      },
    }
    ctx.setSignal('one', [], 1n)
    for (let c = 0; c < notInit.length; c++) if (notInit[c] == 0) ctx.trigger(c)
    for (const s in inputs) {
      ctx.currentComponent = 'main'
      const walk = (v, path) => {
        if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) { path.push(i); walk(v[i], path); path.pop() } }
        else ctx.setSignal(s, path, BigInt(v))
      }
      walk(inputs[s], [])
    }
    const out = new Array(circuit.nVars)
    for (let i = 0; i < circuit.nVars; i++) {
      if (witness[i] === undefined) throw new Error('Signal not assigned: #' + i)
      out[i] = witness[i].toString()
    }
    return out.join(',')
  }
})(globalThis)
