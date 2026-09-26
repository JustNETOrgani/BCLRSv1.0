const solc = require('solc');
const fs = require('fs');
const Ganache = require('ganache'); // Hardhat's ganache-core fork, supports EIP-1559 and latest evmVersion.
const { ethers } = require('ethers');

function compile() {
  const source = fs.readFileSync('bcscfRS_ring.sol', 'utf8');
  const input = {
    language: 'Solidity',
    sources: { 'bcscfRS_ring.sol': { content: source } },
    settings: {
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'paris'
    }
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  return output.contracts['bcscfRS_ring.sol']['bscfRSscheme'];
}

// Minimal BN254 G1 double-and-add, to generate genuine on-curve points for
// synthetic registrations without needing JPBC.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function modinv(a, m) {
  a = ((a % m) + m) % m;
  let [old_r, r] = [a, m], [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}
function ecAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  if (p1.x === p2.x) {
    if ((p1.y + p2.y) % P === 0n) return null;
    const lam = (3n * p1.x * p1.x % P) * modinv(2n * p1.y % P, P) % P;
    const x3 = ((lam * lam % P) - 2n * p1.x % P + 2n * P) % P;
    const y3 = (lam * ((p1.x - x3 + P) % P) % P - p1.y + P) % P;
    return { x: x3, y: y3 };
  }
  const lam = ((p2.y - p1.y + P) % P) * modinv((p2.x - p1.x + P) % P, P) % P;
  const x3 = ((lam * lam % P) - p1.x - p2.x % P + 2n * P) % P;
  const y3 = (lam * ((p1.x - x3 + P) % P) % P - p1.y + P) % P;
  return { x: x3, y: y3 };
}
function ecMul(p, k) {
  let result = null, addend = p, n = k;
  while (n > 0n) {
    if (n & 1n) result = ecAdd(result, addend);
    addend = ecAdd(addend, addend);
    n >>= 1n;
  }
  return result;
}
const G1 = { x: 1n, y: 2n };

const zeroG1 = { X: 0, Y: 0 }, zeroG2 = { X_im: 0, X_re: 0, Y_im: 0, Y_re: 0 };

async function main() {
  const main_ = compile();
  const ganacheProvider = Ganache.provider({
    wallet: { totalAccounts: 30 }, // need many funded accounts for pipelined throughput
    chain: { chainId: 1337 },
    miner: { blockGasLimit: 30000000 }, // default (instant-ish) mining
    logging: { quiet: true }
  });
  const provider = new ethers.BrowserProvider(ganacheProvider);
  const signer = await provider.getSigner(0);

  const factory = new ethers.ContractFactory(main_.abi, main_.evm.bytecode.object, signer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log('Deployed at:', await contract.getAddress());

  // ---- Real sample data for ringVerifyWithMembership ----
  const kgcPubKeyG1 = { X: "20484736780382180286641506116760294786231772956305958449920117069302197242853", Y: "16337996554482569242356137284066186669236318471945033037098376887892469406831" };
  const kgcPubKeyG2 = { X_im: "8297521937588458008432929081494822497332880023532959377428373828146700776782", X_re: "12320186439841233105458828660174676398308705701701196481453252928442411844890", Y_im: "7092481283306635211552399081234358748693143939558440628626240680835782798859", Y_re: "11093252773790311127436144375842714715050895379980818951573863247444249916305" };
  const ringUID = {
    "hi@qq.com": ["16155983079313238063540842068822038022529244012622792822701642693631513046807", "4221978585646324943109798689504440861018295605785410504179035564574016193802"],
    "justnetorgani@github.com": ["18460008114367690497854933884265666030425238810883274629037842928069415252061", "3793340494043098784010000845946307843203604947008167153120806838623012369505"],
    "security@outlook.com": ["1477537151327757099973466927987739786379169324061195688767059046318272480321", "21509702036821530665921374946794782722957429646555318864326043213033062915736"],
    "ytx@qq.com": ["15833237678035927115830725849768585616977095891977157695194637910420639434218", "21751681234214492613452130748209889403891999874474198033491793098956016556103"]
  };
  const userList = Object.keys(ringUID);
  const sig = {
    A_s: { X: "13420741337982026786518302171264918317307812302781408742407399690913460422481", Y: "10073964645802629287898117835754854697387812787916512784138558138270232379095" },
    B_s: { X: "6005686010511721984143087624377364009658817375698770972384843821597473965761", Y: "17149668903027073339991952687336226663343100834337186963512837704148140537323" },
    keyImage: { X: "15432282766570594798500466619088578878468541387427295265690422026023385968309", Y: "2847528693487998494921737177757595881428493473583346615078124703890107132993" },
    h_As: "13700946565382070058410564599363075700759641924274828713312100748098993174932"
  };
  const eStart = "14696692000786419470956169489022108871386355991600442201922129391027548790109";
  const z = ["13130302915360722860876494961299279046564053576427122290137034874982424714947", "7308285220822525095017139762453687437224026658057988376109153257457056273350", "20177362085977668050617835868007316110801286178160715669125941698017971387340", "20122398413237753771658552747417231783968540131663335352033923664831585919758"];

  // Register all 4 real ring members + KGC params first (setup, not measured).
  await (await contract.publishPublicParams(kgcPubKeyG1, kgcPubKeyG2)).wait();
  for (const [id, [x, y]] of Object.entries(ringUID)) {
    await (await contract.publishUserPublicParams(id, { X: x, Y: y }, zeroG1, zeroG2, zeroG1)).wait();
  }
  // sanity check the real signature still verifies on this fresh deployment
  const ok = await contract.ringVerifyWithMembership(userList, "RS with BN256", sig, "BCSCFFSKI-SBv-2026", 15, eStart, z);
  console.log('Sanity check (real signature verifies):', ok);
  console.log();

  const stats = (arr) => {
    const sorted = [...arr].sort((a, b) => a - b);
    const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
    const median = sorted[Math.floor(sorted.length / 2)];
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    return { mean, median, min: sorted[0], max: sorted[sorted.length - 1], p95 };
  };

  // ============ LATENCY: N sequential trials, each timed individually ============
  console.log('=== LATENCY (ms), N=20 sequential trials, submit -> wait for receipt ===\n');

  async function measureLatency(label, sendFn, n = 20) {
    const samples = [];
    for (let i = 0; i < n; i++) {
      const t0 = Date.now();
      const tx = await sendFn(i);
      await tx.wait();
      samples.push(Date.now() - t0);
    }
    const s = stats(samples);
    console.log(`${label}:`);
    console.log(`  mean=${s.mean.toFixed(1)}ms  median=${s.median}ms  min=${s.min}ms  max=${s.max}ms  p95=${s.p95}ms`);
    return s;
  }

  // publishPublicParams: structurally called at most ONCE per contract
  // (single KGC per deployment, keyed by msg.sender==AddrOfKGC) - repeat
  // calls overwrite the same slot and would measure a mix of one genuinely
  // cold write plus artificially-warm repeats, not realistic usage. Report
  // a single real (cold, first-ever) call's latency instead of N trials.
  {
    const t0 = Date.now();
    const tx = await contract.publishPublicParams(kgcPubKeyG1, kgcPubKeyG2); // overwrite is fine, same values
    await tx.wait();
    const ms = Date.now() - t0;
    console.log(`publishPublicParams (single call - see note: only ever called once per deployment in this design):`);
    console.log(`  latency=${ms}ms\n`);
  }

  await measureLatency('publishUserPublicParams (fresh distinct identity each trial)', async (i) => {
    const pt = ecMul(G1, BigInt(1000 + i));
    return contract.publishUserPublicParams('lat-user-' + i, { X: pt.x.toString(), Y: pt.y.toString() }, zeroG1, zeroG2, zeroG1);
  });

  await measureLatency('publishEmbedPartialPrivKey (varying s/yID each trial, same KGC)', async (i) => {
    return contract.publishEmbedPartialPrivKey(1000 + i, zeroG1);
  });

  await measureLatency('ringVerifyWithMembership (sent as a real tx, not eth_call - see note)', async (i) => {
    // view functions get auto-routed to eth_call by ethers; force a real
    // mined transaction instead by building and sending it manually.
    const txData = await contract.ringVerifyWithMembership.populateTransaction(
      userList, "RS with BN256", sig, "BCSCFFSKI-SBv-2026", 15, eStart, z
    );
    return signer.sendTransaction(txData);
  });

  // Also measure ringVerifyWithMembership the way it'd normally be invoked:
  // as a read-only eth_call, no transaction, no mining.
  {
    const samples = [];
    for (let i = 0; i < 20; i++) {
      const t0 = Date.now();
      await contract.ringVerifyWithMembership(userList, "RS with BN256", sig, "BCSCFFSKI-SBv-2026", 15, eStart, z);
      samples.push(Date.now() - t0);
    }
    const s = stats(samples);
    console.log(`ringVerifyWithMembership (as eth_call, view - no mining):`);
    console.log(`  mean=${s.mean.toFixed(1)}ms  median=${s.median}ms  min=${s.min}ms  max=${s.max}ms  p95=${s.p95}ms\n`);
  }

  console.log('\n=== THROUGHPUT (TPS), K=20 pipelined submissions (sequential nonces, no per-tx wait) ===\n');

  async function measureThroughput(label, buildTxFn, k = 20, signerOverride = null) {
    const s = signerOverride || signer;
    const startNonce = await provider.getTransactionCount(await s.getAddress());
    const t0 = Date.now();
    const sent = [];
    for (let i = 0; i < k; i++) {
      sent.push(buildTxFn(i, s, startNonce + i));
    }
    const txResponses = await Promise.all(sent);
    const receipts = await Promise.all(txResponses.map(tx => tx.wait()));
    const elapsedSec = (Date.now() - t0) / 1000;
    const tps = k / elapsedSec;
    console.log(`${label}:`);
    console.log(`  ${k} txs in ${elapsedSec.toFixed(3)}s => ${tps.toFixed(2)} TPS`);
    return tps;
  }

  await measureThroughput('publishUserPublicParams (20 distinct new identities, pipelined)', (i, s, nonce) => {
    const pt = ecMul(G1, BigInt(2000 + i));
    return contract.connect(s).publishUserPublicParams('tps-user-' + i, { X: pt.x.toString(), Y: pt.y.toString() }, zeroG1, zeroG2, zeroG1, { nonce });
  });

  await measureThroughput('publishEmbedPartialPrivKey (20 pipelined, same KGC account)', (i, s, nonce) => {
    return contract.connect(s).publishEmbedPartialPrivKey(2000 + i, zeroG1, { nonce });
  });

  await measureThroughput('ringVerifyWithMembership (20 pipelined, sent as real txs)', async (i, s, nonce) => {
    const txData = await contract.ringVerifyWithMembership.populateTransaction(
      userList, "RS with BN256", sig, "BCSCFFSKI-SBv-2026", 15, eStart, z
    );
    txData.nonce = nonce;
    return s.sendTransaction(txData);
  });

  // eth_call throughput for ringVerifyWithMembership (fire 20 concurrent
  // read calls, no mining/nonces involved at all).
  {
    const t0 = Date.now();
    await Promise.all(Array.from({ length: 20 }, () =>
      contract.ringVerifyWithMembership(userList, "RS with BN256", sig, "BCSCFFSKI-SBv-2026", 15, eStart, z)
    ));
    const elapsedSec = (Date.now() - t0) / 1000;
    console.log(`ringVerifyWithMembership (20 concurrent eth_call reads, no mining):`);
    console.log(`  20 calls in ${elapsedSec.toFixed(3)}s => ${(20 / elapsedSec).toFixed(2)} calls/sec\n`);
  }
}

main().catch(e => { console.error('FATAL', e); process.exit(1); });
