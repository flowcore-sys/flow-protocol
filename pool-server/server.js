/**
 * FTC Mining Pool Server v1.2.0
 * Stratum Protocol + HTTP Stats API
 * Fixed: block detection, hashrate calculation, difficulty formula
 */

const net = require('net');
const crypto = require('crypto');
const http = require('http');

// ============================================================================
// Configuration (from environment variables)
// ============================================================================

const CONFIG = {
    // Pool settings
    POOL_PORT: parseInt(process.env.POOL_PORT) || 3333,
    POOL_DIFFICULTY: parseFloat(process.env.POOL_DIFFICULTY) || 1,
    POOL_FEE: parseFloat(process.env.POOL_FEE) || 0.01,
    POOL_ADDRESS: process.env.POOL_ADDRESS || '1FNSduApfZwckr9mEmKb7XBnmP4yhni857',

    // HTTP Stats API
    HTTP_PORT: parseInt(process.env.HTTP_PORT) || 8080,

    // FTC Node RPC - USE DOMAIN NAME for flexibility
    NODE_HOST: process.env.NODE_HOST || 'node.flowprotocol.net',
    NODE_RPC_PORT: parseInt(process.env.NODE_RPC_PORT) || 17318,
    NODE_RPC_USER: process.env.NODE_RPC_USER || 'ftcuser',
    NODE_RPC_PASS: process.env.NODE_RPC_PASS || 'ftcpass',

    // Mining parameters
    BLOCK_POLL_INTERVAL: 1000,
    SHARE_DIFFICULTY: 65536,
    EXTRANONCE2_SIZE: 4,

    // Vardiff settings
    VARDIFF_MIN: 0.00001,
    VARDIFF_MAX: 65536,
    VARDIFF_TARGET_TIME: 15,
    VARDIFF_RETARGET: 60,
    VARDIFF_VARIANCE: 0.3,
};

// ============================================================================
// Global State
// ============================================================================

let g_clients = new Map();
let g_nextClientId = 1;
let g_extranonce1Counter = 0;
let g_currentJob = null;
let g_jobId = 0;
let g_blockHeight = 0;
let g_networkDifficulty = 65536;

// Stats
let g_stats = {
    startTime: Date.now(),
    blocksFound: 0,
    sharesAccepted: 0,
    sharesRejected: 0,
    totalHashrate: 0,
    connectedMiners: 0,
    lastBlockTime: null,
    lastBlockHeight: 0,
};

// Worker stats (by worker name)
let g_workers = new Map();

// ============================================================================
// Utility Functions
// ============================================================================

function log(level, msg) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [${level}] ${msg}`);
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return Buffer.from(bytes);
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function reverseHex(hex) {
    return hex.match(/.{2}/g).reverse().join('');
}

// Use js-sha3 library for proper keccak256 (NOT sha3-256!)
const { keccak256: keccak256Hex } = require('js-sha3');

function keccak256(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return Buffer.from(keccak256Hex(buf), 'hex');
}

function doubleKeccak256(data) {
    const hash1 = keccak256(data);
    return keccak256(hash1);
}

function generateExtranonce1() {
    g_extranonce1Counter++;
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(g_extranonce1Counter);
    return buf.toString('hex');
}

function diffToTarget(diff) {
    const maxTarget = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');
    const target = maxTarget / BigInt(Math.floor(diff));
    return target.toString(16).padStart(64, '0');
}

function targetToDiff(targetHex) {
    // FTC hash is in LE, reverse to BE for comparison
    const reversedHex = reverseHex(targetHex);
    const target = BigInt('0x' + reversedHex);
    if (target === 0n) return Number.MAX_SAFE_INTEGER;
    // FTC max target (diff 1) from genesis bits 0x1e0fffff:
    // exponent = 0x1e = 30, coefficient = 0x0fffff
    // target = coefficient * 256^(exp-3) = 0x0fffff * 2^(8*27) = 0x0fffff * 2^216
    const maxTarget = BigInt('0x0fffff') << 216n;
    return Number(maxTarget / target);
}

// Get network target from nbits (for block detection)
function nbitsToTarget(nbitsHex) {
    // nbits is in LE hex, convert to number
    const nbits = parseInt(reverseHex(nbitsHex), 16);
    const exp = (nbits >> 24) & 0xff;
    const coeff = nbits & 0x007fffff;
    // target = coeff * 256^(exp-3)
    const target = BigInt(coeff) << BigInt(8 * (exp - 3));
    return target;
}

// Check if hash meets network target (for block detection)
function hashMeetsTarget(hashHex, nbitsHex) {
    // Hash is LE, reverse to BE for comparison
    const hashBE = BigInt('0x' + reverseHex(hashHex));
    const target = nbitsToTarget(nbitsHex);
    return hashBE <= target;
}

function formatHashrate(h) {
    if (h >= 1e12) return (h / 1e12).toFixed(2) + ' TH/s';
    if (h >= 1e9) return (h / 1e9).toFixed(2) + ' GH/s';
    if (h >= 1e6) return (h / 1e6).toFixed(2) + ' MH/s';
    if (h >= 1e3) return (h / 1e3).toFixed(2) + ' KH/s';
    return h.toFixed(0) + ' H/s';
}

function formatUptime(ms) {
    const sec = Math.floor(ms / 1000);
    const days = Math.floor(sec / 86400);
    const hours = Math.floor((sec % 86400) / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h ${mins}m`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

// ============================================================================
// JSON-RPC Client for FTC Node
// ============================================================================

function rpcCall(method, params = []) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: method,
            params: params
        });

        const auth = Buffer.from(`${CONFIG.NODE_RPC_USER}:${CONFIG.NODE_RPC_PASS}`).toString('base64');

        const options = {
            hostname: CONFIG.NODE_HOST,  // Can be domain or IP
            port: CONFIG.NODE_RPC_PORT,
            path: '/',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'Authorization': `Basic ${auth}`
            },
            timeout: 10000
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(body);
                    if (json.error) {
                        reject(new Error(json.error.message || JSON.stringify(json.error)));
                    } else {
                        resolve(json.result);
                    }
                } catch (e) {
                    reject(new Error(`Invalid JSON: ${body.substring(0, 200)}`));
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.write(data);
        req.end();
    });
}

// ============================================================================
// Block Template Management
// ============================================================================

async function getBlockTemplate() {
    try {
        const template = await rpcCall('getblocktemplate', [CONFIG.POOL_ADDRESS]);
        return template;
    } catch (e) {
        log('ERROR', `getBlockTemplate failed: ${e.message}`);
        return null;
    }
}

async function submitBlock(blockHex) {
    try {
        const result = await rpcCall('submitblock', [blockHex]);
        return result === null || result === undefined;
    } catch (e) {
        log('ERROR', `submitBlock failed: ${e.message}`);
        return false;
    }
}

async function updateJob() {
    const template = await getBlockTemplate();
    if (!template) return false;

    const newHeight = template.height;

    // FTC returns: { height, bits, difficulty, blockdata }
    // blockdata is the full serialized block in hex
    if (g_currentJob && g_blockHeight === newHeight) {
        return false;
    }

    g_blockHeight = newHeight;
    g_networkDifficulty = template.difficulty || 65536;
    g_jobId++;

    // Parse block header from blockdata (first 80 bytes = 160 hex chars)
    const blockdata = template.blockdata;
    const headerHex = blockdata.substring(0, 160);

    // Header structure: version(8) + prevhash(64) + merkle(64) + time(8) + bits(8) + nonce(8)
    const version = headerHex.substring(0, 8);
    const prevhash = headerHex.substring(8, 72);
    const merkle = headerHex.substring(72, 136);
    const ntime = headerHex.substring(136, 144);
    const nbits = headerHex.substring(144, 152);

    log('DEBUG', `Template bits from RPC: ${template.bits}`);
    log('DEBUG', `Header hex: ${headerHex}`);
    log('DEBUG', `Extracted nbits: ${nbits} -> send as ${reverseHex(nbits)}`);

    g_currentJob = {
        id: g_jobId.toString(16).padStart(8, '0'),
        prevhash: prevhash,
        merkle: merkle,
        version: version,
        nbits: nbits,
        ntime: ntime,
        blockdata: blockdata,  // Full block for submission
        clean_jobs: true,
    };

    log('INFO', `New job #${g_currentJob.id} height=${newHeight} diff=${g_networkDifficulty}`);
    broadcastJob();
    return true;
}

function buildCoinbase(template, value) {
    const blockHeight = template.height;
    const heightScript = encodeBlockHeight(blockHeight);

    let coinb1 = '01000000';
    coinb1 += '01';
    coinb1 += '0000000000000000000000000000000000000000000000000000000000000000';
    coinb1 += 'ffffffff';

    const extraDataHex = Buffer.from('/FTC Pool/').toString('hex');
    const scriptLen = (heightScript.length / 2) + (extraDataHex.length / 2) + 4 + CONFIG.EXTRANONCE2_SIZE;
    coinb1 += scriptLen.toString(16).padStart(2, '0');
    coinb1 += heightScript;
    coinb1 += extraDataHex;

    let coinb2 = '';
    coinb2 += 'ffffffff';
    coinb2 += '01';

    const valueBuf = Buffer.alloc(8);
    valueBuf.writeBigUInt64LE(BigInt(value));
    coinb2 += valueBuf.toString('hex');

    const outputScript = '6a0c46544320506f6f6c205631';
    coinb2 += (outputScript.length / 2).toString(16).padStart(2, '0');
    coinb2 += outputScript;
    coinb2 += '00000000';

    return { coinb1, coinb2 };
}

function encodeBlockHeight(height) {
    if (height < 17) {
        return (0x50 + height).toString(16).padStart(2, '0');
    }
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(height);
    let len = 4;
    while (len > 1 && buf[len - 1] === 0) len--;
    if (buf[len - 1] & 0x80) len++;
    return len.toString(16).padStart(2, '0') + buf.slice(0, len).toString('hex');
}

// ============================================================================
// Stratum Client
// ============================================================================

class StratumClient {
    constructor(socket, id) {
        this.socket = socket;
        this.id = id;
        this.ip = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        this.port = socket.remotePort;
        this.authorized = false;
        this.subscribed = false;
        this.worker = '';
        this.extranonce1 = generateExtranonce1();
        this.difficulty = CONFIG.POOL_DIFFICULTY;
        this.connectTime = Date.now();
        this.lastActivity = Date.now();
        this.sharesAccepted = 0;
        this.sharesRejected = 0;
        this.lastShareTime = null;
        this.hashrate = 0;
        this.vardiffLastRetarget = Date.now();
        this.vardiffShareCount = 0;
        this.buffer = '';

        log('INFO', `[+] Miner #${id} connected from ${this.ip}`);

        socket.setEncoding('utf8');
        socket.on('data', (data) => this.onData(data));
        socket.on('close', () => this.onClose());
        socket.on('error', (err) => this.onError(err));
    }

    onData(data) {
        log('DEBUG', `Miner #${this.id} raw data: ${data.substring(0, 200)}`);
        this.buffer += data;
        this.lastActivity = Date.now();

        let lines = this.buffer.split('\n');
        this.buffer = lines.pop();

        for (const line of lines) {
            if (line.trim()) {
                log('DEBUG', `Miner #${this.id} message: ${line.substring(0, 100)}`);
                this.handleMessage(line.trim());
            }
        }
    }

    handleMessage(line) {
        let msg;
        try {
            msg = JSON.parse(line);
        } catch (e) {
            return;
        }

        const method = msg.method;
        const params = msg.params || [];
        const id = msg.id;

        switch (method) {
            case 'mining.subscribe':
                this.handleSubscribe(id, params);
                break;
            case 'mining.authorize':
                this.handleAuthorize(id, params);
                break;
            case 'mining.submit':
                this.handleSubmit(id, params);
                break;
            case 'mining.extranonce.subscribe':
                this.send({ id, result: true, error: null });
                break;
            default:
                this.send({ id, result: null, error: [20, 'Unknown method', null] });
        }
    }

    handleSubscribe(id, params) {
        const userAgent = params[0] || 'unknown';
        log('INFO', `Miner #${this.id} subscribe: ${userAgent}`);

        this.subscribed = true;
        this.userAgent = userAgent;

        this.send({
            id: id,
            result: [
                [['mining.set_difficulty', 'sub1'], ['mining.notify', 'sub2']],
                this.extranonce1,
                CONFIG.EXTRANONCE2_SIZE
            ],
            error: null
        });
        // Don't send difficulty/job here - wait for authorization
    }

    handleAuthorize(id, params) {
        const worker = params[0] || 'anonymous';
        this.worker = worker;
        this.authorized = true;

        // Track worker
        if (!g_workers.has(worker)) {
            g_workers.set(worker, {
                name: worker,
                firstSeen: Date.now(),
                sharesAccepted: 0,
                sharesRejected: 0,
                blocksFound: 0,
                lastShare: null,
                connections: 0
            });
        }
        g_workers.get(worker).connections++;

        log('INFO', `Miner #${this.id} authorized: ${worker}`);
        this.send({ id, result: true, error: null });

        // Now send difficulty and job after authorization
        this.sendDifficulty();
        if (g_currentJob) this.sendJob(g_currentJob);
    }

    handleSubmit(id, params) {
        if (!this.authorized) {
            this.send({ id, result: null, error: [24, 'Unauthorized', null] });
            return;
        }

        const [worker, jobId, extranonce2, ntime, nonce] = params;

        if (!g_currentJob || g_currentJob.id !== jobId) {
            this.sharesRejected++;
            g_stats.sharesRejected++;
            if (g_workers.has(worker)) g_workers.get(worker).sharesRejected++;
            this.send({ id, result: null, error: [21, 'Stale job', null] });
            return;
        }

        const shareResult = this.verifyShare(jobId, extranonce2, ntime, nonce);

        if (shareResult.valid) {
            this.sharesAccepted++;
            this.lastShareTime = Date.now();
            this.vardiffShareCount++;
            g_stats.sharesAccepted++;

            if (g_workers.has(worker)) {
                const w = g_workers.get(worker);
                w.sharesAccepted++;
                w.lastShare = Date.now();
            }

            // Estimate hashrate from pool difficulty and time between shares
            this.updateHashrate();

            this.send({ id, result: true, error: null });

            // Check if hash meets network target (actual block found)
            if (shareResult.hashHex && hashMeetsTarget(shareResult.hashHex, g_currentJob.nbits)) {
                log('INFO', `*** BLOCK FOUND by ${worker}! hash=${shareResult.hashHex.substring(0, 16)}... ***`);
                g_stats.blocksFound++;
                g_stats.lastBlockTime = Date.now();
                g_stats.lastBlockHeight = g_blockHeight;
                if (g_workers.has(worker)) g_workers.get(worker).blocksFound++;
                this.submitBlockFromShare(extranonce2, ntime, nonce);
            }
        } else {
            this.sharesRejected++;
            g_stats.sharesRejected++;
            if (g_workers.has(worker)) g_workers.get(worker).sharesRejected++;
            this.send({ id, result: null, error: [shareResult.code, shareResult.reason, null] });
        }

        this.checkVardiff();
    }

    updateHashrate() {
        // Hashrate = pool_difficulty * 2^32 / time_between_shares
        // Use pool difficulty (this.difficulty) rather than share diff which has wrong scale for FTC
        const now = Date.now();
        if (this.lastShareTime) {
            const elapsed = (now - this.lastShareTime) / 1000;
            if (elapsed > 0 && elapsed < 300) {
                this.hashrate = (this.difficulty * 4294967296) / elapsed;
            }
        }
    }

    verifyShare(jobId, extranonce2Hex, ntimeHex, nonceHex) {
        try {
            const job = g_currentJob;

            // FTC: Build header from job parts + submitted nonce
            // Header: version(4) + prevhash(32) + merkle(32) + time(4) + bits(4) + nonce(4)
            // Note: hex strings from blockdata are already in wire format (LE for ints)
            const header = Buffer.alloc(80);
            let offset = 0;

            // Version - copy bytes directly (already LE in hex)
            hexToBytes(job.version).copy(header, offset);
            offset += 4;

            // Prevhash - copy bytes directly
            hexToBytes(job.prevhash).copy(header, offset);
            offset += 32;

            // Merkle root - copy bytes directly
            hexToBytes(job.merkle).copy(header, offset);
            offset += 32;

            // Time - use submitted time (BE from miner) or job time (LE from blockdata)
            // If submitted, reverse from BE to LE; if from job, already LE
            const timeHex = ntimeHex ? reverseHex(ntimeHex.padStart(8, '0')) : job.ntime;
            hexToBytes(timeHex).copy(header, offset);
            offset += 4;

            // Bits - copy bytes directly (already LE in hex)
            hexToBytes(job.nbits).copy(header, offset);
            offset += 4;

            // Nonce (submitted by miner) - reverse bytes (miner sends BE, header needs LE)
            const nonceReversed = reverseHex(nonceHex.padStart(8, '0'));
            hexToBytes(nonceReversed).copy(header, offset);

            // DEBUG: Log header components for troubleshooting
            log('DEBUG', `=== Share verification ===`);
            log('DEBUG', `Job version:  ${job.version} (sent as ${reverseHex(job.version)})`);
            log('DEBUG', `Job prevhash: ${job.prevhash.substring(0, 32)}...`);
            log('DEBUG', `Job merkle:   ${job.merkle.substring(0, 32)}...`);
            log('DEBUG', `Job nbits:    ${job.nbits} (sent as ${reverseHex(job.nbits)})`);
            log('DEBUG', `Job ntime:    ${job.ntime} (sent as ${reverseHex(job.ntime)})`);
            log('DEBUG', `Miner ntime:  ${ntimeHex} -> reversed: ${timeHex}`);
            log('DEBUG', `Miner nonce:  ${nonceHex} -> reversed: ${nonceReversed}`);
            log('DEBUG', `Pool Header:  ${bytesToHex(header)}`);
            log('DEBUG', `Orig Header:  ${job.blockdata.substring(0, 160)}`);

            // Hash the header (double keccak256)
            const hash = doubleKeccak256(header);
            const hashHex = bytesToHex(hash);
            const hashDiff = targetToDiff(hashHex);

            log('DEBUG', `Hash: ${hashHex}, Diff: ${hashDiff}, Required: ${this.difficulty}`);

            if (hashDiff < this.difficulty) {
                return { valid: false, code: 23, reason: 'Low difficulty', diff: hashDiff };
            }

            return { valid: true, diff: hashDiff, nonce: nonceHex, hashHex: hashHex };
        } catch (e) {
            log('ERROR', `verifyShare error: ${e.message}`);
            return { valid: false, code: 20, reason: 'Error', diff: 0 };
        }
    }

    async submitBlockFromShare(extranonce2Hex, ntimeHex, nonceHex) {
        const job = g_currentJob;

        // FTC: Update blockdata with found nonce
        // Nonce is at bytes 76-80 in header = hex chars 152-160
        const blockdataWithNonce = job.blockdata.substring(0, 152) +
                                   nonceHex.padStart(8, '0') +
                                   job.blockdata.substring(160);

        log('INFO', `Submitting block with nonce ${nonceHex}...`);
        const success = await submitBlock(blockdataWithNonce);

        if (success) {
            log('INFO', `*** BLOCK ACCEPTED BY NETWORK! ***`);
        } else {
            log('ERROR', `Block rejected by network`);
        }
    }

    checkVardiff() {
        const now = Date.now();
        const elapsed = (now - this.vardiffLastRetarget) / 1000;
        if (elapsed < CONFIG.VARDIFF_RETARGET) return;

        const sharesPerSec = this.vardiffShareCount / elapsed;
        const targetSharesPerSec = 1 / CONFIG.VARDIFF_TARGET_TIME;
        if (sharesPerSec === 0) return;

        const ratio = sharesPerSec / targetSharesPerSec;
        if (ratio < (1 - CONFIG.VARDIFF_VARIANCE) || ratio > (1 + CONFIG.VARDIFF_VARIANCE)) {
            let newDiff = this.difficulty * ratio;
            newDiff = Math.max(CONFIG.VARDIFF_MIN, Math.min(CONFIG.VARDIFF_MAX, newDiff));
            newDiff = Math.round(newDiff);

            if (newDiff !== this.difficulty) {
                log('INFO', `Miner #${this.id}: Vardiff ${this.difficulty} -> ${newDiff}`);
                this.difficulty = newDiff;
                this.sendDifficulty();
            }
        }

        this.vardiffLastRetarget = now;
        this.vardiffShareCount = 0;
    }

    sendDifficulty() {
        this.send({ id: null, method: 'mining.set_difficulty', params: [this.difficulty] });
    }

    sendJob(job) {
        if (!this.subscribed) return;
        // FTC format: send header parts, miner finds nonce
        // params: [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
        // For FTC: coinb1=merkle (miner uses it), coinb2="", merkle_branch=[]
        // Note: version, nbits, ntime must be reversed to BE hex for Stratum (miner parses as BE)
        this.send({
            id: null,
            method: 'mining.notify',
            params: [job.id, job.prevhash, job.merkle, '', [],
                     reverseHex(job.version), reverseHex(job.nbits), reverseHex(job.ntime), job.clean_jobs]
        });
    }

    send(obj) {
        try {
            this.socket.write(JSON.stringify(obj) + '\n');
        } catch (e) {}
    }

    onClose() {
        log('INFO', `[-] Miner #${this.id} disconnected (${this.worker})`);
        if (this.worker && g_workers.has(this.worker)) {
            g_workers.get(this.worker).connections--;
        }
        g_clients.delete(this.id);
        g_stats.connectedMiners = g_clients.size;
    }

    onError(err) {}
}

// ============================================================================
// Job Broadcasting
// ============================================================================

function broadcastJob() {
    if (!g_currentJob) return;
    for (const [id, client] of g_clients) {
        client.sendJob(g_currentJob);
    }
}

// ============================================================================
// HTTP Stats API
// ============================================================================

function startHttpServer() {
    const httpServer = http.createServer((req, res) => {
        // CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET');

        if (req.url === '/api/stats' || req.url === '/stats') {
            // Calculate total hashrate
            let totalHashrate = 0;
            for (const [id, client] of g_clients) {
                totalHashrate += client.hashrate || 0;
            }

            const stats = {
                pool: {
                    name: 'FTC Mining Pool',
                    version: '1.2.0',
                    fee: CONFIG.POOL_FEE * 100 + '%',
                    uptime: formatUptime(Date.now() - g_stats.startTime),
                    uptimeMs: Date.now() - g_stats.startTime,
                },
                network: {
                    height: g_blockHeight,
                    difficulty: g_networkDifficulty,
                },
                miners: {
                    online: g_stats.connectedMiners,
                    hashrate: totalHashrate,
                    hashrateFormatted: formatHashrate(totalHashrate),
                },
                shares: {
                    accepted: g_stats.sharesAccepted,
                    rejected: g_stats.sharesRejected,
                    total: g_stats.sharesAccepted + g_stats.sharesRejected,
                    acceptRate: g_stats.sharesAccepted + g_stats.sharesRejected > 0
                        ? ((g_stats.sharesAccepted / (g_stats.sharesAccepted + g_stats.sharesRejected)) * 100).toFixed(1) + '%'
                        : '0%',
                },
                blocks: {
                    found: g_stats.blocksFound,
                    lastFoundAt: g_stats.lastBlockTime,
                    lastFoundHeight: g_stats.lastBlockHeight,
                },
                timestamp: Date.now(),
            };

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(stats, null, 2));

        } else if (req.url === '/api/miners' || req.url === '/miners') {
            // List connected miners
            const miners = [];
            for (const [id, client] of g_clients) {
                miners.push({
                    id: client.id,
                    worker: client.worker || 'connecting...',
                    ip: client.ip,
                    hashrate: client.hashrate,
                    hashrateFormatted: formatHashrate(client.hashrate || 0),
                    difficulty: client.difficulty,
                    sharesAccepted: client.sharesAccepted,
                    sharesRejected: client.sharesRejected,
                    connectedFor: formatUptime(Date.now() - client.connectTime),
                    lastShare: client.lastShareTime ? new Date(client.lastShareTime).toISOString() : null,
                    userAgent: client.userAgent || 'unknown',
                });
            }

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ miners, count: miners.length }, null, 2));

        } else if (req.url === '/api/workers' || req.url === '/workers') {
            // Worker statistics
            const workers = [];
            for (const [name, w] of g_workers) {
                if (w.connections > 0 || w.sharesAccepted > 0) {
                    workers.push({
                        name: w.name,
                        connections: w.connections,
                        sharesAccepted: w.sharesAccepted,
                        sharesRejected: w.sharesRejected,
                        blocksFound: w.blocksFound,
                        lastShare: w.lastShare ? new Date(w.lastShare).toISOString() : null,
                    });
                }
            }

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ workers }, null, 2));

        } else if (req.url === '/' || req.url === '/index.html') {
            // Simple HTML dashboard
            res.setHeader('Content-Type', 'text/html');
            res.end(generateDashboardHtml());

        } else {
            res.statusCode = 404;
            res.end('Not Found');
        }
    });

    httpServer.listen(CONFIG.HTTP_PORT, '0.0.0.0', () => {
        log('INFO', `HTTP Stats API on port ${CONFIG.HTTP_PORT}`);
        log('INFO', `Dashboard: http://localhost:${CONFIG.HTTP_PORT}/`);
    });
}

function generateDashboardHtml() {
    let totalHashrate = 0;
    for (const [id, client] of g_clients) {
        totalHashrate += client.hashrate || 0;
    }

    return `<!DOCTYPE html>
<html>
<head>
    <title>FTC Mining Pool</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="10">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0a0a0a; color: #fff; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00ff88; margin-bottom: 30px; font-size: 2em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .stat-card { background: #1a1a1a; border-radius: 12px; padding: 24px; border: 1px solid #333; }
        .stat-card h3 { color: #888; font-size: 0.85em; text-transform: uppercase; margin-bottom: 8px; }
        .stat-card .value { font-size: 2.2em; font-weight: bold; color: #00ff88; }
        .stat-card .sub { color: #666; font-size: 0.9em; margin-top: 5px; }
        .miners-table { margin-top: 30px; width: 100%; }
        .miners-table h2 { margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; background: #1a1a1a; border-radius: 12px; overflow: hidden; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #222; color: #888; font-weight: 500; text-transform: uppercase; font-size: 0.8em; }
        td { color: #ddd; }
        .online { color: #00ff88; }
        .footer { margin-top: 30px; color: #555; font-size: 0.85em; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>FTC Mining Pool</h1>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Miners Online</h3>
                <div class="value">${g_stats.connectedMiners}</div>
                <div class="sub">Active connections</div>
            </div>
            <div class="stat-card">
                <h3>Pool Hashrate</h3>
                <div class="value">${formatHashrate(totalHashrate)}</div>
                <div class="sub">Combined power</div>
            </div>
            <div class="stat-card">
                <h3>Shares</h3>
                <div class="value">${g_stats.sharesAccepted}</div>
                <div class="sub">${g_stats.sharesRejected} rejected</div>
            </div>
            <div class="stat-card">
                <h3>Blocks Found</h3>
                <div class="value">${g_stats.blocksFound}</div>
                <div class="sub">Network height: ${g_blockHeight}</div>
            </div>
            <div class="stat-card">
                <h3>Network Difficulty</h3>
                <div class="value">${g_networkDifficulty.toLocaleString()}</div>
                <div class="sub">Current target</div>
            </div>
            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="value">${formatUptime(Date.now() - g_stats.startTime)}</div>
                <div class="sub">Pool fee: ${CONFIG.POOL_FEE * 100}%</div>
            </div>
        </div>

        <div class="miners-table">
            <h2>Connected Miners</h2>
            <table>
                <thead>
                    <tr>
                        <th>Worker</th>
                        <th>Hashrate</th>
                        <th>Shares</th>
                        <th>Connected</th>
                    </tr>
                </thead>
                <tbody>
                    ${Array.from(g_clients.values()).map(c => `
                    <tr>
                        <td><span class="online">●</span> ${c.worker || 'connecting...'}</td>
                        <td>${formatHashrate(c.hashrate || 0)}</td>
                        <td>${c.sharesAccepted} / ${c.sharesRejected}</td>
                        <td>${formatUptime(Date.now() - c.connectTime)}</td>
                    </tr>
                    `).join('')}
                    ${g_clients.size === 0 ? '<tr><td colspan="4" style="text-align:center;color:#666">No miners connected</td></tr>' : ''}
                </tbody>
            </table>
        </div>

        <div class="footer">
            FTC Pool v1.2.0 | Stratum: pool.flowprotocol.net:3333 | Auto-refresh: 10s
        </div>
    </div>
</body>
</html>`;
}

// ============================================================================
// Main Server
// ============================================================================

async function startServer() {
    log('INFO', '═'.repeat(60));
    log('INFO', 'FTC Mining Pool Server v1.2.0');
    log('INFO', '═'.repeat(60));
    log('INFO', `Node: ${CONFIG.NODE_HOST}:${CONFIG.NODE_RPC_PORT}`);
    log('INFO', `Stratum port: ${CONFIG.POOL_PORT}`);
    log('INFO', `HTTP port: ${CONFIG.HTTP_PORT}`);
    log('INFO', `Pool difficulty: ${CONFIG.POOL_DIFFICULTY}`);
    log('INFO', '');

    // Verify keccak256 implementation
    const testData = Buffer.from('');  // Empty input
    const testHash = keccak256(testData);
    const expectedHash = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
    if (testHash.toString('hex') !== expectedHash) {
        log('ERROR', `Keccak256 test FAILED! Got ${testHash.toString('hex')}`);
        log('ERROR', `Expected ${expectedHash}`);
        process.exit(1);
    }
    log('INFO', 'Keccak256 implementation verified OK');

    // Test node connection
    log('INFO', `Connecting to FTC node...`);
    try {
        const info = await rpcCall('getinfo');
        log('INFO', `Node OK! Chain: ${info.chain}, Height: ${info.blocks}`);
        g_blockHeight = info.blocks;
    } catch (e) {
        log('ERROR', `Failed to connect: ${e.message}`);
        log('ERROR', 'Check NODE_HOST and RPC credentials');
        process.exit(1);
    }

    await updateJob();

    setInterval(async () => {
        await updateJob();
    }, CONFIG.BLOCK_POLL_INTERVAL);

    // Stratum server
    const stratumServer = net.createServer((socket) => {
        const clientId = g_nextClientId++;
        const client = new StratumClient(socket, clientId);
        g_clients.set(clientId, client);
        g_stats.connectedMiners = g_clients.size;
    });

    stratumServer.listen(CONFIG.POOL_PORT, '0.0.0.0', () => {
        log('INFO', `Stratum server on port ${CONFIG.POOL_PORT}`);
    });

    // HTTP Stats server
    startHttpServer();

    // Stats log
    setInterval(() => {
        let totalHashrate = 0;
        for (const [id, client] of g_clients) {
            totalHashrate += client.hashrate || 0;
        }
        log('STATS', `Miners: ${g_stats.connectedMiners} | ${formatHashrate(totalHashrate)} | Shares: ${g_stats.sharesAccepted}/${g_stats.sharesAccepted + g_stats.sharesRejected} | Blocks: ${g_stats.blocksFound}`);
    }, 60000);

    log('INFO', '');
    log('INFO', 'Pool is READY!');

    process.on('SIGINT', () => {
        log('INFO', 'Shutting down...');
        process.exit(0);
    });
}

startServer().catch(e => {
    log('ERROR', `Fatal: ${e.message}`);
    process.exit(1);
});
