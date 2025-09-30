// Ncrypt.js - Novel hashing algorithm with temporal entropy
const crypto = require('crypto');

class NcryptError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'NcryptError';
        this.code = code;
    }
}

class Ncrypt {
    constructor(options = {}) {
        this.version = 1;
        this.waveDepth = options.waveDepth || 7;
        this.dimensionCount = options.dimensionCount || 5;
        this.fractalIterations = options.fractalIterations || 4;
        this.outputSize = 64;
        
        // Mathematical constants for wave transformations
        this.PHI = 1.618033988749895;
        this.E = 2.718281828459045;
        this.PI = 3.141592653589793;
    }

    /**
     * Hash a password using microsecond epoch as salt
     * @param {string} password - The password to hash
     * @returns {string} Base64 encoded hash with embedded timestamp
     */
    hash(password) {
        if (typeof password !== 'string' || password.length === 0) {
            throw new NcryptError('Password must be a non-empty string', 'INVALID_INPUT');
        }

        if (password.length > 1024) {
            throw new NcryptError('Password too long (max 1024 chars)', 'PASSWORD_TOO_LONG');
        }

        const microTime = this.getMicrosecondTimestamp();
        const salt = this.generateTemporalSalt(microTime);
        const hash = this.quantumWaveHash(password, salt, microTime);
        
        const encoded = Buffer.concat([
            Buffer.from([this.version]),
            Buffer.from(microTime.toString(16).padStart(16, '0'), 'hex'),
            hash
        ]);
        
        return encoded.toString('base64');
    }

    /**
     * Verify a password against a hash
     * @param {string} password - The password to verify
     * @param {string} hashedPassword - The base64 encoded hash
     * @returns {boolean} True if password matches
     */
    compare(password, hashedPassword) {
        try {
            if (typeof password !== 'string' || typeof hashedPassword !== 'string') {
                return false;
            }

            const decoded = Buffer.from(hashedPassword, 'base64');
            
            if (decoded.length !== 73) {
                return false;
            }

            const version = decoded[0];
            if (version !== this.version) {
                throw new NcryptError('Unsupported hash version', 'VERSION_MISMATCH');
            }

            const microTimeHex = decoded.subarray(1, 9).toString('hex');
            const microTime = BigInt('0x' + microTimeHex);
            const originalHash = decoded.subarray(9);
            
            const salt = this.generateTemporalSalt(microTime);
            const computedHash = this.quantumWaveHash(password, salt, microTime);
            
            return this.constantTimeCompare(originalHash, computedHash);
        } catch {
            return false;
        }
    }

    // === CORE ALGORITHM ===

    quantumWaveHash(password, salt, microTime) {
        const passwordBuf = Buffer.from(password, 'utf8');
        
        let state = this.initializeQuantumState(passwordBuf, salt);
        
        for (let wave = 0; wave < this.waveDepth; wave++) {
            state = this.waveTransform(state, passwordBuf, salt, wave, microTime);
        }
        
        state = this.fractalMix(state, microTime);
        const collapsed = this.dimensionalCollapse(state, passwordBuf, salt);
        
        return this.finalCompression(collapsed);
    }

    initializeQuantumState(password, salt) {
        const stateSize = 256;
        const state = Buffer.alloc(stateSize);
        
        const combined = Buffer.concat([password, salt]);
        let seed = crypto.createHash('blake2b512').update(combined).digest();
        
        for (let i = 0; i < stateSize; i += seed.length) {
            const chunk = Math.min(seed.length, stateSize - i);
            seed.copy(state, i, 0, chunk);
            seed = crypto.createHash('blake2b512').update(seed).update(Buffer.from([i])).digest();
        }
        
        return state;
    }

    waveTransform(state, password, salt, waveIndex, microTime) {
        const transformed = Buffer.alloc(state.length);
        
        for (let i = 0; i < state.length; i++) {
            const phase = (i * this.PHI + waveIndex * this.E) % (2 * this.PI);
            const amplitude = Math.sin(phase) * Math.cos(phase * this.PHI);
            const waveValue = Math.floor((amplitude + 1) * 127.5);
            const timeEntropy = Number((microTime >> BigInt(i % 64)) & BigInt(0xFF));
            
            transformed[i] = (
                state[i] ^ 
                waveValue ^ 
                timeEntropy ^
                salt[i % salt.length]
            ) & 0xFF;
        }
        
        return this.sboxTransform(transformed, waveIndex);
    }

    sboxTransform(data, round) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            let x = data[i] / 255.0;
            const r = 3.99;
            
            for (let j = 0; j < round + 3; j++) {
                x = r * x * (1 - x);
            }
            
            result[i] = Math.floor(x * 255) & 0xFF;
        }
        
        return result;
    }

    fractalMix(state, microTime) {
        let mixed = Buffer.from(state);
        
        for (let iter = 0; iter < this.fractalIterations; iter++) {
            const segmentSize = Math.floor(mixed.length / (iter + 2));
            
            for (let seg = 0; seg < mixed.length; seg += segmentSize) {
                const endSeg = Math.min(seg + segmentSize, mixed.length);
                const segment = mixed.subarray(seg, endSeg);
                const transformed = this.mandelbrotHash(segment, iter, microTime);
                transformed.copy(mixed, seg);
            }
            
            mixed = this.rotateBuffer(mixed, iter * 7);
        }
        
        return mixed;
    }

    mandelbrotHash(data, depth, microTime) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            let real = (data[i] / 255.0) * 2 - 1;
            let imag = (data[(i + 1) % data.length] / 255.0) * 2 - 1;
            
            let zReal = 0;
            let zImag = 0;
            let iterations = 0;
            
            while (iterations < 20 + depth && (zReal * zReal + zImag * zImag) < 4) {
                const tempReal = zReal * zReal - zImag * zImag + real;
                zImag = 2 * zReal * zImag + imag;
                zReal = tempReal;
                iterations++;
            }
            
            const timeComponent = Number((microTime >> BigInt(i % 64)) & BigInt(0xFF));
            result[i] = (iterations * 13 + timeComponent) & 0xFF;
        }
        
        return result;
    }

    dimensionalCollapse(state, password, salt) {
        const dimensions = [];
        
        for (let dim = 0; dim < this.dimensionCount; dim++) {
            const projection = this.projectDimension(state, password, salt, dim);
            dimensions.push(projection);
        }
        
        return this.collapseDimensions(dimensions);
    }

    projectDimension(state, password, salt, dimension) {
        const dimHash = crypto.createHash('sha3-512');
        dimHash.update(state);
        dimHash.update(password);
        dimHash.update(salt);
        dimHash.update(Buffer.from([dimension]));
        
        let projection = dimHash.digest();
        
        for (let i = 0; i < projection.length; i++) {
            projection[i] = (projection[i] + dimension * 17 + i * 3) & 0xFF;
        }
        
        return projection;
    }

    collapseDimensions(dimensions) {
        const collapsed = Buffer.alloc(64);
        
        for (let i = 0; i < collapsed.length; i++) {
            let value = 0;
            
            for (let dim = 0; dim < dimensions.length; dim++) {
                const dimValue = dimensions[dim][i % dimensions[dim].length];
                value ^= dimValue;
                value = (value + dimValue * (dim + 1)) & 0xFF;
            }
            
            collapsed[i] = value;
        }
        
        return collapsed;
    }

    finalCompression(data) {
        const sha3 = crypto.createHash('sha3-512').update(data).digest();
        const blake2 = crypto.createHash('blake2b512').update(data).digest();
        
        const result = Buffer.alloc(64);
        
        for (let i = 0; i < 64; i++) {
            result[i] = sha3[i] ^ blake2[i] ^ data[i % data.length];
        }
        
        return result;
    }

    // === UTILITY FUNCTIONS ===

    getMicrosecondTimestamp() {
        const [seconds, nanoseconds] = process.hrtime();
        return BigInt(seconds) * BigInt(1000000) + BigInt(Math.floor(nanoseconds / 1000));
    }

    generateTemporalSalt(microTime) {
        const timeBuf = Buffer.alloc(8);
        timeBuf.writeBigUInt64BE(microTime);
        
        const salt = Buffer.alloc(32);
        let key = timeBuf;
        
        for (let i = 0; i < 32; i += key.length) {
            key = crypto.createHash('sha256').update(key).digest();
            const chunk = Math.min(key.length, 32 - i);
            key.copy(salt, i, 0, chunk);
        }
        
        return salt;
    }

    rotateBuffer(buffer, positions) {
        const rotated = Buffer.alloc(buffer.length);
        const shift = positions % buffer.length;
        
        buffer.copy(rotated, 0, shift);
        buffer.copy(rotated, buffer.length - shift, 0, shift);
        
        return rotated;
    }

    constantTimeCompare(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result === 0;
    }
}

// === USAGE EXAMPLES ===



module.exports = { Ncrypt, NcryptError };