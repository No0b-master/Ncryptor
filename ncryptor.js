// Ncryptor.js
const crypto = require('crypto');

class NcryptorError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'NcryptorError';
        this.code = code;
    }
}

class Ncryptor {
    constructor(options = {}) {
        this.version = 1;
        this.memoryCost = options.memoryCost || 17; // 128MB
        this.timeCost = options.timeCost || 3;
        this.parallelism = options.parallelism || 2;
        this.saltSize = options.saltSize || 32;
        this.outputSize = options.outputSize || 64;
        this.maxMemory = options.maxMemory || 1024; // MB
        this.maxTimeCost = options.maxTimeCost || 10;

        this.validateParameters();
    }

    validateParameters() {
        if (this.memoryCost < 14 || this.memoryCost > 24) {
            throw new NcryptorError('Memory cost must be between 14 and 24', 'INVALID_PARAMS');
        }
        if (this.timeCost < 1 || this.timeCost > this.maxTimeCost) {
            throw new NcryptorError(`Time cost must be between 1 and ${this.maxTimeCost}`, 'INVALID_PARAMS');
        }
        if (this.parallelism < 1 || this.parallelism > 8) {
            throw new NcryptorError('Parallelism must be between 1 and 8', 'INVALID_PARAMS');
        }
        const estimatedMemory = (1 << this.memoryCost) * 1024;
        if (estimatedMemory > this.maxMemory * 1024 * 1024) {
            throw new NcryptorError(`Memory usage would exceed ${this.maxMemory}MB`, 'MEMORY_LIMIT_EXCEEDED');
        }
    }

    generateSalt(size = this.saltSize) {
        try {
            return crypto.randomBytes(size);
        } catch {
            throw new NcryptorError('Failed to generate cryptographically secure salt', 'RNG_FAILURE');
        }
    }

    async mixBlocks(blockA, blockB, salt) {
        const hmac = crypto.createHmac('sha512', salt);
        hmac.update(blockA);
        hmac.update(blockB);
        const hmacResult = hmac.digest();

        const blake2b = crypto.createHash('blake2b512');
        blake2b.update(Buffer.concat([blockA, blockB, salt]));
        const blakeResult = blake2b.digest();

        const mixed = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            mixed[i] = hmacResult[i] ^ blakeResult[i];
        }
        return mixed;
    }

    createMemoryMatrix() {
        const rows = 1 << this.memoryCost;
        const cols = 1024; // 1KB blocks
        const matrix = new Array(rows);
        for (let i = 0; i < rows; i++) {
            matrix[i] = Buffer.alloc(cols);
        }
        return matrix;
    }

    computeMemoryIndex(baseIndex, salt, max) {
        const hash = crypto.createHash('sha256');
        hash.update(salt);
        hash.update(Buffer.from([baseIndex & 0xff, (baseIndex >> 8) & 0xff]));
        const digest = hash.digest();

        const prime1 = 15485863n;
        const prime2 = 32416190071n;

        let index = BigInt(baseIndex);
        index = (index * prime1 + BigInt(digest.readUInt32LE(0))) % prime2;
        index = (index * prime2 + BigInt(digest.readUInt32LE(4))) % BigInt(max);

        return Number(index);
    }

    async deriveInitialKey(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(password, salt, 1000, 64, 'sha512', (err, derivedKey) => {
                if (err) reject(new NcryptorError('Key derivation failed', 'KEY_DERIVATION_FAILED'));
                else resolve(derivedKey);
            });
        });
    }

    async initializeMatrix(matrix, key, salt) {
        const rows = matrix.length;
        const cols = matrix[0].length;

        for (let i = 0; i < rows; i++) {
            const rowKey = crypto.createHmac('sha512', salt);
            rowKey.update(key);
            rowKey.update(Buffer.from([i & 0xff, (i >> 8) & 0xff]));
            const rowHash = rowKey.digest();

            for (let j = 0; j < cols; j += 64) {
                const chunkSize = Math.min(64, cols - j);
                rowHash.copy(matrix[i], j, 0, chunkSize);
            }
        }
    }

    async transformMatrix(matrix, password, salt) {
        const rows = matrix.length;
        const cols = matrix[0].length;

        for (let lane = 0; lane < this.parallelism; lane++) {
            let state = crypto.createHmac('sha512', salt)
                .update(password)
                .update(Buffer.from([lane]))
                .digest();

            for (let iter = 0; iter < this.timeCost; iter++) {
                for (let i = 0; i < rows; i++) {
                    const rowIndex = this.computeMemoryIndex(i, state, rows);

                    for (let j = 0; j < cols; j += 64) {
                        const chunk = matrix[rowIndex].slice(j, j + 64);
                        const transformed = await this.mixBlocks(chunk, state, salt);

                        for (let k = 0; k < 64 && j + k < cols; k++) {
                            matrix[rowIndex][j + k] ^= transformed[k];
                        }

                        state = crypto.createHmac('sha512', salt)
                            .update(state)
                            .update(transformed)
                            .digest();
                    }
                }
            }
        }
    }

    async deriveFinalHash(matrix, salt) {
        let accumulator = Buffer.alloc(0);
        const sampleCount = Math.min(16, matrix.length);
        const step = Math.max(1, Math.floor(matrix.length / sampleCount));

        for (let i = 0; i < matrix.length; i += step) {
            const rowHash = crypto.createHash('blake2b512')
                .update(matrix[i])
                .update(salt)
                .update(Buffer.from([i & 0xff, (i >> 8) & 0xff]))
                .digest();
            accumulator = Buffer.concat([accumulator, rowHash]);
        }

        return crypto.createHash('blake2b512').update(accumulator).digest();
    }

    // === Simplified Public APIs ===

    async hash(password, salt = null) {
        if (typeof password !== 'string' || password.length === 0) {
            throw new NcryptorError('Password must be a non-empty string', 'INVALID_INPUT');
        }

        if (password.length > 1024) {
            throw new NcryptorError('Password too long', 'PASSWORD_TOO_LONG');
        }

        const saltBuffer = salt || this.generateSalt();
        if (saltBuffer.length !== this.saltSize) {
            throw new NcryptorError(`Salt must be ${this.saltSize} bytes`, 'INVALID_SALT');
        }

        const passwordBuffer = Buffer.from(password, 'utf8');
        const derivedKey = await this.deriveInitialKey(passwordBuffer, saltBuffer);
        const memoryMatrix = this.createMemoryMatrix();
        await this.initializeMatrix(memoryMatrix, derivedKey, saltBuffer);
        await this.transformMatrix(memoryMatrix, passwordBuffer, saltBuffer);
        const finalHash = await this.deriveFinalHash(memoryMatrix, saltBuffer);

        return {
            hash: finalHash.toString('base64'),
            salt: saltBuffer.toString('base64')
        };
    }

    async verifyHash(password, hashedData) {
        try {
            if (!hashedData || !hashedData.hash || !hashedData.salt) {
                throw new NcryptorError('Invalid hashed data structure', 'INVALID_HASH_FORMAT');
            }

            const saltBuffer = Buffer.from(hashedData.salt, 'base64');
            const computed = await this.hash(password, saltBuffer);

            return this.constantTimeCompare(
                Buffer.from(hashedData.hash, 'base64'),
                Buffer.from(computed.hash, 'base64')
            );
        } catch {
            return false;
        }
    }

    checkPasswordStrength(password) {
        if (typeof password !== 'string') return { valid: false, reason: 'Invalid input' };

        const minLength = 8;
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);

        const strong = password.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial;

        return {
            valid: strong,
            reason: strong ? 'Strong password' : 'Weak password: must include upper, lower, number, special char and be at least 8 chars'
        };
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

module.exports = { Ncryptor, NcryptorError };
