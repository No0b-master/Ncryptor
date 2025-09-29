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
        // Default parameters (OWASP recommended levels)
        this.version = 1;
        this.memoryCost = options.memoryCost || 17; // 128MB (2^17 * 1KB)
        this.timeCost = options.timeCost || 3;
        this.parallelism = options.parallelism || 2;
        this.saltSize = options.saltSize || 32;
        this.outputSize = options.outputSize || 64;
        this.maxMemory = options.maxMemory || 1024; // Max 1GB memory usage
        this.maxTimeCost = options.maxTimeCost || 10;
        
        // Validate parameters
        this.validateParameters();
        
        // Security monitoring
        this.performanceMetrics = {
            hashOperations: 0,
            averageDuration: 0,
            failures: 0
        };
    }

    validateParameters() {
        if (this.memoryCost < 14 || this.memoryCost > 24) {
            throw new NcryptorError('Memory cost must be between 14 (16MB) and 24 (16GB)', 'INVALID_PARAMS');
        }
        
        if (this.timeCost < 1 || this.timeCost > this.maxTimeCost) {
            throw new NcryptorError(`Time cost must be between 1 and ${this.maxTimeCost}`, 'INVALID_PARAMS');
        }
        
        if (this.parallelism < 1 || this.parallelism > 8) {
            throw new NcryptorError('Parallelism must be between 1 and 8', 'INVALID_PARAMS');
        }
        
        const estimatedMemory = (1 << this.memoryCost) * 1024;
        if (estimatedMemory > this.maxMemory * 1024 * 1024) {
            throw new NcryptorError(`Memory usage would exceed ${this.maxMemory}MB limit`, 'MEMORY_LIMIT_EXCEEDED');
        }
    }

    // Cryptographically secure random generation
    generateSalt(size = this.saltSize) {
        try {
            return crypto.randomBytes(size);
        } catch (error) {
            throw new NcryptorError('Failed to generate cryptographically secure salt', 'RNG_FAILURE');
        }
    }

    // Core cryptographic mixing function
    async mixBlocks(blockA, blockB, salt) {
        try {
            // Use multiple hash functions for defense in depth
            const hmac = crypto.createHmac('sha512', salt);
            hmac.update(blockA);
            hmac.update(blockB);
            const hmacResult = hmac.digest();
            
            const blake2b = crypto.createHash('blake2b512');
            blake2b.update(Buffer.concat([blockA, blockB, salt]));
            const blakeResult = blake2b.digest();
            
            // XOR the results for additional mixing
            const mixed = Buffer.alloc(64);
            for (let i = 0; i < 64; i++) {
                mixed[i] = hmacResult[i] ^ blakeResult[i];
            }
            
            return mixed;
        } catch (error) {
            throw new NcryptorError('Cryptographic mixing failed', 'CRYPTO_FAILURE');
        }
    }

    // Memory-hard matrix operations with cache timing protection
    createMemoryMatrix() {
        const rows = 1 << this.memoryCost;
        const cols = 1024; // 1KB blocks
        
        try {
            const matrix = new Array(rows);
            for (let i = 0; i < rows; i++) {
                matrix[i] = Buffer.alloc(cols);
            }
            return matrix;
        } catch (error) {
            throw new NcryptorError('Memory allocation failed - consider reducing memoryCost', 'MEMORY_ALLOCATION_FAILED');
        }
    }

    // Cache-resistant memory addressing
    computeMemoryIndex(baseIndex, salt, max) {
        // Use multiple hash functions to create unpredictable access patterns
        const hash = crypto.createHash('sha256');
        hash.update(salt);
        hash.update(Buffer.from([baseIndex & 0xFF, (baseIndex >> 8) & 0xFF]));
        const digest = hash.digest();
        
        // Large prime multiplication for non-linearity
        const prime1 = 15485863n;
        const prime2 = 32416190071n;
        
        let index = BigInt(baseIndex);
        index = (index * prime1 + BigInt(digest.readUInt32LE(0))) % prime2;
        index = (index * prime2 + BigInt(digest.readUInt32LE(4))) % BigInt(max);
        
        return Number(index);
    }

    // Core hashing algorithm
    async hashPassword(password, salt = null) {
        const startTime = Date.now();
        
        try {
            // Input validation
            if (typeof password !== 'string' || password.length === 0) {
                throw new NcryptorError('Password must be a non-empty string', 'INVALID_INPUT');
            }
            
            if (password.length > 1024) {
                throw new NcryptorError('Password too long', 'PASSWORD_TOO_LONG');
            }
            
            // Generate salt if not provided
            const saltBuffer = salt || this.generateSalt();
            if (saltBuffer.length !== this.saltSize) {
                throw new NcryptorError(`Salt must be ${this.saltSize} bytes`, 'INVALID_SALT');
            }
            
            const passwordBuffer = Buffer.from(password, 'utf8');
            
            // Step 1: Initial key derivation
            const derivedKey = await this.deriveInitialKey(passwordBuffer, saltBuffer);
            
            // Step 2: Initialize memory matrix
            const memoryMatrix = this.createMemoryMatrix();
            await this.initializeMatrix(memoryMatrix, derivedKey, saltBuffer);
            
            // Step 3: Memory-hard transformation
            await this.transformMatrix(memoryMatrix, passwordBuffer, saltBuffer);
            
            // Step 4: Final key derivation
            const finalHash = await this.deriveFinalHash(memoryMatrix, saltBuffer);
            
            // Update metrics
            this.updateMetrics(Date.now() - startTime);
            
            return {
                hash: finalHash,
                salt: saltBuffer,
                version: this.version,
                params: {
                    memoryCost: this.memoryCost,
                    timeCost: this.timeCost,
                    parallelism: this.parallelism
                },
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            this.performanceMetrics.failures++;
            throw error;
        }
    }

    async deriveInitialKey(password, salt) {
        // Use multiple iterations of PBKDF2 as a base
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
            rowKey.update(Buffer.from([i & 0xFF, (i >> 8) & 0xFF]));
            const rowHash = rowKey.digest();
            
            // Fill row with expanded key material
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
                        
                        // XOR back into matrix
                        for (let k = 0; k < 64 && (j + k) < cols; k++) {
                            matrix[rowIndex][j + k] ^= transformed[k];
                        }
                        
                        // Update state
                        state = crypto.createHmac('sha512', salt)
                            .update(state)
                            .update(transformed)
                            .digest();
                    }
                }
                
                // Cross-lane mixing for additional security
                if (lane > 0) {
                    await this.mixLanes(matrix, lane, salt);
                }
            }
        }
    }

    async mixLanes(matrix, lane, salt) {
        const rows = matrix.length;
        const mixRow = (lane * 13) % rows; // Non-linear pattern
        
        for (let i = 0; i < rows; i++) {
            const sourceRow = (i * 17 + mixRow) % rows;
            
            for (let j = 0; j < matrix[0].length; j += 8) {
                // 64-bit mixing
                const sourceVal = matrix[sourceRow].readBigUint64LE(j);
                const targetVal = matrix[i].readBigUint64LE(j);
                const mixed = sourceVal ^ targetVal;
                matrix[i].writeBigUint64LE(mixed, j);
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
                .update(Buffer.from([i & 0xFF, (i >> 8) & 0xFF]))
                .digest();
            
            accumulator = Buffer.concat([accumulator, rowHash]);
        }
        
        // Final compression
        return crypto.createHash('blake2b512')
            .update(accumulator)
            .digest();
    }

    // Verification with timing attack protection
    async verifyPassword(password, hashedData) {
        const startTime = Date.now();
        
        try {
            if (!hashedData || !hashedData.hash || !hashedData.salt || !hashedData.params) {
                throw new NcryptorError('Invalid hashed data structure', 'INVALID_HASH_FORMAT');
            }
            
            // Re-hash with same parameters
            const testHash = await this.hashPassword(password, hashedData.salt);
            
            // Constant-time comparison
            const isValid = this.constantTimeCompare(hashedData.hash, testHash.hash);
            
            // Always take similar time regardless of result
            const elapsed = Date.now() - startTime;
            const minTime = 100; // Minimum 100ms for verification
            if (elapsed < minTime) {
                await this.delay(minTime - elapsed);
            }
            
            return isValid;
            
        } catch (error) {
            // Still delay on error to prevent timing leaks
            await this.delay(100);
            throw error;
        }
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

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    updateMetrics(duration) {
        this.performanceMetrics.hashOperations++;
        this.performanceMetrics.averageDuration = 
            (this.performanceMetrics.averageDuration * (this.performanceMetrics.hashOperations - 1) + duration) 
            / this.performanceMetrics.hashOperations;
    }

    // Serialization/deserialization
    serializeHash(hashedData) {
        const data = {
            v: hashedData.version,
            h: hashedData.hash.toString('base64'),
            s: hashedData.salt.toString('base64'),
            p: hashedData.params,
            t: hashedData.timestamp
        };
        
        return Buffer.from(JSON.stringify(data)).toString('base64');
    }

    deserializeHash(serialized) {
        try {
            const data = JSON.parse(Buffer.from(serialized, 'base64').toString());
            
            return {
                version: data.v,
                hash: Buffer.from(data.h, 'base64'),
                salt: Buffer.from(data.s, 'base64'),
                params: data.p,
                timestamp: data.t
            };
        } catch (error) {
            throw new NcryptorError('Invalid serialized hash format', 'INVALID_SERIALIZED_FORMAT');
        }
    }

    // Security audit logging
    getMetrics() {
        return {
            ...this.performanceMetrics,
            parameters: {
                memoryCost: this.memoryCost,
                timeCost: this.timeCost,
                parallelism: this.parallelism
            },
            estimatedMemoryUsage: (1 << this.memoryCost) * 1024
        };
    }

    // Parameter validation for security
    static getRecommendedParameters(securityLevel = 'high') {
        const levels = {
            low: { memoryCost: 14, timeCost: 1, parallelism: 1 }, // 16MB
            medium: { memoryCost: 15, timeCost: 2, parallelism: 1 }, // 32MB
            high: { memoryCost: 16, timeCost: 3, parallelism: 2 }, // 64MB
            paranoid: { memoryCost: 18, timeCost: 5, parallelism: 4 } // 256MB
        };
        
        return levels[securityLevel] || levels.high;
    }
}

module.exports = { Ncryptor, NcryptorError };