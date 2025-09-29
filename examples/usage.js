// examples/enterprise-usage.js
const { Ncryptor } = require('../ncryptor.js');

class EnterprisePasswordManager {
    constructor() {
        // Use OWASP-recommended parameters
        this.hasher = new Ncryptor(Ncryptor.getRecommendedParameters('high'));
        this.auditLogger = this.setupAuditLogger();
    }

    setupAuditLogger() {
        return {
            logSecurityEvent: (event, details) => {
                console.log(`[SECURITY] ${event}:`, {
                    ...details,
                    timestamp: new Date().toISOString(),
                    pid: process.pid
                });
            }
        };
    }

    async registerUser(email, password) {
        try {
            // Validate password strength
            this.validatePasswordStrength(password);
            
            // Hash password
            const startTime = Date.now();
            const hashedData = await this.hasher.hashPassword(password);
            const duration = Date.now() - startTime;
            
            // Store in database (simulated)
            const userRecord = {
                email,
                passwordHash: this.hasher.serializeHash(hashedData),
                createdAt: new Date(),
                version: hashedData.version
            };
            
            // Log security event
            this.auditLogger.logSecurityEvent('USER_REGISTERED', {
                email,
                hashDuration: duration,
                memoryCost: hashedData.params.memoryCost
            });
            
            return userRecord;
            
        } catch (error) {
            this.auditLogger.logSecurityEvent('REGISTRATION_FAILED', {
                email,
                error: error.message
            });
            throw error;
        }
    }

    async authenticateUser(email, password, storedHash) {
        try {
            const startTime = Date.now();
            const hashedData = this.hasher.deserializeHash(storedHash);
            const isValid = await this.hasher.verifyPassword(password, hashedData);
            const duration = Date.now() - startTime;
            
            this.auditLogger.logSecurityEvent('AUTHENTICATION_ATTEMPT', {
                email,
                success: isValid,
                duration,
                timestamp: new Date().toISOString()
            });
            
            return isValid;
            
        } catch (error) {
            this.auditLogger.logSecurityEvent('AUTHENTICATION_ERROR', {
                email,
                error: error.message
            });
            return false;
        }
    }

    validatePasswordStrength(password) {
        const requirements = [
            { test: p => p.length >= 12, message: 'Password must be at least 12 characters' },
            { test: p => /[A-Z]/.test(p), message: 'Password must contain uppercase letters' },
            { test: p => /[a-z]/.test(p), message: 'Password must contain lowercase letters' },
            { test: p => /[0-9]/.test(p), message: 'Password must contain numbers' },
            { test: p => /[^A-Za-z0-9]/.test(p), message: 'Password must contain special characters' }
        ];
        
        for (const req of requirements) {
            if (!req.test(password)) {
                throw new NcryptorError(req.message, 'WEAK_PASSWORD');
            }
        }
    }

    async upgradeHash(storedHash, newParams) {
        try {
            const oldData = this.hasher.deserializeHash(storedHash);
            
            // Create new hasher with upgraded parameters
            const upgradedHasher = new Ncryptor(newParams);
            
            // We can't get the original password, so we indicate need for rehash
            return {
                needsRehash: true,
                recommendedParams: newParams,
                currentVersion: oldData.version
            };
            
        } catch (error) {
            throw new NcryptorError('Hash upgrade failed', 'HASH_UPGRADE_FAILED');
        }
    }
}

// Usage example


module.exports = { EnterprisePasswordManager };