// test/Ncryptor.test.js
const { Ncryptor, NcryptorError } = require('../ncryptor.js');
const { performance } = require('perf_hooks');

describe('Ncryptor Password Hashing', () => {
    let Ncryptor;

    beforeEach(() => {
        Ncryptor = new Ncryptor({ memoryCost: 14 }); // Smaller for faster tests
    });

    test('should hash and verify password correctly', async () => {
        const password = 'SecurePassword123!';
        const hashed = await Ncryptor.hashPassword(password);
        
        expect(hashed.hash).toBeInstanceOf(Buffer);
        expect(hashed.salt).toBeInstanceOf(Buffer);
        expect(hashed.hash.length).toBe(64);
        expect(hashed.salt.length).toBe(32);
        
        const isValid = await Ncryptor.verifyPassword(password, hashed);
        expect(isValid).toBe(true);
    });

    test('should reject incorrect passwords', async () => {
        const password = 'SecurePassword123!';
        const hashed = await Ncryptor.hashPassword(password);
        
        const isValid = await Ncryptor.verifyPassword('WrongPassword', hashed);
        expect(isValid).toBe(false);
    });

    test('should handle special characters in passwords', async () => {
        const passwords = [
            'pâsswörd-with-ünïcodé',
            '密码@123',
            '🔒🛡️💻⭐',
            'very-long-password-'.repeat(10)
        ];
        
        for (const password of passwords) {
            const hashed = await Ncryptor.hashPassword(password);
            const isValid = await Ncryptor.verifyPassword(password, hashed);
            expect(isValid).toBe(true);
        }
    });

    test('should reject empty passwords', async () => {
        await expect(Ncryptor.hashPassword('')).rejects.toThrow(NcryptorError);
    });

    test('should enforce memory limits', async () => {
        const highMemory = new Ncryptor({ memoryCost: 25 });
        await expect(highMemory.hashPassword('test')).rejects.toThrow(NcryptorError);
    });

    test('should provide constant-time verification', async () => {
        const password = 'test';
        const hashed = await Ncryptor.hashPassword(password);
        
        const times = [];
        for (let i = 0; i < 10; i++) {
            const start = performance.now();
            await Ncryptor.verifyPassword(password, hashed);
            times.push(performance.now() - start);
        }
        
        // Variance should be small (within 20%)
        const avg = times.reduce((a, b) => a + b) / times.length;
        const variance = times.map(t => Math.abs(t - avg) / avg);
        expect(Math.max(...variance)).toBeLessThan(0.2);
    });

    test('should serialize and deserialize correctly', async () => {
        const password = 'test';
        const hashed = await Ncryptor.hashPassword(password);
        const serialized = Ncryptor.serializeHash(hashed);
        const deserialized = Ncryptor.deserializeHash(serialized);
        
        expect(deserialized.hash.equals(hashed.hash)).toBe(true);
        expect(deserialized.salt.equals(hashed.salt)).toBe(true);
    });

    test('should track performance metrics', async () => {
        await Ncryptor.hashPassword('test');
        const metrics = Ncryptor.getMetrics();
        
        expect(metrics.hashOperations).toBe(1);
        expect(metrics.averageDuration).toBeGreaterThan(0);
    });
});