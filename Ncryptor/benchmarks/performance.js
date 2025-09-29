// benchmarks/performance.js
const { Ncryptor } = require('../ncryptor.js');
const { performance, PerformanceObserver } = require('perf_hooks');

class NcryptorBenchmark {
    constructor() {
        this.results = [];
        this.setupPerformanceObserver();
    }

    setupPerformanceObserver() {
        const obs = new PerformanceObserver((items) => {
            items.getEntries().forEach((entry) => {
                console.log(`${entry.name}: ${entry.duration.toFixed(2)}ms`);
            });
        });
        obs.observe({ entryTypes: ['measure'] });
    }

    async runBenchmark() {
        const testCases = [
            { name: 'Low Security', params: { memoryCost: 14, timeCost: 1, parallelism: 1 }},
            { name: 'Medium Security', params: { memoryCost: 15, timeCost: 2, parallelism: 1 }},
            { name: 'High Security', params: { memoryCost: 16, timeCost: 3, parallelism: 2 }},
            { name: 'Paranoid Security', params: { memoryCost: 18, timeCost: 5, parallelism: 4 }}
        ];

        const password = 'BenchmarkPassword123!';

        for (const testCase of testCases) {
            console.log(`\n=== ${testCase.name} ===`);
            
            const hasher = new Ncryptor(testCase.params);
            
            // Measure hashing
            performance.mark('hash-start');
            const hashed = await hasher.hashPassword(password);
            performance.mark('hash-end');
            performance.measure('Hashing', 'hash-start', 'hash-end');

            // Measure verification
            performance.mark('verify-start');
            const isValid = await hasher.verifyPassword(password, hashed);
            performance.mark('verify-end');
            performance.measure('Verification', 'verify-start', 'verify-end');

            // Memory usage (approximate)
            const memoryUsage = (1 << testCase.params.memoryCost) * 1024;
            
            this.results.push({
                ...testCase,
                hashTime: performance.getEntriesByName('Hashing')[0].duration,
                verifyTime: performance.getEntriesByName('Verification')[0].duration,
                memoryUsage: Math.round(memoryUsage / (1024 * 1024)) + 'MB',
                isValid
            });

            // Cleanup
            performance.clearMarks();
            performance.clearMeasures();
        }

        this.printResults();
    }

    printResults() {
        console.log('\n=== BENCHMARK RESULTS ===');
        console.table(this.results.map(r => ({
            'Security Level': r.name,
            'Hash Time (ms)': r.hashTime.toFixed(2),
            'Verify Time (ms)': r.verifyTime.toFixed(2),
            'Memory Usage': r.memoryUsage,
            'Valid': r.isValid
        })));
    }
}

// Run benchmark if called directly
if (require.main === module) {
    const benchmark = new NcryptorBenchmark();
    benchmark.runBenchmark().catch(console.error);
}

module.exports = NcryptorBenchmark;