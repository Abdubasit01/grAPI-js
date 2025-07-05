const assert = require('assert');
const { isPotentialApi } = require('../grapi/core.js');

describe('isPotentialApi', () => {
    it('should return true for API-like URLs', () => {
        assert.strictEqual(isPotentialApi('/api/users'), true);
        assert.strictEqual(isPotentialApi('https://example.com/graphql'), true);
        assert.strictEqual(isPotentialApi('/v1/data'), true);
    });

    it('should return false for non-API-like URLs', () => {
        assert.strictEqual(isPotentialApi('https://example.com/home'), false);
    });
});
