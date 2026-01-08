/**
 * FTC Pool Server Configuration
 *
 * Modify these settings for your environment
 */

module.exports = {
    // Pool settings
    POOL_PORT: parseInt(process.env.POOL_PORT) || 3333,
    POOL_DIFFICULTY: parseInt(process.env.POOL_DIFFICULTY) || 1,
    POOL_FEE: parseFloat(process.env.POOL_FEE) || 0.01,

    // FTC Node RPC connection
    // For production: use internal IP of FTC node instance
    NODE_HOST: process.env.NODE_HOST || '127.0.0.1',
    NODE_RPC_PORT: parseInt(process.env.NODE_RPC_PORT) || 17318,
    NODE_RPC_USER: process.env.NODE_RPC_USER || 'ftcuser',
    NODE_RPC_PASS: process.env.NODE_RPC_PASS || 'ftcpass',

    // Mining parameters
    BLOCK_POLL_INTERVAL: 1000,
    SHARE_DIFFICULTY: 65536,
    EXTRANONCE2_SIZE: 4,

    // Vardiff settings
    VARDIFF_MIN: 1,
    VARDIFF_MAX: 65536,
    VARDIFF_TARGET_TIME: 15,
    VARDIFF_RETARGET: 60,
    VARDIFF_VARIANCE: 0.3,
};
