'use strict';

/**
 * Vercel Serverless Function entrypoint for DEEPORA backend
 */
const handle = require('../src/server');

module.exports = async (req, res) => {
  try {
    await handle(req, res);
  } catch (error) {
    console.error('[Vercel Serverless Error]:', error);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Internal Server Error' }));
    } else {
      res.end();
    }
  }
};
