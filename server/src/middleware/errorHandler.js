/** Centralized error handling — no stack traces or internals leak to clients. */

function notFound(req, res) {
  res.status(404).json({ error: 'Not found' });
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  if (err.name === 'ValidationError') {
    // generic message — schema internals must not leak to clients
    return res.status(400).json({ error: 'Validation failed' });
  }
  if (err.statusCode && err.statusCode < 500) {
    return res.status(err.statusCode).json({ error: err.message, code: err.code || undefined });
  }
  console.error('[error]', err);
  res.status(500).json({ error: 'Internal server error' });
}

module.exports = { notFound, errorHandler };
