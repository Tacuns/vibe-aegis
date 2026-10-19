export function onError(err, req, res, next) {
  logger.error({ requestId: req.id }, 'unhandled error');
  res.status(500).json({ error: 'Internal error', requestId: req.id });
}
