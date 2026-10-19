export function onError(err, req, res, next) {
  res.status(500).json({ error: err.stack });
}
