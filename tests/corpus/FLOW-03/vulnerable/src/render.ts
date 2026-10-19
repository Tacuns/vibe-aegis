export function show(req) {
  const name = req.query.name;
  document.getElementById('n').innerHTML = name;
}
