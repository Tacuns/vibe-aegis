export const Orders = ({ orders }) => (
  <ul>{orders.map(o => <li key={o.id}>{o.name}</li>)}</ul>
);
