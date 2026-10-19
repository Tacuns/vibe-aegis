export const Orders = ({ orders }) => (
  orders.length === 0 ? <p>No orders yet.</p> : <ul>{orders.map(o => <li key={o.id}>{o.name}</li>)}</ul>
);
