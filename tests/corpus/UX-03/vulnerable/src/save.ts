export async function save(data) {
  try {
    await api.save(data);
  } catch (e) {
    console.error(e);
  }
}
