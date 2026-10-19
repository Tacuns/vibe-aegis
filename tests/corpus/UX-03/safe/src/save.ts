export async function save(data) {
  try {
    await api.save(data);
  } catch (e) {
    toast.error('Could not save. Please try again.');
    throw e;
  }
}
