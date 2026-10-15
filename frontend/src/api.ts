export async function request<T>(
  path: string,
  token?: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const response = await fetch(`/api${path}`, { ...init, headers });
  if (!response.ok) {
    const result = (await response.json().catch(() => null)) as
      | { detail?: string }
      | null;
    throw new Error(result?.detail || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
