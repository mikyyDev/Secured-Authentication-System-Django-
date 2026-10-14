import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE_URL;

if (!baseURL) {
  throw new Error("VITE_API_BASE_URL is not configured.");
}

export const api = axios.create({
  baseURL,
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

let csrfToken: string | null = null;

const unsafeMethods = new Set(["post", "put", "patch", "delete"]);

export async function refreshCsrfToken(): Promise<void> {
  const response = await api.get<{ csrfToken: string }>("/auth/csrf/");

  csrfToken = response.data.csrfToken;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method ?? "get").toLowerCase();

  if (unsafeMethods.has(method)) {
    if (!csrfToken) {
      await refreshCsrfToken();
    }

    if (!csrfToken) {
      throw new Error("Unable to initialize CSRF protection.");
    }

    config.headers.set("X-CSRFToken", csrfToken);
  }

  return config;
});
