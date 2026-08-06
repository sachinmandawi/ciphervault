import { onRequest as __auth_callback_js_onRequest } from "D:\\ciphervault\\functions\\auth\\callback.js"
import { onRequest as __auth_login_js_onRequest } from "D:\\ciphervault\\functions\\auth\\login.js"

export const routes = [
    {
      routePath: "/auth/callback",
      mountPath: "/auth",
      method: "",
      middlewares: [],
      modules: [__auth_callback_js_onRequest],
    },
  {
      routePath: "/auth/login",
      mountPath: "/auth",
      method: "",
      middlewares: [],
      modules: [__auth_login_js_onRequest],
    },
  ]