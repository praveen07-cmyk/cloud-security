import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";
import {
  getAuth,
  GoogleAuthProvider,
  GithubAuthProvider,
  signInWithPopup,
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";

// Replace these values with your Firebase web app config.
// Keep backend service account secrets out of this file.
const firebaseConfig = {
  apiKey: "YOUR_FIREBASE_WEB_API_KEY",
  authDomain: "YOUR_FIREBASE_PROJECT.firebaseapp.com",
  projectId: "YOUR_FIREBASE_PROJECT_ID",
  appId: "YOUR_FIREBASE_WEB_APP_ID",
};

const firebaseConfigured = Object.values(firebaseConfig).every((value) => {
  return value && !value.startsWith("YOUR_") && !value.includes("YOUR_FIREBASE");
});

let auth = null;
if (firebaseConfigured) {
  const app = initializeApp(firebaseConfig);
  auth = getAuth(app);
}

function getCsrfToken() {
  const input = document.querySelector('input[name="csrf_token"]');
  return input ? input.value : "";
}

async function sendTokenToBackend(result, providerName) {
  const idToken = await result.user.getIdToken();
  const response = await fetch("/firebase-login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": getCsrfToken(),
    },
    body: JSON.stringify({
      idToken,
      provider: providerName,
    }),
  });

  const payload = await response.json();
  if (!response.ok || !payload.success) {
    throw new Error(payload.message || "Firebase login failed.");
  }
  window.location.href = payload.redirect || "/dashboard";
}

function showFirebaseMessage(message) {
  const form = document.getElementById("loginForm");
  if (!form) return;
  const helper = document.createElement("div");
  helper.className = "login-alert";
  helper.textContent = message;
  form.insertBefore(helper, form.querySelector(".login-separator"));
  window.setTimeout(() => helper.remove(), 3500);
}

async function loginWithProvider(provider, providerName) {
  if (!firebaseConfigured || !auth) {
    showFirebaseMessage("Firebase OAuth is not configured yet.");
    return;
  }

  try {
    const result = await signInWithPopup(auth, provider);
    await sendTokenToBackend(result, providerName);
  } catch (error) {
    showFirebaseMessage(error.message || "Firebase sign-in failed.");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const googleButton = document.getElementById("googleLoginBtn");
  const githubButton = document.getElementById("githubLoginBtn");

  if (!firebaseConfigured) {
    [googleButton, githubButton].forEach((button) => {
      if (!button) return;
      button.setAttribute("title", "Firebase OAuth is not configured yet.");
      button.classList.add("oauth-ready");
    });
  }

  if (googleButton) {
    googleButton.addEventListener("click", () => {
      loginWithProvider(new GoogleAuthProvider(), "google");
    });
  }

  if (githubButton) {
    githubButton.addEventListener("click", () => {
      loginWithProvider(new GithubAuthProvider(), "github");
    });
  }
});
