// Knowsie password reset (2026-10-07).
//
// The app's "Forgot password?" asks Supabase (our sign-in provider) to
// email a link to this page. The link can arrive in three shapes, and this
// page accepts all of them:
//
//  1. #token_hash=...&type=recovery -- our own email template (see the
//     setup notes). Nothing is used up until the person presses "Change
//     password", so a mail scanner that opens links first can't spend it,
//     and it works whichever sign-in flow the app uses.
//  2. #access_token=...&refresh_token=...&type=recovery -- Supabase's
//     default template with the app's "implicit" flow (the app doesn't set
//     flowType, and supabase-js defaults to implicit). Supabase has already
//     checked the link and hands over a short sign-in session.
//  3. ?code=... -- the "PKCE" flow. It only works in the browser that asked
//     for the link, and only the app asks, so in practice it fails; it's
//     here in case the app ever switches flows (then use template 1).
//
// Links that failed come back as error=... in the address. Nothing is
// stored in the browser: the session lives in memory only, and the page
// signs it out once the password is changed.
(function () {
  'use strict';

  // Public by design: the project address and its "anon" key are the same
  // ones built into the app. Row-level security decides what they can do.
  var SUPABASE_URL = 'https://jxmurbnwauluwgopzulk.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imp4bXVyYm53YXVsdXdnb3B6dWxrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODY3MzM2NjAsImV4cCI6MjEwMjMwOTY2MH0.U7Y3GM97jbdYQHyw5rDwy8ygV-iuVrmRD7LW2E7L_lA';

  // Supabase's own minimum can't be read from here; 8 is at least as strict
  // as its default (6). If the project ever asks for more, its answer is
  // shown as it comes. 72 bytes is the most Supabase accepts.
  var MIN_LENGTH = 8;
  var MAX_BYTES = 72;

  var SUPPORT = 'support@knowsie.app';
  var MESSAGES = {
    tooShort: 'Use at least ' + MIN_LENGTH + ' characters.',
    tooLong: 'That password is too long. Use 72 characters or fewer.',
    mismatch: "The passwords don't match.",
    offline: "We couldn't reach Knowsie. Check your connection and try again.",
    tooMany: 'Too many attempts. Wait a few minutes, then try again.',
    samePassword: "That's the password you already have. Choose a different one, or go back to the app and log in with it.",
    generic: "Something went wrong, and your password wasn't changed. Try again, or write to " + SUPPORT + '.',
  };

  var STATES = ['loading', 'form', 'done', 'expired', 'no-link', 'unavailable'];

  function el(id) {
    return document.getElementById(id);
  }

  function show(state) {
    STATES.forEach(function (name) {
      el('state-' + name).hidden = name !== state;
    });
  }

  // Never show a password form inside someone else's page.
  if (window.top !== window.self) {
    show('no-link');
    return;
  }

  // The library comes from a CDN; if it didn't load, leave the address as
  // it is so a reload can try again with the same link.
  if (!window.supabase || typeof window.supabase.createClient !== 'function') {
    show('unavailable');
    return;
  }

  var link = readLink();
  // Take the link's secrets out of the address bar and the browser history.
  if (window.location.search || window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname);
  }

  if (link.kind === 'error') {
    show('expired');
    return;
  }
  if (link.kind === 'none') {
    show('no-link');
    return;
  }

  var client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  var form = el('reset-form');
  var newPassword = el('new-password');
  var repeatPassword = el('repeat-password');
  var showPasswords = el('show-passwords');
  var submitButton = el('submit-button');
  var formError = el('form-error');
  var sessionReady = false;
  var busy = false;

  showPasswords.addEventListener('change', function () {
    var type = showPasswords.checked ? 'text' : 'password';
    newPassword.type = type;
    repeatPassword.type = type;
  });

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (!busy) changePassword();
  });

  show('form');

  function readLink() {
    var query = new URLSearchParams(window.location.search);
    var hash = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    function param(name) {
      return hash.get(name) || query.get(name);
    }
    if (param('error') || param('error_code')) return { kind: 'error' };
    var isRecovery = param('type') === 'recovery';
    if (isRecovery && param('token_hash')) {
      return { kind: 'token_hash', tokenHash: param('token_hash') };
    }
    if (isRecovery && param('access_token') && param('refresh_token')) {
      return { kind: 'session', accessToken: param('access_token'), refreshToken: param('refresh_token') };
    }
    if (query.get('code')) return { kind: 'code', code: query.get('code') };
    return { kind: 'none' };
  }

  // Turns the link into a signed-in session, once. Kept for retries, so a
  // weak-password answer or a dropped connection doesn't need a new link.
  function ensureSession() {
    if (sessionReady) return Promise.resolve(null);
    var request;
    if (link.kind === 'token_hash') {
      request = client.auth.verifyOtp({ token_hash: link.tokenHash, type: 'recovery' });
    } else if (link.kind === 'session') {
      request = client.auth.setSession({ access_token: link.accessToken, refresh_token: link.refreshToken });
    } else {
      request = client.auth.exchangeCodeForSession(link.code);
    }
    return request.then(function (result) {
      if (result.error) return result.error;
      if (!result.data || !result.data.session) return { name: 'AuthSessionMissingError' };
      sessionReady = true;
      return null;
    });
  }

  function changePassword() {
    hideError();
    var password = newPassword.value;
    if (password.length < MIN_LENGTH) return showError(MESSAGES.tooShort, newPassword);
    if (new TextEncoder().encode(password).length > MAX_BYTES) return showError(MESSAGES.tooLong, newPassword);
    if (password !== repeatPassword.value) return showError(MESSAGES.mismatch, repeatPassword);

    setBusy(true);
    ensureSession()
      .then(function (sessionError) {
        if (sessionError) {
          handleLinkError(sessionError);
          return;
        }
        return client.auth.updateUser({ password: password }).then(function (result) {
          if (result.error) {
            handleUpdateError(result.error);
            return;
          }
          return finish();
        });
      })
      .catch(function () {
        showError(MESSAGES.generic);
      })
      .then(function () {
        setBusy(false);
      });
  }

  function finish() {
    newPassword.value = '';
    repeatPassword.value = '';
    // Ends this page's session only; the app signs in afresh.
    return client.auth
      .signOut({ scope: 'local' })
      .catch(function () {})
      .then(function () {
        show('done');
      });
  }

  function isOffline(error) {
    return error && error.name === 'AuthRetryableFetchError';
  }

  // The link couldn't be turned into a session.
  function handleLinkError(error) {
    if (isOffline(error)) return showError(MESSAGES.offline);
    if (error.code === 'over_request_rate_limit') return showError(MESSAGES.tooMany);
    show('expired');
  }

  function handleUpdateError(error) {
    if (isOffline(error)) return showError(MESSAGES.offline);
    if (error.code === 'over_request_rate_limit') return showError(MESSAGES.tooMany);
    if (error.code === 'same_password') return showError(MESSAGES.samePassword, newPassword);
    if (error.code === 'weak_password' || error.code === 'validation_failed') {
      return showError(error.message || MESSAGES.generic, newPassword);
    }
    var sessionGone = ['session_not_found', 'session_expired', 'bad_jwt', 'refresh_token_not_found', 'user_not_found'];
    if (error.status === 401 || error.status === 403 || sessionGone.indexOf(error.code) !== -1) {
      show('expired');
      return;
    }
    showError(MESSAGES.generic);
  }

  function showError(message, field) {
    formError.textContent = message;
    formError.hidden = false;
    if (field) field.focus();
  }

  function hideError() {
    formError.hidden = true;
    formError.textContent = '';
  }

  function setBusy(value) {
    busy = value;
    submitButton.disabled = value;
    submitButton.textContent = value ? 'Changing…' : 'Change password';
  }
})();
