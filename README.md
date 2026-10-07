# knowsie.app

The Knowsie website (static, served by GitHub Pages at https://knowsie.app).

## /reset/

The password reset page that the app's "Forgot password?" email links to.
`reset/reset.js` holds the Supabase project URL and its anon key: both are
public by design (they're built into the app too). It loads
`@supabase/supabase-js` 2.112.3 from jsDelivr with an integrity hash; to
change the version, update the URL in the script tag and the
Content-Security-Policy, and the `integrity` value
(`openssl dgst -sha384 -binary supabase.js | openssl base64 -A`).
