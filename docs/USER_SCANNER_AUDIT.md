# user-scanner module audit (2026-10-08)

`recce email --deep` used to wrap only [holehe](https://github.com/megadose/holehe)
1.61, and after the [holehe audit](HOLEHE_AUDIT.md) just 4 of its modules were
proven to work. This audit evaluates
[user-scanner](https://github.com/kaifcodec/user-scanner) 1.5.2.1 (MIT, PyPI
release of 2026-09-30) as the replacement. The outcome: user-scanner is now
the main deep-mode backend. holehe runs only for the sites user-scanner lacks.
The lists in `recce/modules/email_deep.py` (`USER_SCANNER_MODULES`,
`NOTIFYING_USER_SCANNER_MODULES`, `BROKEN_USER_SCANNER_MODULES`,
`HOLEHE_REPLACED_BY_USER_SCANNER`) come from this audit.

## Result

| verdict | holehe 1.61 | user-scanner 1.5.2.1 |
|---|---|---|
| working: found an operator address, and no made-up address | 4 | **18** |
| answers, unverified: real "not registered" answers, but neither operator address has an account there | 29 | 81 |
| always-true: "finds" made-up addresses | 1 | 1 |
| always-false: "not registered" whatever the input | 15 | 0 |
| erroring | 39 | 2 |
| blocked: bot wall from every exit tested | 17 | 5 |
| notify-risk: could alert the owner of the address, never run | 16 | 104 |
| **modules** | 121 | 211 |

recce now runs 117 probes: 99 user-scanner modules (the working and
answering ones) plus 18 holehe modules for sites user-scanner lacks. Two of
those holehe modules, lastpass and replit, are proven working, so deep mode
went from 4 proven sites to 20. Every FOUND hit still gets the same-domain
made-up-address canary.

A live `recce email --deep` run with this code found 18 sites for the
outlook.com operator address (16 from user-scanner, plus lastpass and replit
from holehe) and 4 for the pm.me address. Every hit passed the canary.

## Method

- **Code review before install.** The PyPI wheel was checked byte for byte
  against the `1.5.2.1` git tag (commit `c60d5b0`). The source of all 211
  email modules was read before anything ran. user-scanner flags 44 email
  modules as "loud" (it skips them unless `--allow-loud` is passed). The
  review excluded 59 more, using the same rule as the holehe audit: anything
  that sends a reset, OTP or login link, signs in with a password (failed
  sign-ins feed lockout counters and "unusual sign-in" mails), submits a
  sign-up (the account gets created, or a "you already have an account"
  mail goes out, if the deliberately broken field is ever accepted), starts
  a recovery flow, or could otherwise mail the address. Shopify's
  `customerCreate` mails an activation link to guest-checkout addresses, and
  one newsletter form's check runs with `subscribe=true`. The 108 modules
  left are quiet lookups: availability checks, sign-in method lookups and
  sign-up form validators. One of them, `shopping/trocvelo`, exists only on
  `main` and is not in the release.
- **Inputs:** the two operator-owned addresses (an outlook.com and a pm.me
  address) and three made-up ones: random local parts at example.com,
  outlook.com and pm.me. That way a check that answers per domain is caught
  as well.
- **Exits:** the VM's Proton VPN exit (NL), Tor, and, with made-up addresses
  only, a residential UK line.
- **Raw responses:** every HTTP exchange each module made (httpx and
  curl_cffi) was captured and read. This audit found no silent
  fall-through: each "not registered" verdict matches an explicit answer in
  the response body (`{"exists":false}`, `{"taken":false}`, `"User does
  not exist"`, a 404 with an error code, and so on).
- **A notifier slipped through the review.** `learning/vedantu` looked like a
  lookup (`preLoginVerification`), but its response said
  `"emailSent":true,"smsSent":true` for every address. It ran once against
  each audit address on the Proton exit before this was spotted. It is now
  in the never-run list, and the responses of every other module were
  searched for any sign of a send (`sent`, `otp`, `code`, `link`); none
  showed one. The two operator mailboxes may hold a Vedantu message from
  2026-10-08.

## Exit differences

- The Proton exit gave the most answers. Tor was worse: 26 modules that
  answer on Proton error over Tor, eventbrite and spotify among them.
- The five `shopping/alza_*` modules get a 403 on Proton and Tor but answer
  from the residential line. They stay in the run list and show up as
  errors on the default exit.
- `annaabi`, `github`, `nytimes`, `threadless` and `vimeo` are bot-walled
  on every exit, and `firefox` and `emirates` error everywhere. None of
  these run.
- `office365` (Autodiscover) answers 200 for any @outlook.com address, the
  made-up one included, so it is always-true for Microsoft consumer domains
  and never runs. holehe's `office365` module uses a different check and
  stays.
- In this audit, `tumblr` built its own curl_cffi session, which bypassed
  the audit's exit routing, so its Tor and residential answers actually went
  out over Proton. recce routes it through the chosen exit (see below).

## How recce runs user-scanner

- The dependency is pinned (`user-scanner==1.5.2.1`). A test checks that
  every email module in the installed release is in exactly one of the
  three lists, so a version bump fails CI until the new modules are
  reviewed.
- recce calls each module's `validate_<site>(email)` directly. It never
  imports user-scanner's email orchestrator, which monkey-patches
  `httpx.AsyncClient` for the whole process.
- The modules build their own clients, so the run's exit (`--proxy`,
  `RECCE_EMAIL_PROXY`, `RECCE_PROXY`) reaches them through a context
  variable. Each module's `httpx` global is replaced with a shim that adds
  the proxy to every `AsyncClient`, tumblr's curl_cffi `Session` gets the
  same treatment, and the shared browser-impersonating sessions read their
  proxy from the same variable. On the VM, the Proton, Tor and residential
  exits each showed up as the source IP for both client types.
- `TAKEN` maps to a FOUND hit (with the module's extra fields in the
  summary), `AVAILABLE` to not found, rate-limit errors to skipped (so the
  retry pass picks them up), and other errors to error. Each hit's
  `extra.backend` says which library answered.

## Sites both libraries cover

| site | holehe 1.61 | user-scanner 1.5.2.1 | recce runs |
|---|---|---|---|
| adobe | notify-risk | working | user-scanner |
| amazon | always-false | notify-risk: other | neither |
| anydo | answers, unverified | answers, unverified | user-scanner |
| atlassian | erroring | answers, unverified | user-scanner |
| axonaut | answers, unverified | answers, unverified | user-scanner |
| buymeacoffee | erroring | notify-risk: loud | neither |
| codecademy | blocked | working | user-scanner |
| codepen | blocked | answers, unverified | user-scanner |
| devrant | notify-risk | notify-risk: other | neither |
| envato | always-false | answers, unverified | user-scanner |
| eventbrite | working | working | user-scanner |
| firefox | erroring | erroring | neither |
| flickr | always-false | notify-risk: other | neither |
| freelancer | answers, unverified | answers, unverified | user-scanner |
| github | erroring | blocked | neither |
| gravatar | answers, unverified | answers, unverified | user-scanner |
| hubspot | notify-risk | notify-risk: other | neither |
| insightly | answers, unverified | answers, unverified | user-scanner |
| instagram | erroring | working | user-scanner |
| komoot | erroring | notify-risk: other | neither |
| naturabuy | answers, unverified | answers, unverified | user-scanner |
| office365 | answers, unverified | always-true | holehe |
| patreon | erroring | notify-risk: other | neither |
| pinterest | erroring | working | user-scanner |
| plurk | answers, unverified | answers, unverified | user-scanner |
| pornhub | erroring | notify-risk: other | neither |
| quora | blocked | answers, unverified | user-scanner |
| redtube | answers, unverified | answers, unverified | user-scanner |
| spotify | working | working | user-scanner |
| tumblr | erroring | working | user-scanner |
| twitter / x | answers, unverified | answers, unverified | user-scanner |
| vivino | notify-risk | notify-risk: other | neither |
| wordpress | answers, unverified | answers, unverified | user-scanner |
| xnxx | answers, unverified | answers, unverified | user-scanner |
| xvideos | answers, unverified | answers, unverified | user-scanner |
| zoho | answers, unverified | answers, unverified | user-scanner |

## Per module

| verdict | module | why | exit notes |
|---|---|---|---|
| working | creator/adobe | found an operator address; every made-up address not found (only accounts with a password count; social/OTP-only accounts read as not found) |  |
| working | entertainment/appletv | found an operator address; every made-up address not found |  |
| working | news/bbc | found an operator address; every made-up address not found |  |
| working | creator/canva | found an operator address; every made-up address not found |  |
| working | gaming/chess_com | found an operator address; every made-up address not found | rejects example.com; errors over Tor |
| working | dev/codecademy | found an operator address; every made-up address not found |  |
| working | learning/coursera | found an operator address; every made-up address not found |  |
| working | gaming/crazygames | found an operator address; every made-up address not found | errors over Tor |
| working | learning/duolingo | found an operator address; every made-up address not found |  |
| working | sports/espn | found an operator address; every made-up address not found |  |
| working | other/eventbrite | found an operator address; every made-up address not found | errors over Tor |
| working | dev/hackthebox | found an operator address; every made-up address not found |  |
| working | dev/huggingface | found an operator address; every made-up address not found |  |
| working | social/instagram | found an operator address; every made-up address not found | rejects example.com |
| working | fitness/myfitnesspal | found an operator address; every made-up address not found |  |
| working | social/pinterest | found an operator address; every made-up address not found |  |
| working | music/spotify | found an operator address; every made-up address not found | errors over Tor |
| working | social/tumblr | found an operator address; every made-up address not found | rejects example.com; uses its own curl_cffi session; recce routes it through the exit |
| answers, unverified | news/aljazeera | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | learning/allen | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | shopping/alza_at | real "not registered" answers; neither operator address has an account there | blocked on Proton and Tor; answers from the residential line |
| answers, unverified | shopping/alza_cz | real "not registered" answers; neither operator address has an account there | blocked on Proton and Tor; answers from the residential line |
| answers, unverified | shopping/alza_de | real "not registered" answers; neither operator address has an account there | blocked on Proton and Tor; answers from the residential line |
| answers, unverified | shopping/alza_hu | real "not registered" answers; neither operator address has an account there | blocked on Proton and Tor; answers from the residential line |
| answers, unverified | shopping/alza_sk | real "not registered" answers; neither operator address has an account there | blocked on Proton and Tor; answers from the residential line |
| answers, unverified | other/anydo | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | learning/aslbloom | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/atlassian | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | crm/axonaut | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | learning/cakeapp | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | learning/classdojo | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/codepen | real "not registered" answers; neither operator address has an account there | intermittent 403s on Proton |
| answers, unverified | music/deezer | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | jobs/dirbam | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | other/dropbox | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/envato | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | shopping/etsy | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/faproulette | real "not registered" answers; neither operator address has an account there | rejects example.com |
| answers, unverified | women_health/femometer | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | creator/figma | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | fitness/fitnessblender | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | news/flipboard | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | news/foxnews | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | jobs/freelancer | real "not registered" answers; neither operator address has an account there | rejects example.com |
| answers, unverified | music/gaana | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | women_health/glow | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | social/gravatar | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/hackerrank | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/howtogeek | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | news/indiatimes | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | crm/insightly | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | music/jiosaavn | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | entertainment/justwatch | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | jobs/kandideeri | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | creator/kick | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | learning/lingq | real "not registered" answers; neither operator address has an account there | rejects every made-up address; errors from the residential line |
| answers, unverified | social/locket | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | social/lovenudge | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | sports/marca | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | gaming/medal | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | women_health/meetyou | real "not registered" answers; neither operator address has an account there | errors from the residential line |
| answers, unverified | social/mewe | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | other/moz | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | entertainment/myanimelist | real "not registered" answers; neither operator address has an account there | rejects example.com |
| answers, unverified | women_health/myperiodtracker | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | shopping/naturabuy | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | sports/nba | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | hosting/neocities | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | shopping/nykaaman | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | dating/okcupid | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | jobs/otsintood | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | sports/playtomic | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | social/plurk | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | travel/polarsteps | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | learning/quizlet | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | community/quora | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | shopping/rappi | real "not registered" answers; neither operator address has an account there | never reaches its loud login step: that needs user-scanner's --allow-loud in the process argv |
| answers, unverified | adult/redtube | real "not registered" answers; neither operator address has an account there | rejects example.com |
| answers, unverified | other/secondline | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dating/skout | real "not registered" answers; neither operator address has an account there | rejects example.com |
| answers, unverified | travel/skyscanner | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | learning/speak | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | other/start_me | real "not registered" answers; neither operator address has an account there | errors from the residential line |
| answers, unverified | entertainment/sunnxt | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/superporn | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | shopping/tatacliq | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | shopping/tindie | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/tube8 | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | jobs/visidarbi | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | shopping/walmart | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | creator/wisio | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/wix | real "not registered" answers; neither operator address has an account there | errors over Tor |
| answers, unverified | dev/wondershare | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | dev/wordpress | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | social/x | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/xnxx | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/xvideos | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | adult/youporn | real "not registered" answers; neither operator address has an account there |  |
| answers, unverified | crm/zoho | real "not registered" answers; neither operator address has an account there |  |
| always-true | other/office365 | Autodiscover answers 200 for any @outlook.com address, made-up ones included |  |
| erroring | travel/emirates | times out from every exit |  |
| erroring | other/firefox | account-status API answers 406 |  |
| blocked | learning/annaabi | Cloudflare challenge from every exit |  |
| blocked | dev/github | sign-up check behind DataDome from every exit; the user-search half only sees addresses published on a profile |  |
| blocked | news/nytimes | DataDome 403 from every exit |  |
| blocked | creator/threadless | Cloudflare 403 on the check from every exit |  |
| blocked | creator/vimeo | captcha challenge from every exit |  |
| notify-risk: loud | other/ama | flagged loud upstream: resetPassword sends a reset email |  |
| notify-risk: loud | learning/asafeer | flagged loud upstream: forgotPass sends a reset email |  |
| notify-risk: loud | adult/babestation | flagged loud upstream: sends a username-reminder email |  |
| notify-risk: loud | learning/bnrlanguages | flagged loud upstream: Firebase getOobConfirmationCode sends a reset email |  |
| notify-risk: loud | learning/bunpo | flagged loud upstream: Firebase getOobConfirmationCode sends a reset email |  |
| notify-risk: loud | creator/buymeacoffee | flagged loud upstream: email login sends an OTP |  |
| notify-risk: loud | learning/cambly | flagged loud upstream: forgotPassword sends a reset email |  |
| notify-risk: loud | social/couplejoy | flagged loud upstream: reset-password sends a reset email |  |
| notify-risk: loud | jobs/cv_ee | flagged loud upstream: forgot-password sends a reset email |  |
| notify-risk: loud | jobs/cv_lv | flagged loud upstream: forgot-password sends a reset email |  |
| notify-risk: loud | jobs/cvkeskus | flagged loud upstream: sends a username reminder |  |
| notify-risk: loud | jobs/cvmarket_lt | flagged loud upstream: sends a username reminder |  |
| notify-risk: loud | jobs/cvmarket_lv | flagged loud upstream: sends a username reminder |  |
| notify-risk: loud | jobs/cvonline_lt | flagged loud upstream: forgot-password sends a reset email |  |
| notify-risk: loud | other/dragongroot | flagged loud upstream: sends a sign-up OTP to free addresses |  |
| notify-risk: loud | learning/duocards | flagged loud upstream: may send a login link to passwordless accounts |  |
| notify-risk: loud | adult/fantasia | flagged loud upstream: sends a sign-in code |  |
| notify-risk: loud | fitness/finch | flagged loud upstream: Firebase getOobConfirmationCode sends a reset email |  |
| notify-risk: loud | shopping/flipkart | flagged loud upstream: login identity verify |  |
| notify-risk: loud | adult/flirtbate | flagged loud upstream: sends a password-reset email |  |
| notify-risk: loud | learning/hanzii | flagged loud upstream: password/reset sends a reset email |  |
| notify-risk: loud | learning/hellochinese | flagged loud upstream: forget_password sends a reset email |  |
| notify-risk: loud | jobs/hercul | flagged loud upstream: requests a password reset for registered addresses |  |
| notify-risk: loud | learning/heyjapan | flagged loud upstream: sends a recovery code |  |
| notify-risk: loud | entertainment/hoichoi | flagged loud upstream: sends a sign-in OTP |  |
| notify-risk: loud | learning/jetpunk | flagged loud upstream: sends a password-reset email |  |
| notify-risk: loud | jobs/jobs_cz | flagged loud upstream: password-reset form sends a link |  |
| notify-risk: loud | learning/linga | flagged loud upstream: recovery sends an email |  |
| notify-risk: loud | dev/luarocks | flagged loud upstream: forgot-password sends a reset link |  |
| notify-risk: loud | adult/made_porn | flagged loud upstream: change-password endpoint emails a reset link |  |
| notify-risk: loud | dev/medium | flagged loud upstream: sends a login code |  |
| notify-risk: loud | learning/memrise | flagged loud upstream: password-reset form sends a link |  |
| notify-risk: loud | entertainment/netflix | flagged loud upstream: starts the sign-up journey |  |
| notify-risk: loud | creator/payhip | flagged loud upstream: forgot-password sends a reset email |  |
| notify-risk: loud | learning/programminghub | flagged loud upstream: recover/initiate sends a recovery email |  |
| notify-risk: loud | jobs/pulser | flagged loud upstream: requests a password reset |  |
| notify-risk: loud | adult/sexvid | flagged loud upstream: reset-password flow mails a new password |  |
| notify-risk: loud | social/slowly | flagged loud upstream: sends an email passcode |  |
| notify-risk: loud | learning/speakly | flagged loud upstream: password reset sends an email |  |
| notify-risk: loud | social/superlive | flagged loud upstream: sends a password-renewal code |  |
| notify-risk: loud | learning/talkpal | flagged loud upstream: recovery-request sends a reset email |  |
| notify-risk: loud | sports/uniscore | flagged loud upstream: forgot-password sends a magic link |  |
| notify-risk: loud | learning/vedantu | **found in this audit:** preLoginVerification answers "emailSent":true,"smsSent":true for every address: it sends a login code (found in this audit; ran once per audit address before the response was read) |  |
| notify-risk: loud | social/weawow | flagged loud upstream: password-reset form sends a link |  |
| notify-risk: loud | entertainment/weverse | flagged loud upstream: opens a password-reset OTP session |  |
| notify-risk: other | gaming/addictinggames | submits a registration with a valid password; only a reused username stops it |  |
| notify-risk: other | sports/aiscore | submits a registration with a valid password; a free address gets a registration token back |  |
| notify-risk: other | learning/alison | submits a registration with a blank password |  |
| notify-risk: other | shopping/amazon | submits the sign-in email step; the newer /ax/claim flow can mail a one-time code (and it reads any captcha as registered) |  |
| notify-risk: other | entertainment/anilist | calls the ResetPassword GraphQL mutation |  |
| notify-risk: other | learning/babbel | submits a registration with a blank password |  |
| notify-risk: other | sports/besoccer | submits a registration with a blank password (BeSoccer) |  |
| notify-risk: other | hosting/bunny | submits a registration (password fails policy) |  |
| notify-risk: other | social/classmates | submits a sign-in with a wrong password |  |
| notify-risk: other | news/cnn | creates an identity with a password (registration request) |  |
| notify-risk: other | dev/codewars | submits a sign-up with blank username/password |  |
| notify-risk: other | other/deviantart | submits a sign-up with a blank password |  |
| notify-risk: other | dev/devrant | submits a registration with a blank username |  |
| notify-risk: other | community/disqus | submits a sign-up with a blank password |  |
| notify-risk: other | other/dollarfix | submits a sign-in with a wrong password |  |
| notify-risk: other | entertainment/dreame | submits a sign-in with a wrong password |  |
| notify-risk: other | fitness/evolveyou | submits a sign-in with a wrong password |  |
| notify-risk: other | social/facebook | first step of the account-recovery flow (identify) |  |
| notify-risk: other | adult/fapfolder | submits a sign-up (password "1") |  |
| notify-risk: other | shopping/fixderma | Shopify customerCreate: for a guest-checkout address Shopify mails an account-activation link |  |
| notify-risk: other | creator/flickr | Cognito SignUp with a valid password; only the PreSignUp hook stops account creation |  |
| notify-risk: other | entertainment/girlslife | submits a registration with a blank password |  |
| notify-risk: other | news/globaltimes | submits a sign-in with a wrong password; the site counts failures toward a lockout |  |
| notify-risk: other | creator/gumroad | submits a sign-up (3-character password) |  |
| notify-risk: other | dev/hackerearth | submits a sign-up with a blank password |  |
| notify-risk: other | dev/hackerone | submits a sign-up with mismatched passwords |  |
| notify-risk: other | shopping/hautesauce | Shopify customerCreate: for a guest-checkout address Shopify mails an account-activation link |  |
| notify-risk: other | crm/hubspot | submits a sign-in with a blank password |  |
| notify-risk: other | women_health/iyoni | Firebase verifyPassword with a wrong password (failed sign-in) |  |
| notify-risk: other | travel/komoot | advances the sign-in flow; Komoot can mail a sign-in link |  |
| notify-risk: other | creator/leanpub | submits a sign-up with a book (1-character password) |  |
| notify-risk: other | dating/lespark | submits a sign-in with a wrong password |  |
| notify-risk: other | adult/letsporn | submits a sign-up (mismatched passwords) |  |
| notify-risk: other | entertainment/letterboxd | submits a registration with a valid password (empty captcha) |  |
| notify-risk: other | dating/locanto | register_attempt: sign-up starts from the address alone and may mail a registration link |  |
| notify-risk: other | adult/lovescape | submits a full sign-up with a valid password; only a reused username stops it |  |
| notify-risk: other | social/mastodon | submits a full registration with a valid password; only a reused username stops it |  |
| notify-risk: other | social/meeff | submits a sign-in with a blank password |  |
| notify-risk: other | music/mixcloud | submits a registration with a blank password |  |
| notify-risk: other | learning/mondly | submits a sign-in with a wrong password |  |
| notify-risk: other | entertainment/nebula_tv | submits a registration (1-character password) |  |
| notify-risk: other | community/nextdoor | password grant with a wrong password (failed sign-in) |  |
| notify-risk: other | other/numsify | submits a registration (password fails policy) |  |
| notify-risk: other | creator/patreon | first step of the login flow; passwordless accounts may be sent a sign-in code |  |
| notify-risk: other | adult/pornhub | module notes the check mails the account holder for the plain address; probes a +tag alias instead |  |
| notify-risk: other | women_health/premom | submits a sign-up with a valid password; only a missing first name stops it |  |
| notify-risk: other | dev/qiita | submits a registration with a valid password (empty captcha); reports "available" for anything else |  |
| notify-risk: other | dev/rubygems | submits a sign-up with a blank password |  |
| notify-risk: other | other/screener | submits a registration with a blank password |  |
| notify-risk: other | gaming/stackb | submits a sign-in with a wrong password |  |
| notify-risk: other | community/stackoverflow | submits a sign-in with a wrong password |  |
| notify-risk: other | entertainment/stremio | submits a sign-in with a wrong password |  |
| notify-risk: other | fitness/sweat | Auth0 password grant with a wrong password (Auth0 can mail a lockout notice) |  |
| notify-risk: other | learning/talkme | submits a sign-in with a wrong password |  |
| notify-risk: other | adult/thegay | submits a sign-up (no captcha token) |  |
| notify-risk: other | shopping/vivino | submits a sign-in with a wrong password |  |
| notify-risk: other | social/whering | Firebase verifyPassword with a wrong password (failed sign-in) |  |
| notify-risk: other | women_health/womanlog | submits a sign-in with a wrong password |  |
| notify-risk: other | dev/xda | newsletter form's check-user-exists called with subscribe=true |  |
