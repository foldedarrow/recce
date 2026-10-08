# holehe module audit (2026-10-08)

`recce email --deep` wraps [holehe](https://github.com/megadose/holehe) 1.61,
whose last release was July 2022 and last commit September 2024. This audit
covers all 121 of its modules (roadmap #6) and sets
`NOTIFYING_HOLEHE_MODULES` and `BROKEN_HOLEHE_MODULES` in
`recce/modules/email_deep.py`.

## Method

- **Inputs:** two addresses the operator owns (an outlook.com and a pm.me
  address) and four made-up ones: two random local parts at example.com and
  one each at outlook.com and pm.me. That way a check that answers per domain
  is caught as well.
- **No notifications:** every module's source was read before anything ran.
  Modules that submit a password, create or start an account, or walk a
  password-reset flow (16, below) were only ever sent made-up addresses, and
  `samsung` (the resetPassword flow) was not run at all.
- **Exits:** the VM's Proton VPN exit (NL), Tor, and, with made-up addresses
  only, a residential UK line.
- **Raw responses:** holehe falls through to `exists: False` on most
  unexpected responses, so a blocked or changed endpoint reads as "not
  registered". Each module's HTTP exchanges for a made-up address were
  captured and read, which separates real negatives from silent breakage.

## Verdicts

| verdict | modules | run by recce |
|---|---|---|
| working | 4 — found an operator address, and no made-up address | yes |
| answers, unverified | 29 — real "not registered" answers, but neither operator address has an account there, so no hit is proven | yes |
| always-true | 1 — "finds" made-up addresses | no |
| always-false | 15 — says "not registered" whatever the input | no |
| erroring | 39 — crashes, times out, or reports everything as rate-limited (dead domain, stale endpoint) | no |
| blocked | 17 — bot wall (Cloudflare, DataDome, Distil) on every exit tested | no |
| notify-risk (skipped, fakes only) | 16 — could alert the owner of the address | no |

So recce now runs 33 of the 121 modules instead of 108. Every FOUND hit is
re-probed with a made-up address at the same domain, and a site that also
"finds" that address is downgraded to unknown (`--no-deep-verify` turns
this off). The same-domain choice comes from this audit: the `protonmail`
module "finds" any made-up @pm.me address, because Proton's key server
returns keys for nonexistent addresses on its own domains, while an
example.com canary passes it cleanly.

## Exit differences

- The Proton exit gave the most answers. Tor was worse for every module, and
  nothing that was blocked on Proton worked over Tor.
- From the residential line, `onlinesequencer` and `redtube` answered
  (both blocked on Proton), but `coroflot`, `koditv`, `replit` and
  `myspace` hit Cloudflare.
- The 17 "blocked" modules failed on all three exits, so they are skipped. A
  different residential IP may get through.

## Per module

| verdict | module | why | exit notes |
|---|---|---|---|
| working | products/eventbrite | found an operator address; every made-up address not found | blocked over Tor |
| working | software/lastpass | found an operator address; every made-up address not found |  |
| working | programing/replit | found an operator address; every made-up address not found | answers on Proton; Cloudflare 403 from the residential line |
| working | music/spotify | found an operator address; every made-up address not found | blocked over Tor |
| answers, unverified | productivity/anydo | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | crm/axonaut | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | forum/biosmods | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | sport/bodybuilding | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | forum/clashfarmer | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | jobs/coroflot | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | answers on Proton; Cloudflare 403 from the residential line |
| answers, unverified | learning/diigo | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | jobs/freelancer | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | rejects example.com; outlook.com and pm.me fakes answer |
| answers, unverified | cms/gravatar | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | crm/insightly | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | forum/koditv | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | answers on Proton; Cloudflare challenge from the residential line |
| answers, unverified | music/lastfm | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | errors over Tor for real addresses |
| answers, unverified | social_media/myspace | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | answers on Proton; no answer from Tor or the residential line |
| answers, unverified | shopping/naturabuy | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | forum/nextpvr | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | software/office365 | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | "rate-limited" for outlook.com addresses (consumer mailboxes are not Microsoft 365 tenants) |
| answers, unverified | forum/onlinesequencer | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | Cloudflare on Proton and Tor; answers from the residential line |
| answers, unverified | social_media/plurk | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | medias/rambler | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | porn/redtube | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | token missing on Proton and Tor; answers from the residential line |
| answers, unverified | medias/sporcle | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | Cloudflare 403 from the residential line is read as not registered |
| answers, unverified | programing/teamtreehouse | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | rejects example.com; outlook.com and pm.me fakes answer |
| answers, unverified | forum/thecardboard | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | social_media/twitter | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | social_media/wattpad | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven | rejects example.com; outlook.com and pm.me fakes answer |
| answers, unverified | cms/wordpress | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | porn/xnxx | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | porn/xvideos | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| answers, unverified | crm/zoho | real "not registered" answers for every input; neither operator address is registered, so a hit is unproven |  |
| always-true | mails/protonmail | always true: Proton's key server returns a key for made-up Proton-domain addresses |  |
| always-false | shopping/amazon | sign-in POST answers 404: always false |  |
| always-false | software/archive | sign-up check redirects to /signup: always false |  |
| always-false | shopping/armurerieauxerre | endpoint answers 410 Gone: always false |  |
| always-false | forum/biotechnologyforums | MyBB 'authorization code mismatch': always false |  |
| always-false | forum/blitzortung | availability check redirects to the forum index: always false |  |
| always-false | medical/caringbridge | sign-in POST answers 405: always false |  |
| always-false | shopping/dominosfr | Akamai 403 read as not registered: always false |  |
| always-false | shopping/envato | Cloudflare 403 read as not registered: always false |  |
| always-false | social_media/fanpop | registration closed ('currently unavailable'): always false |  |
| always-false | medias/flickr | identity API answers 'cognito error': always false |  |
| always-false | mails/laposte | endpoint 404: always false |  |
| always-false | forum/mybb | availability check returns the HTML forum page: always false |  |
| always-false | forum/ndemiccreations | availability check returns an empty body: always false |  |
| always-false | social_media/taringa | availability API returns the HTML app shell: always false |  |
| always-false | social_media/tellonym | API wants a token (403 TOKEN_INVALID): always false |  |
| erroring | crm/amocrm | moved to kommo.com; the check answers 405 |  |
| erroring | cms/atlassian | login page no longer carries the CSRF token |  |
| erroring | forum/badeggsonline | forum answers with PHP warnings instead of a token |  |
| erroring | social_media/bitmoji | Snapchat's login page changed (v2); token not found |  |
| erroring | music/blip | consistently times out |  |
| erroring | crowfunding/buymeacoffee | AttributeError on the response shape |  |
| erroring | forum/chinaphonearena | DNS gone |  |
| erroring | forum/cpahero | TLS certificate no longer matches the host |  |
| erroring | forum/cracked_to | DNS gone |  |
| erroring | social_media/crevado | site answers 404; IndexError |  |
| erroring | shopping/deliveroo | DNS gone |  |
| erroring | medias/ello | Cloudflare 520 (Ello shut down) |  |
| erroring | productivity/evernote | login moved to accounts.evernote.com; IndexError |  |
| erroring | software/firefox | account-status API answers 406 |  |
| erroring | forum/freiberg | forum 404 |  |
| erroring | shopping/garmin | sign-up token missing from the page |  |
| erroring | programing/github | sign-up page 403s; IndexError |  |
| erroring | mails/google | sign-up moved to the lifecycle flow; token not found |  |
| erroring | social_media/imgur | email check answers 406/403 |  |
| erroring | social_media/instagram | sign-up page no longer carries the CSRF token |  |
| erroring | software/issuu | check endpoint 503 (no_route) |  |
| erroring | medias/komoot | sign-in endpoint 404 |  |
| erroring | forum/nattyornot | DNS gone |  |
| erroring | products/nike | DNS gone (unite.nike.com) |  |
| erroring | crm/nocrm | check endpoint 404 |  |
| erroring | social_media/patreon | email-available API 404 |  |
| erroring | social_media/pinterest | EmailExistsResource 403; JSONDecodeError |  |
| erroring | porn/pornhub | check endpoint 404/410 |  |
| erroring | osint/rocketreach | validateEmail 404; KeyError |  |
| erroring | social_media/snapchat | login page changed (v2); IndexError |  |
| erroring | music/soundcloud | client id no longer scrapeable; IndexError |  |
| erroring | social_media/strava | email_unique endpoint 404 |  |
| erroring | crm/teamleader | availability API returns the HTML app shell |  |
| erroring | forum/thevapingforum | domain for sale |  |
| erroring | social_media/tumblr | API token no longer found in the page |  |
| erroring | music/tunefind | join page 404 |  |
| erroring | cms/voxmedia | Fastly 'unknown domain' |  |
| erroring | social_media/xing | sign-up page 404 |  |
| erroring | mails/yahoo | login page no longer carries acrumb; times out over Tor |  |
| blocked | forum/babeshows | Cloudflare challenge from every exit |  |
| blocked | transport/blablacar | DataDome captcha from every exit |  |
| blocked | forum/blackworldforum | 403 'forbidden by administrative rules' from every exit |  |
| blocked | forum/bluegrassrivals | Cloudflare 403 from every exit |  |
| blocked | forum/cambridgemt | Cloudflare challenge from every exit |  |
| blocked | programing/codecademy | bot check (/errors/browser) from every exit |  |
| blocked | forum/codeigniter | Cloudflare challenge from every exit |  |
| blocked | programing/codepen | Cloudflare challenge from every exit |  |
| blocked | forum/cpaelites | Cloudflare 403 from every exit |  |
| blocked | forum/demonforums | Cloudflare challenge from every exit |  |
| blocked | shopping/ebay | Distil / 403 bot wall from every exit |  |
| blocked | crm/nimble | Cloudflare challenge from every exit |  |
| blocked | learning/quora | Cloudflare challenge from every exit |  |
| blocked | music/smule | Cloudflare challenge on most requests from every exit | occasionally passes Cloudflare on Proton |
| blocked | forum/therianguide | 429 'you're a spambot' from every exit |  |
| blocked | real_estate/vrbo | 429 'Bot or Not?' from every exit |  |
| blocked | social_media/vsco | Cloudflare 403 from every exit |  |
| notify-risk (skipped, fakes only) | company/aboutme | posts a sign-up form (endpoint now 302 -> 404) |  |
| notify-risk (skipped, fakes only) | software/adobe | password-recovery challenge flow; existing accounts fail there and read as rate-limited |  |
| notify-risk (skipped, fakes only) | programing/devrant | posts a registration (rejected for the blank username before the email is checked) |  |
| notify-risk (skipped, fakes only) | social_media/discord | posts a full registration with consent; only the missing date of birth stops it |  |
| notify-risk (skipped, fakes only) | software/docker | posts a sign-up (endpoint 404) |  |
| notify-risk (skipped, fakes only) | crm/hubspot | submits a sign-in with a blank password |  |
| notify-risk (skipped, fakes only) | mails/mail_ru | password-restore endpoint (and posts the literal text '{email}', so never finds anything) |  |
| notify-risk (skipped, fakes only) | crm/nutshell | submits a sign-in with a wrong password (now refused: 'disable your adblocker') |  |
| notify-risk (skipped, fakes only) | social_media/odnoklassniki | password-recovery flow (the address no longer reaches the recovery page: always false) |  |
| notify-risk (skipped, fakes only) | social_media/parler | submits a sign-in with a wrong password (API redirects to the app: always false) |  |
| notify-risk (skipped, fakes only) | crm/pipedrive | starts a sign-up for addresses that are free (Cloudflare 403 from every exit) |  |
| notify-risk (skipped, fakes only) | products/samsung | walks the resetPassword flow |  |
| notify-risk (skipped, fakes only) | jobs/seoclerks | submits a full sign-up (refused on captcha: always false) |  |
| notify-risk (skipped, fakes only) | medical/sevencups | posts to CreateAccount.php (CloudFront 403) |  |
| notify-risk (skipped, fakes only) | payment/venmo | posts a new-user record (crashes on an undefined name first) |  |
| notify-risk (skipped, fakes only) | shopping/vivino | submits a sign-in with a wrong password (CSRF token fetched from tunefind.com: never works) |  |

## Maintained alternatives

- No holehe fork is maintained. megadose/holehe's last push was September
  2024 (116 open issues), and the recently pushed forks on GitHub have 0 stars
  and no upstream fixes. There is no other holehe package on PyPI.
- [user-scanner](https://github.com/kaifcodec/user-scanner) (MIT, about 5.3k
  stars, commits this week, PyPI `user-scanner` 1.5.2.1 from 2026-09-30)
  covers about 220 email modules in its `email_scan` package and marks
  modules that notify the target as "loud", skipping them unless
  `--allow-loud` is passed.
- **Outcome (2026-10-08):** user-scanner was audited the same way
  ([USER_SCANNER_AUDIT.md](USER_SCANNER_AUDIT.md)): 18 of its modules
  proved working against 4 here, so it is now deep mode's main backend.
  holehe still runs 18 of the 33 modules above, the ones for sites
  user-scanner lacks (lastpass and replit among them). The 15 it hands over
  are listed in `HOLEHE_REPLACED_BY_USER_SCANNER`.
