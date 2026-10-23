# HollowWarden

A self-hosted Discord bot that verifies people before they get access to your
server. It replaces DoubleCounter and is built security-first.

New members see only a verification channel. They click **Verify**, pass a
check, and the bot gives them your "Verified" role, which unlocks everything
else. Anything suspicious goes to your moderators to approve or deny.

## Choosing a verification method

Set `VERIFY_METHOD` in `.env`. You can switch at any time; restart the bot afterwards.

| | `captcha` | `web` |
|---|---|---|
| How it works | An image code shown privately in Discord | Log in with Discord on your own site |
| Stops raid/spam bots | Yes | Yes |
| Catches alt accounts and banned users returning | No | Yes, when they verify from the same home network |
| Exposed to the internet | **Nothing.** No web server runs at all | One small HTTPS site behind Nginx Proxy Manager |
| Data stored about people | Nothing beyond pending reviews | A keyed hash of their IP (never the IP itself), deleted after 180 days |

Both methods flag accounts younger than `MIN_ACCOUNT_AGE_DAYS`.

**Recommendation:** start with `captcha`. It has zero network exposure. Move
to `web` if alts or ban evasion actually become a problem.

## Setup

### 1. Create the Discord application

1. Go to <https://discord.com/developers/applications>, click **New Application**, and name it.
2. **Installation** tab (do this before the Bot tab, or Discord won't let
   you make the bot private: *"Private application cannot have a default
   authorization link"*):
   - Set **Install Link** to **None** and save.
   - Under **Installation Contexts**, untick **User Install** and keep only
     **Guild Install**.
3. **Bot** tab:
   - Click **Reset Token** and copy the token (you'll save it in the Configure step below).
   - Turn **Public Bot OFF**. Otherwise anyone who finds the bot could add it
     to their own server. (The bot also leaves any server that isn't yours,
     but there's no reason to rely on that alone.)
   - Leave all three **Privileged Gateway Intents OFF**. The bot doesn't
     need them, and every permission it lacks is one an attacker can't
     abuse if the token ever leaks.
4. **Web mode only**, on the **OAuth2** tab:
   - Under **Redirects**, add `https://verify.example.com/callback` (your real domain).
   - Copy the **Client ID**, then reset and copy the **Client Secret**.
5. Invite the bot. **OAuth2 → URL Generator** → scopes `bot` and
   `applications.commands`, permissions **Manage Roles, View Channels, Send
   Messages, Embed Links, Attach Files**. Open the URL and pick your server.
   **Never grant Administrator.**

Turn on two-factor authentication for your Discord account. Whoever controls
that account controls the bot.

### 2. Set up your server

1. Create a role called **Verified** with **no permissions of its own**. The
   bot refuses to hand out a role carrying moderator or admin permissions,
   because a mistake there would let anyone who passes verification take
   over your server.
2. In **Server Settings → Roles**, drag the bot's role **above** Verified.
   Discord only lets a bot assign roles that sit below its own.
3. Lock your channels: deny **View Channel** for `@everyone` and allow it for
   Verified, except in a `#verify` channel that everyone can see but not
   type in.
4. Create a private mod channel (for example `#verification-log`) that the bot can post in.

   **Give the bot's role explicit allows in both channels.** Denying
   `@everyone` takes these permissions away from the bot as well, unless its
   own role is allowed them in that channel's permission settings:
   - `#verify`: **View Channel, Send Messages, Embed Links, Attach Files**
   - the mod channel: **View Channel, Send Messages, Embed Links**

   If the mod channel is wrong, the bot logs exactly which permissions are
   missing when it starts. If `#verify` is wrong, `/verification-panel`
   tells you privately when you run it.
5. Decide which roles are **bot admins** (for example `Owner` and
   `Moderator`). Only members with one of these roles, plus the server owner,
   can use the bot's commands and its Approve/Deny buttons. Discord
   permissions don't count here, not even Administrator. Only the roles you list do.
6. Turn on Developer Mode (**User Settings → Advanced**) so you can right-click
   and **Copy ID** on the server, the Verified role, the mod channel and each
   bot-admin role.

### 3. Configure

On your home server:

```bash
git clone https://github.com/kingofhollows099/hollowwarden.git
cd hollowwarden
cp .env.example .env
nano .env   # fill in the IDs and choose VERIFY_METHOD
```

Create the secret files. `read -rs` keeps the token out of your shell
history and off the screen:

```bash
read -rsp "Bot token: " value && printf '%s' "$value" > secrets/discord_bot_token; unset value; echo

# Web mode: paste the client secret and generate a random IP hashing key.
read -rsp "Client secret: " value && printf '%s' "$value" > secrets/discord_client_secret; unset value; echo
openssl rand -base64 48 > secrets/ip_hash_key

# CAPTCHA mode: those two files still have to exist (Compose requires them), but they're never read.
# [ -f secrets/discord_client_secret ] || echo unused > secrets/discord_client_secret
# [ -f secrets/ip_hash_key ] || echo unused > secrets/ip_hash_key

# Only the container's user (UID 10001) may read them.
sudo chown 10001:10001 secrets/*
sudo chmod 400 secrets/*
```

**Back up `secrets/ip_hash_key` somewhere safe.** If it changes, every stored
IP hash becomes meaningless and alt detection starts over from scratch. Keep
it private as well: anyone holding both the key and the database could test
guesses about which IP a member used.

### 4. Web mode: Nginx Proxy Manager

Skip this section in CAPTCHA mode.

1. Set `NPM_NETWORK` in `.env` to the Docker network your NPM container uses:
   `docker inspect <npm-container> --format '{{json .NetworkSettings.Networks}}'`.
2. Set `TRUSTED_PROXIES` to that network's subnet:
   `docker network inspect <network> --format '{{(index .IPAM.Config 0).Subnet}}'`.
3. In NPM, add a **Proxy Host**:
   - Domain: `verify.example.com`, scheme `http`, forward hostname `hollowwarden`, port `8080`.
   - Enable **Block Common Exploits**.
   - SSL tab: request a certificate and enable **Force SSL**, **HTTP/2** and **HSTS**.

#### Getting the real IP (important)

Alt detection compares visitors' IPs, so the bot must see the visitor's
address and not your proxy's. It accepts an IP header only from
`TRUSTED_PROXIES` and ignores it from anyone else. If it gets a missing or
ambiguous value, it refuses to verify rather than guess. Pick the line that
matches your Cloudflare DNS record:

- **DNS only (grey cloud):** use `CLIENT_IP_HEADER=X-Real-IP`. NPM already
  sets this header to the connecting IP. The tradeoff is that your home IP is
  visible in DNS.
- **Proxied (orange cloud)**, the recommended option because it hides your home IP and absorbs
  attacks: NPM now sees Cloudflare's IPs, not visitors'. Either
  - use `CLIENT_IP_HEADER=CF-Connecting-IP` **and** configure your router or
    firewall so ports 80/443 accept connections only from
    [Cloudflare's IP ranges](https://www.cloudflare.com/ips/). Without that
    restriction, someone could connect to your home IP directly and send a
    fake `CF-Connecting-IP` to dodge alt detection; or
  - configure NPM to restore the real IP from Cloudflare and keep `X-Real-IP`.

**Test it before trusting it.** Verify one test account on home Wi-Fi and a
second on mobile data. They should not be flagged. Then verify a third
account on home Wi-Fi. It *should* be flagged as sharing a network with the
first. If every new person is flagged as matching everyone else, the bot is
seeing Cloudflare's or NPM's address, so fix the header settings.

### 5. Run it

```bash
docker compose up -d --build
docker compose logs -f   # look for "logged in as" and any setup errors
```

At startup the bot checks its own setup and logs plain-English errors for
common mistakes (role order, a dangerous verified role, a missing channel).

Once it's running, a bot admin can type **`/test-config`** anywhere in the
server. It privately shows a report of problems, warnings and passed checks:

- **Roles:** the Verified role is safe and assignable, the admin roles exist,
  and the bot doesn't have Administrator.
- **Channels:** the bot can post in the mod channel, the mod channel is
  hidden from `@everyone` and from verified members, and which channels
  unverified members can see.
- **Discord app settings:** Public Bot is off and, in web mode, the OAuth
  redirect is registered and the client secret is valid.
- **Database:** it can be written to.
- **Website (web mode):** the bot loads its own public page the way a
  member's browser would, checking DNS, HTTPS and Nginx Proxy Manager, and
  that visitor IPs are read correctly, including common Cloudflare mistakes.
  If your router doesn't support NAT loopback, this check can fail even
  though the site works. The report says so.

Fix anything listed under **Problems**, then type `/verification-panel` in
`#verify` to post the Verify button.

## Day to day

- **Held for review:** a message appears in the mod channel explaining why,
  with **Approve** and **Deny** buttons. Only bot admins can use them, and
  the bot checks that on every click.
- **Manually verifying someone:** an admin can skip all checks for a person
  they vouch for. Use `/verify-member member:@them note:why`, or right-click
  the member → **Apps → Verify member**. Only bot admins can do this. Every
  manual verification is posted to the mod log with the admin's name, and the
  admin is also named in Discord's audit log. If the person was waiting for
  review, that review closes.
- **Changing who's a bot admin:** edit `ADMIN_ROLE_IDS` in `.env`, then run
  `docker compose up -d`. Changes to *who holds* those roles take effect
  immediately, with no restart. Bot commands are visible to every member
  (non-admins get "Only bot admins can do that"). To hide them, go to **Server
  Settings → Integrations → HollowWarden**. That setting only controls
  visibility. Access is always decided by the bot.
- **Updating:** `git pull && docker compose up -d --build`.
- **Bot token leaked?** Reset it immediately in the developer portal,
  replace `secrets/discord_bot_token`, and run `docker compose up -d`.
- **Backups:** the `hollowwarden-data` volume holds the database, including
  IP hashes. Protect backups as carefully as the live data.

## Security design

| Risk | How HollowWarden handles it |
|---|---|
| Database leak exposes members' IPs | Raw IPs are never stored, only HMAC-SHA256 with a secret key. A plain hash would be reversible by hashing all ~4 billion IPv4 addresses; the key makes that impossible. Hashes are deleted after `IP_RETENTION_DAYS`, and SQLite `secure_delete` overwrites deleted rows. |
| Database leak exposes usable links | Verification tokens and OAuth states are stored only as SHA-256 hashes. They are single-use and expire within 10 minutes. |
| Someone shares their verification link, or an alt uses a friend's link | Links appear only in a private (ephemeral) Discord message. Finishing one requires logging in with Discord *as that same account*. |
| Login CSRF (tricking someone into completing a login the attacker started) | OAuth `state` is bound to the browser with a `__Host-` cookie that is Secure, HttpOnly and SameSite. It's single-use. |
| Visitor fakes their IP with a header | Headers are believed only from `TRUSTED_PROXIES`. Multi-value headers are rejected rather than parsed. |
| Token leaks to Discord through the Referer header | `Referrer-Policy: no-referrer`. |
| XSS, clickjacking, MIME sniffing | No JavaScript, everything escaped, a strict CSP (`default-src 'none'`, with the one stylesheet allowed by its hash), and `frame-ancestors 'none'`. |
| Secrets showing up in logs | Access logging is off. The bot never logs tokens, codes or IPs, and secrets are hidden from object reprs. |
| Brute force and floods | Per-IP limits on the website and per-user limits on the Verify button. The rate limiter's memory is capped. CAPTCHA allows 3 attempts. |
| Over-privileged bot | No privileged intents. Needs only Manage Roles plus messaging permissions. Refuses to grant a dangerous role. Leaves any server that isn't yours. Bot commands and review buttons check for your chosen admin roles in code on every use. `@everyone` and the Verified role can't be made admin roles. |
| Compromised container | Runs as a non-root user with a read-only filesystem, all Linux capabilities dropped, `no-new-privileges`, and memory and process limits. No published ports. Secrets are files, not environment variables. |
| Malicious or tampered dependency | Only three direct dependencies. All packages are pinned by version *and* hash (`--require-hashes`), and builds install wheels only. |

### Known limitations

- **VPNs and mobile data defeat IP matching.** A determined ban evader can
  verify from a different network. Alt detection catches the casual cases,
  which is most of them.
- **Households share an IP.** Siblings or roommates will be flagged as
  matching each other. That's why the default is `review`, not automatic denial.
- **Image CAPTCHAs can be solved by AI.** CAPTCHA mode stops scripted raid
  bots, not a determined human.
- **Tell your friends what's collected.** In web mode, the site records a
  one-way hash of the IP each person verifies from, for up to 180 days, to
  catch alt accounts. Being upfront about it is good practice and builds trust.

## Terms and privacy

- [Terms of Service](TERMS.md)
- [Privacy Policy](PRIVACY.md)

These describe what this bot actually does with its default settings. If you
change `IP_RETENTION_DAYS` or the logging limits in `docker-compose.yml`,
update the numbers in `PRIVACY.md` to match. The Discord developer portal
(**General Information**) has fields for a Terms of Service URL and a
Privacy Policy URL. You can paste the GitHub links to these files there.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest
```

To change dependencies, edit `requirements.in`, then regenerate the pins with
`pip-compile --generate-hashes --allow-unsafe --strip-extras requirements.in`.
Review what changed before committing.

Look and feel follows the Clipboard Cleaner design system: dark navy, flat,
one raspberry accent (`#e94560`), and outcome messages that begin with `✓` or
`⚠` followed by two spaces. Discord only has fixed button colours, so its red stands in
for the accent on the "go" buttons (Verify, Enter code). Approve and Deny are
both grey and differ by symbol, so a red button can't be mistaken for Deny.

Code style note: variables and functions use camelCase by project
convention. Methods that discord.py calls by name (`setup_hook`, `on_ready`,
`callback`, `on_submit`, `from_custom_id`) must stay snake_case.
