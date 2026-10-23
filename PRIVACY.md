# HollowWarden Privacy Policy

**Effective date:** October 23, 2026

HollowWarden is a Discord bot that checks new members before they get access
to a private Discord server. It's run by that server's owner (the
**operator**) on the operator's own computer, not by a company. This policy
explains what the bot collects, why, how long it's kept, and who can see it.

In short: HollowWarden collects as little as it can, never stores your IP
address, never sells or shares your data for advertising, and deletes
everything it can on a schedule.

## 1. What HollowWarden collects

The server uses **one** of two verification methods. What's collected
depends on which one.

### Both methods

| Data | Why | How long it's kept |
|---|---|---|
| Your **Discord user ID** while you verify | To know who to give the Verified role to | A few minutes. CAPTCHA codes expire after 5 minutes and verification links after 10. |
| Your **account's creation date** | Accounts younger than a set number of days are held for review, to stop throwaway accounts | Never stored. It's calculated from your Discord ID each time. |
| A **pending review** (your Discord ID and the time) | If your verification is held, moderators need to approve or deny it | Until a moderator decides. Then it's deleted. |
| **Messages in the server's private moderator channel** | To tell moderators who verified, who was held and why, and any moderator decisions or notes | These are ordinary Discord messages. They stay until a moderator deletes them. |
| **Bot activity logs** on the operator's computer (Discord user IDs and what happened, e.g. "verified" or "held for review") | Troubleshooting and security | Logs are capped at about 30 MB, so older entries are overwritten automatically. |

Discord's own **audit log** also records when the bot gives you a role. That
record is kept by Discord under Discord's rules.

### Only if the server uses the web login method

| Data | Why | How long it's kept |
|---|---|---|
| A **one-way hash of your IP address**, linked to your Discord ID | To spot alternate accounts, and banned members coming back, that verify from the same internet connection | Deleted automatically **180 days** after it was last used, unless the operator sets a shorter or longer period |
| Your **IP address**, briefly | To hash it, and to check whether it belongs to a known VPN (see below) | Only while your request is being handled. It's never written to disk or kept in memory afterwards. Retry limits use the hash, which is kept in memory for about 10 to 20 minutes. |
| One **cookie** (`__Host-hw_nonce`) | Security: it makes sure the Discord login finishes in the same browser it started in | Up to 10 minutes. It's deleted as soon as you finish. |
| Your **Discord ID** from the "Log in with Discord" step | To confirm the person logging in is the person who clicked Verify | Used once, as above |
| **Whether you connected through a known VPN** (yes or no) | A VPN hides which network you're on, so a moderator takes a quick look instead | Not stored by the bot. If you're held for review, the moderator message says so (see section 3). |

**About the IP hash.** HollowWarden **never stores your IP address.** It
stores a keyed hash (HMAC-SHA256 with a secret key), which can't be turned
back into your IP address without that key. For IPv6, only the first half of
the address (the /64 network prefix) is used. That's the part that usually
identifies a household's connection rather than a single device.

**About the VPN check.** The bot compares your IP address against a public
list of IP ranges that belong to VPN services. The list is downloaded to the
operator's server, and **the check happens there**: your IP is never sent to
a VPN-detection service or anyone else. Downloading the list doesn't send
any information about you. If you're on a VPN, you're not blocked. A
moderator reviews your verification instead. The operator can turn this check
off.

**About the Discord login.** The bot asks Discord only for the `identify`
permission. That shows it your Discord ID and basic profile, but **not**
your email, your servers, your messages, or the ability to act as you. The
bot reads your ID, then immediately tells Discord to cancel the access it
was given. It never stores that access.

**About the cookie.** It's the only cookie, it's needed for security, and
it's not used for tracking or advertising.

## 2. What HollowWarden does *not* collect

- Your IP address (only the hash described above)
- Your email address, phone number, real name or location
- Your messages or the contents of any channel
- Your list of servers or friends
- Browser fingerprints, analytics or advertising trackers

## 3. Who can see your data

- **The server's moderators and admins** can see the moderator channel. If
  you're held for review, they'll see why, for example "account is 2 days old"
  or "verified from the same network as @someone" or "connected through a known
  VPN network". **This means moderators
  can learn that two accounts verified from the same internet connection**
  (say, siblings or roommates). They never see the IP address itself.
- **The operator** runs the computer the bot lives on, so they can access its
  database and logs.
- **Discord** handles the bot's messages, roles and login, under
  [Discord's Privacy Policy](https://discord.com/privacy).
- **Cloudflare**, if the operator uses it to protect the verification
  website, passes your connection through its network under
  [Cloudflare's Privacy Policy](https://www.cloudflare.com/privacypolicy/).

Nobody else. Your data is **never sold, rented or shared for advertising**,
and it's never used for anything except keeping the server safe.

## 4. Why it's used (legal basis)

If you're in the European Economic Area or the UK: HollowWarden processes
your data because it's in the **legitimate interest** of the server and its
members to keep out spam bots, raids, and people evading bans. It collects
only what that purpose needs and deletes it on a schedule.

## 5. How your data is protected

- The bot runs in a locked-down container on the operator's own hardware.
- It stores IP hashes instead of IP addresses, and the hashing key is kept
  separate from the database.
- Verification links work only once, expire quickly, and are stored only as
  hashes.
- The database is set to overwrite deleted data, not just mark it as
  deleted.
- The source code is public, so anyone can check that it does what this
  policy says: <https://github.com/Kingofhollows099/HollowWarden>.

No system is perfectly secure, but this one is built to hold as little as
possible, so there's little to lose if something goes wrong.

## 6. Your choices and rights

- **Don't want your IP hashed or checked?** Ask a server admin to verify you
  manually instead. Admins can let you in without running any checks.
- **See or delete your data.** Message a server admin or the operator
  directly. Please don't open a public GitHub issue for this, because that
  would make your request public. The operator will tell you what's stored
  about you and delete it if you ask. Data that's needed to enforce an active
  ban may be kept for as long as the ban applies.
- **Leaving the server** doesn't automatically delete anything, but your IP
  hash still expires on schedule (see section 1).

## 7. Age

You must meet Discord's minimum age requirement to use Discord, and so to
use HollowWarden. The bot doesn't knowingly collect data from anyone below
that age.

## 8. Changes to this policy

If this policy changes, the new version will be posted in the GitHub
repository with a new effective date. Its full history is visible there. If
a change significantly affects how your data is used, it will also be
announced in the server.

## 9. Contact

For questions or requests, message the server's admins on Discord. For
questions about the code itself, open an issue at
<https://github.com/Kingofhollows099/HollowWarden/issues>, but never include
personal information in an issue.
