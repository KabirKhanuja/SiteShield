1. A website health check. Is your HTTPS set up properly? Is the certificate valid? Does your site send the security settings browsers expect?
2. An email spoofing check. Can someone send fake emails pretending to be your domain?
3. An "is anything leaking" check. Are private files like .env or .git, or debug pages, publicly reachable? Are secret keys visible in your site's JavaScript?
4. A brute-force check. Can someone try thousands of passwords on your login page without being blocked?
5. A basic attack test. Does your site react to simple, harmless XSS/SQL-injection test inputs? This only runs after you prove you own the site.
6. An outdated software check. Are you running a framework version with publicly known vulnerabilities?
7. A library check. Do any packages you installed have known security holes?
8. A code check. Are there passwords or API keys in your code, dangerous functions, sloppy settings, or shortcuts that AI coding tools commonly leave behind?
9. Proof, not guesses. When a problem shows up in both the code and the live site, it's marked confirmed, so you know what's real and what to fix first.
10. One grade (A–F). A single, easy-to-read security score for the whole app.
11. Fixes you can copy-paste. Each problem comes with exact code or config written for your setup (Next.js, Express, Vercel, nginx…), not just "fix this."
12. Fix verification. Re-scan after fixing and see before vs. after, what's fixed and what's still broken.
13. Safety built in. It won't run any attack-style test on a site until you prove you own it.
14. Three ways to use it. A website dashboard, a command-line tool (npx siteshield scan), or an automatic check in GitHub that blocks bad code from being merged.