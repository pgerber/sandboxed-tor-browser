# sandboxed-bor-browser
### Yanwing Angel (yawning at schwanenlied dot me)

Tor Browser sandboxed somewhat correctly, requires bubblewrap and a system-wide
Tor instance.  Obviously only works on Linux, and will NEVER support anything
else.

Dependencies:

 * A modern Linux system on x86_64 architecture.
 * tor running as a daemon with the SOCKS and control ports accessible.
 * libseccomp2
 * bubblewrap >= 0.1.2 (https://github.com/projectatomic/bubblewrap)
 * Go (Tested with 1.7.x build time only)
 * gb (https://getgb.io/ build time only, fuck cloudflare)
 * A C compiler (build time only)
 * Make (build time only)

Broken functionality:

 * Audio
 * DRI
 * Tor Browser UI update related UI elements should be hidden/disabled, but
   can't be..  (https://trac.torproject.org/projects/tor/ticket/20083)

Notes:

 * Yes, I'm serious about the license.  It's not ready to be used by the
   general public, no one should be re-distributing binaries, and no one
   should be making pre-compiled packages.
 * Unlike `tor-browser-launcher` there is no fancy GUI, and never will be.
 * Questions that are could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
 * Really, just fuck off and leave me alone.  I'm making this available as an
   example of how something like this can work, and not because I want to talk
   to people about it.

