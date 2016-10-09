# sandboxed-tor-browser
### Yanwnig Angel (yawning at schwanenlied dot me)

> I would build a great sandbox.  And nobody builds sandboxes better than me,
> believe me.  I will build a great, great sandbox on our application border.
> And I will have Tor Browser pay for that sandbox.

Tor Browser sandboxed somewhat correctly, requires bubblewrap and a system-wide
Tor instance.  Obviously only works on Linux, and will NEVER support anything
else since sandboxing is OS specific.

There are several unresolved issues that affect security and fingerprinting.
Do not assume that this is perfect, merely "an improvement over nothing".  If
you require strong security, consider combining the sandbox with something like
Qubes or Tails.

Runtime dependencies:

 * A modern Linux system on x86/x86_64 architecture (Tested on x86_64).
 * tor running as a daemon with the SOCKS and control ports accessible
 * bubblewrap >= 0.1.2 (https://github.com/projectatomic/bubblewrap)
 * libseccomp2
 * (Optional) PulseAudio

Build time dependencies:

 * Make
 * A C compiler
 * gb (https://getgb.io/ Yes I know it's behind fucking cloudflare)
 * Go (Tested with 1.7.x)

Things that the sandbox breaks:

 * Audio (Unless allowed via the config)
 * DRI
 * HTTPS-Everywhere's SSL Observatory (Upstream bug)
 * X11 input methods (IBus requires access to the host D-Bus)
 * Installing addons via the browser UI (Unless allowed via the config)
 * Tor Browser's updater (launcher handles keeping the bundle up to date)
 * Tor Browser's circuit display (Will be fixed)

Upstream Bugs:

 * Tor Browser still shows update related UI elements.
   (https://bugs.torproject.org/20083)
 * The alpha/hardened bundles can't be installed.
   (https://bugs.torproject.org/20219)
 * HTTPS-Everywhere doesn't use Isolation properly at all, or honor SSL
   Observatory being disabled.
   (https://bugs.torproject.org/20195)

Notes:

 * Follows the XDG Base Dir specification.
 * Configuration via a TOML file.  No it's not documented.  Read the code.
 * It can take a while for the browser window to actually appear because it
   is checking for updates over Tor, and potentially installing/updating the
   bundle (also over Tor).
 * Questions that could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
