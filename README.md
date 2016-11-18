# sandboxed-tor-browser
### Yawning Angel (yawning at schwanenlied dot me)

> I would build a great sandbox.  And nobody builds sandboxes better than me,
> believe me.  I will build a great, great sandbox on our application border.
> And I will have Tor Browser pay for that sandbox.

Tor Browser sandboxed somewhat correctly using bubblewrap.  Obviously only
works on Linux, and will NEVER support anything else since sandboxing is OS
specific.

There are several unresolved issues that affect security and fingerprinting.
Do not assume that this is perfect, merely "an improvement over nothing".  If
you require strong security, consider combining the sandbox with something like
Qubes or Tails.

Runtime dependencies:

 * A modern Linux system on x86/x86_64 architecture (Tested on x86_64).
 * bubblewrap >= 0.1.2 (https://github.com/projectatomic/bubblewrap).  It is
   *STRONGLY* recommended that 0.1.3 or later is used.
 * libseccomp2 >= 2.2.1
 * Gtk+ 3.0
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

Upstream Bugs:

 * Tor Browser still shows update related UI elements.
   (https://bugs.torproject.org/20083)
 * HTTPS-Everywhere doesn't use Isolation properly at all, or honor SSL
   Observatory being disabled.
   (https://bugs.torproject.org/20195)

Notes:

 * Follows the XDG Base Dir specification.
 * Configuration via a JSON file.  No it's not documented.  Read the code.
 * Questions that could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
