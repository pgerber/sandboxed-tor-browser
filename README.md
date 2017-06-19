# sandboxed-tor-browser
### Yawning Angel (yawning at schwanenlied dot me)

##### WARNING: Active development is on indefinite hiatus.

> I would build a great sandbox.  And nobody builds sandboxes better than me,
> believe me.  I will build a great, great sandbox on our application border.
> And I will have Tor Browser pay for that sandbox.

Tor Browser sandboxed somewhat correctly using bubblewrap.  Obviously only
works on Linux, and will NEVER support anything else since sandboxing is OS
specific.

There are several unresolved issues that affect security and fingerprinting.
Do not assume that this is perfect, merely "an improvement over nothing".

Runtime dependencies:

 * A modern Linux system on x86_64 architecture.
 * bubblewrap >= 0.1.3 (https://github.com/projectatomic/bubblewrap).
 * Gtk+ >= 3.14.0
 * (Optional) PulseAudio
 * (Optional) Adwaita Gtk+-2.0 theme
 * (Optional) libnotify and a Desktop Notification daemon

Build time dependencies:

 * Make
 * A C compiler
 * gb (https://getgb.io/ Yes I know it's behind fucking cloudflare)
 * Go (Tested with 1.7.x)
 * libnotify

Things that the sandbox breaks:

 * Audio (Unless allowed via the config)
 * DRI
 * X11 input methods (IBus requires access to the host D-Bus)
 * Installing addons via the browser UI (Unless allowed via the config)
 * Tor Browser's updater (launcher handles keeping the bundle up to date)

Places where the sandbox could be better:

 * More about the host system is exposed than neccecary, primarily because
   Firefox crashes without `/proc`.

Upstream Bugs:

 * Tor Browser should run without a `/proc` filesystem.
   (https://bugs.torproject.org/20283)
 * OpenGL software rendering is  broken on certain Linux systems.
   (https://bugs.torproject.org/20866)
 * On certain systems, Firefox crashes with an X11 error due to the lack of
   MIT-SHM support.  This appears to be a race condition, and still occurs
   despite mitigations. (https://bugzilla.mozilla.org/show_bug.cgi?id=1271100)

Notes:

 * Follows the XDG Base Dir specification.
 * Questions that could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
 * By default the sandbox `~/Desktop` and `~/Downloads` directories are mapped
   to the host `~/.local/share/sandboxed-tor-browser/tor-browser/Browser/[Desktop,Downloads]`
   directories.
 * https://git.schwanenlied.me/yawning/sandboxed-tor-browser/wiki has something
   resembling build instructions, that may or may not be up to date.
