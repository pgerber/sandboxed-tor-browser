# sandboxed-tor-browser
### Yanwnig Angel (yawning at schwanenlied dot me)

> I would build a great sandbox.  And nobody builds sandboxes better than me,
> believe me.  I will build a great, great sandbox on our application border.
> And I will have Tor Browser pay for that sandbox.

Tor Browser sandboxed somewhat correctly, requires bubblewrap and a system-wide
Tor instance.  Obviously only works on Linux, and will NEVER support anything
else.

Runtime dependencies:

 * A modern Linux system on x86/x86_64 architecture (Tested on x86_64).
 * tor running as a daemon with the SOCKS and control ports accessible
 * bubblewrap >= 0.1.2 (https://github.com/projectatomic/bubblewrap)
 * libseccomp2

Build time dependencies:

 * Make
 * A C compiler
 * gb (https://getgb.io/ Yes I know it's behind fucking cloudflare)
 * Go (Tested with 1.7.x)

Functionality intentionally broken with the sandbox:

 * Audio
 * DRI
 * X11 input methods (IBus requires access to the host D-Bus)
 * Installing addons via the browser UI.
 * Tor Browser's updater.
 * Tor Browser's circuit display.

Features:

 * Follows the XDG Base Dir specification.

 * Configuration via a TOML file.  No it's not documented.  Read the code.

 * Download and install Tor Browser.

   * Fetches and installs the latest Tor Browser over Tor.
   * Validates the PGP signature with a hard coded copy of the PGP key.

 * Update Tor Browser.

   * Version check over Tor on launch, validating the `dist.torproject.org`
     cert with an internal copy.
   * Download MAR format updates over Tor.
   * Validates the MAR signature with hard coded copies of the MAR signing
     key(s).
   * Apply the MAR updates using the `updater` excutable shipped with Tor,
     supporting both incremental and complete updates.  This process is in a
     sandbox that does not allow external network access at all.

 * Run a sandboxed instance of Tor Browser.

   * Assumes a system Tor instance.
   * Sandboxing based around bubblewrap.
   * A LD_PRELOAD stub is used to force firefox to use AF_LOCAL sockets for
     the control and SOCKS ports.  This will go away when all released channels
     of the browser support AF_LOCAL socket access.
   * Host filesystem access is minimalized to locations holding files required
     for Tor Browser to function, with read only access unless specified
     otherwise.  It is worth noting that the user's HOME directory is not
     exposed in the sandbox, only the `Downloads` directory.
     * System library directories.
     * Gtk Theme related directories.
     * The X11 AF_LOCAL socket directory in /tmp (.Xauthority is re-written to
       only expose credentials for the active display).
     * The browser directory.
     * The browser profile directory (read/write, extensions sub-dir read only).
     * The browser downloads directory (read/write)
     * A runtime directory.
       * Contains a surrogate control port that gives "fake" responses to Tor
         Browser.  Does not talk to the real control port.
       * A re-dispatching SOCKS proxy that allows "New Identity" to work, that
         talks to the system tor instance.

Sandbox weaknesses:

 * X11 is a huge mess of utter fail.  Since the sandboxed processes get direct
   access to the host X server, this is an exploitation vector.  Using a nested
   X solution "just works" assuming access control is setup, so that's a way to
   mitigate this for those that want that.
 * Firefox requires a `/proc` filesystem, which contains more information than
   it should have access to.
 * While the user name is re-written in the sandbox to `amnesia`, the UID/GID
   are not.
 * The Firefox process still can access the network over Tor to exfiltrate
   data.
 * The Firefox process can write bad things to the profile directory if it
   choses to do so.

Bugs:

 * Tor Browser still shows update related UI elements.
   (https://trac.torproject.org/projects/tor/ticket/20083)
 * The alpha/hardened bundles can't be installed.
   (https://bugs.torproject.org/19481 https://bugs.torproject.org/20180)

Notes:

 * It can take a while for the browser window to actually appear because it
   is checking for updates over Tor, and potentially installing/updating the
   bundle (also over Tor).
 * Yes, I'm serious about the license.  It's not ready to be used by the
   general public, no one should be re-distributing binaries, and no one
   should be making pre-compiled packages.
 * Unlike `tor-browser-launcher` there is no fancy GUI, and never will be.
 * Questions that could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
 * Really, just fuck off and leave me alone.  I'm making this available as an
   example of how something like this can work, and not because I want to talk
   to people about it.

