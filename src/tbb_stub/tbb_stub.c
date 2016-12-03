/**
 * tbb_stub.c: AF_LOCAL-ify Tor Browser.
 * Copyright (C) 2016  Yawning Angel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is a minimal stub intended to be loaded with LD_PRELOAD that attempts
 * to force Firefox to use AF_LOCAL (aka AF_UNIX) sockets, so people that want
 * to deny external network access with a sandboxing mechanism can do so.
 *
 * In an ideal world Firefox will have support for accessing proxies over
 * AF_LOCAL in mainline.  I am told this will happen sooner or later but:
 *  * I didn't feel like waiting.
 *  * My eyes glazed over when I looked at the Firefox networking code.
 *
 * WARNINGS:
 *  * This does not attempt to prevent other methods of creating sockets,
 *    so if you are using this outside of the scope of a sandboxing
 *    solution, you are doing something horribly wrong.
 *  * If the app you are preloading this into is not Tor Browser, you are
 *    doing something wrong, and probably want torsocks instead.
 *  * If you can't figure out how to compile this, fuck off and leave me alone.
 */

#define _GNU_SOURCE /* Fuck *BSD and Macintoys. */

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>

#ifndef __i386__
#include <glob.h>
#include <stdbool.h>
#endif

static pthread_once_t stub_init_once = PTHREAD_ONCE_INIT;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_socket)(int, int, int) = NULL;
static void *(*real_dlopen)(const char *, int) = NULL;
static Bool (*real_XQueryExtension)(Display*, _Xconst char*, int*, int*, int*) = NULL;
static struct sockaddr_un socks_addr;
static struct sockaddr_un control_addr;


#define SYSTEM_SOCKS_PORT 9050
#define SYSTEM_CONTROL_PORT 9051
#define TBB_SOCKS_PORT 9150
#define TBB_CONTROL_PORT 9151


static void stub_init(void);

int
connect(int fd, const struct sockaddr *address, socklen_t address_len)
{
  struct sockaddr *replaced_addr = NULL;
  struct sockaddr_in *in_addr = NULL;

  if (address == NULL || address_len < sizeof(struct sockaddr)) {
    errno = EINVAL;
    return -1;
  }

  pthread_once(&stub_init_once, stub_init);

  /* Fast path for non-outgoing sockets. */
  if (address->sa_family == AF_LOCAL) {
    return real_connect(fd, address, address_len);
  }

  /* Unless something really goofy is going on, we should only ever have
   * AF_LOCAL or AF_INET sockets.  Enforce this.
   */
  if (address->sa_family != AF_INET || address_len < sizeof(struct sockaddr_in)) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  /* Demultiplex based on port.  In an ideal world, this should be
   * TOR_[SOCKS,CONTROL]_PORT based, but I'm lazy and they're both totally
   * arbitrary and only used to demux, so fuck it, whatever.
   */
  in_addr = (struct sockaddr_in*)address;

  switch (ntohs(in_addr->sin_port)) {
    case SYSTEM_SOCKS_PORT: /* FALLSTHROUGH */
    case TBB_SOCKS_PORT:
      replaced_addr = (struct sockaddr *)&socks_addr;
      break;
    case SYSTEM_CONTROL_PORT: /* FALLSTHROUGH */
    case TBB_CONTROL_PORT:
      replaced_addr = (struct sockaddr *)&control_addr;
      break;
    default:
      errno = EHOSTUNREACH;
      return -1;
  }

  return real_connect(fd, replaced_addr, sizeof(struct sockaddr_un));
}

int
socket(int domain, int type, int protocol)
{
  pthread_once(&stub_init_once, stub_init);

  /* Replace AF_INET with AF_LOCAL. */
  if (domain == AF_INET)
    domain = AF_LOCAL;

  /* Only allow AF_LOCAL (aka AF_UNIX) sockets to be constructed. */
  if (domain != AF_LOCAL) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  return real_socket(domain, type, protocol);
}

static int
has_prefix(const char *a, const char *b) {
  return strncmp(a, b, strlen(b)) == 0;
}

void *
dlopen(const char *filename, int flags)
{
  void *ret;
  pthread_once(&stub_init_once, stub_init);

  if (filename != NULL) {
    if (has_prefix(filename, "libgnomeui"))
      return NULL;
    if (has_prefix(filename, "libgconf"))
      return NULL;
  }

  ret = real_dlopen(filename, flags);
#if 0
  /* This is useful for debugging the internal/dynlib package. */
  if (ret == NULL)
    fprintf(stderr, "tbb_stub: dlopen('%s', %d) returned NULL\n", filename, flags);
#endif
  return ret;
}

Bool
XQueryExtension(Display *display, _Xconst char *name, int *major, int *event, int *error) {
  pthread_once(&stub_init_once, stub_init);

  if (!strcmp(name, "MIT-SHM")) {
    *major = 0;
    return False;
  }

  return real_XQueryExtension(display, name, major, event, error);
}

#ifndef __i386__

typedef struct pa_mutex pm;
static pm* (*real_pa_mutex_new)(bool, bool);

static char *
glob_library(const char *lib_glob) {
  glob_t gb;
  char *lib = NULL;
  size_t i;

  if (glob(lib_glob, GLOB_MARK, NULL, &gb) != 0) {
    return NULL;
  }

  for (i = 0; i < gb.gl_pathc; i++) {
    const char *path = gb.gl_pathv[i];
    size_t plen = strlen(path);

    if (plen > 0 && path[plen] != '/') {
      lib = strndup(path, plen);
      break;
    }
  }

  globfree(&gb);

  return lib;
}

/* There are rumors that PI futexes have scary race conditions, that enable
 * an exploit that is being sold by the forces of darkness.  On systems where
 * we can filter futex kernel args, we reject such calls.
 *
 * However this breaks PulseAudio, because PI futex usage is determined at
 * compile time.  This fixes up the mutex creation call, to never request PI
 * mutexes.
 *
 * Thanks to the unnamed reporter who filed the issues on the tails, bug
 * tracker and chatted with me on IRC about it.
 * See: https://labs.riseup.net/code/issues/11524
 *
 * Note: This could be enabled unconditionally (ie: also on x86), but since
 * that platform doesn't filter syscalls by argument due to seccomp-bpf
 * limitations, it seems somewhat pointless.
 */
pm *
pa_mutex_new(bool recursive, bool inherit_priority) {
  (void) inherit_priority;

  pthread_once(&stub_init_once, stub_init);

  if (real_pa_mutex_new == NULL) {
    void *handle;
    char *lib;

    if ((lib = glob_library("/usr/lib/pulseaudio/libpulsecore-*.so")) == NULL) {
      fprintf(stderr, "ERROR: Failed to find `libpulsecore-*.so`");
      abort();
    }

    if ((handle = real_dlopen(lib, RTLD_LAZY|RTLD_LOCAL)) == NULL) {
      fprintf(stderr, "ERROR: Failed to dlopen() libpulsecore.so: %s\n", dlerror());
      abort();
    }
    free(lib);

    if ((real_pa_mutex_new = dlsym(handle, "pa_mutex_new")) == NULL) {
      fprintf(stderr, "ERROR: Failed to find `pa_mutex_new()` symbol: %s\n", dlerror());
      abort();
    }
    dlclose(handle);
  }
  return real_pa_mutex_new(recursive, false);
}

#endif

/*  Initialize the stub. */
static void
stub_init(void)
{
  char *socks_path = secure_getenv("TOR_STUB_SOCKS_SOCKET");
  char *control_path = secure_getenv("TOR_STUB_CONTROL_SOCKET");
  size_t dest_len = sizeof(socks_addr.sun_path);
  void *handle = NULL;

  /* If `TOR_STUB_SOCKS_SOCKET` isn't set, bail. */
  if (socks_path == NULL) {
    fprintf(stderr, "ERROR: `TOR_STUB_SOCKS_SOCKET` enviornment variable not set.\n");
    goto out;
  }

  /* If `TOR_STUB_CONTROL_SOCKET` isn't set, bail. */
  if (control_path == NULL) {
    fprintf(stderr, "ERROR: `TOR_STUB_CONTROL_SOCKET` enviornment variable not set.\n");
    goto out;
  }

  /* Find the real symbols so we can call into libc after proccesing. */
  if ((real_connect = dlsym(RTLD_NEXT, "connect")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `connect()` symbol: %s\n", dlerror());
    goto out;
  }
  if ((real_socket = dlsym(RTLD_NEXT, "socket")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `socket()` symbol: %s\n", dlerror());
    goto out;
  }

  /* Initialize the SOCKS target address. */
  socks_addr.sun_family = AF_LOCAL;
  strncpy(socks_addr.sun_path, socks_path, dest_len);
  socks_addr.sun_path[dest_len-1] = '\0';

  /* Initialize the Control target address. */
  control_addr.sun_family = AF_LOCAL;
  strncpy(control_addr.sun_path, control_path, dest_len);
  control_addr.sun_path[dest_len-1] = '\0';

  /* Tor Browser is built with GNOME integration, which is loaded dynamically
   * via dlopen().  This is fine and all, except that Firefox's idea of
   * handling "GMOME libraries present but the services are not running", is
   * to throw up a dialog box.
   *
   * There isn't a good way to fix this except via either rebuilding Firefox
   * or making the dlopen() call fail somehow.
   */
  if ((real_dlopen = dlsym(RTLD_NEXT, "dlopen")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find 'dlopen()' symbol: %s\n", dlerror());
    goto out;
  }

  /* Firefox does not degrade gracefully when "MIT-SHM" fails.
   *
   * See: https://bugzilla.mozilla.org/show_bug.cgi?id=1271100#c20
   */
  if ((handle = real_dlopen("libXext.so.6", RTLD_LAZY)) == NULL) {
    fprintf(stderr, "ERROR: Failed to dlopen() libXext.so: %s\n", dlerror());
    goto out;
  }
  if ((real_XQueryExtension = dlsym(handle, "XQueryExtension")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `XQueryExtension()` symbol: %s\n", dlerror());
    goto out;
  }

  return;

out:
  abort();
}
