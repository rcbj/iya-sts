/*
 * File: spiffe/native/peercred.c
 *
 * ---------------------------------------------------------------------------
 * THE KERNEL'S VIEW OF A UNIX SOCKET PEER, FOR SPIFFE WORKLOAD ATTESTATION
 * (#40 phase four, 2026-09-21).
 *
 * Node has no API for SO_PEERCRED: `net.Socket` exposes none and
 * /proc/net/unix does not record the peer. A SPIRE agent reads it to learn
 * WHICH PROCESS is calling its Workload API, and every workload selector
 * (`unix:uid:…`, `docker:label:…`, `k8s:pod-name:…`) follows from that pid.
 * rcbj's decision on #40 was this: a small N-API addon, compiled only inside
 * an image build (`build-native.sh`), never on the host, and no general
 * foreign-function interface in the process.
 *
 * FIVE FUNCTIONS, AND NOTHING ELSE:
 *
 *   peerCred(fd)      getsockopt(SO_PEERCRED): { pid, uid, gid } as the
 *                     kernel recorded them when the peer connected. pid is 0
 *                     for a peer in a pid namespace this process cannot see.
 *   peerPidfd(fd)     getsockopt(SO_PEERPIDFD), Linux 6.5+: a pidfd for the
 *                     peer taken by the kernel AT CONNECT, which no pid reuse
 *                     can redirect. -1 where the kernel has no such option.
 *   pidfdOpen(pid)    pidfd_open(2), Linux 5.3+: the fallback, taken as soon
 *                     after accept as this process can. -1 on failure.
 *   pidfdAlive(pidfd) pidfd_send_signal(pidfd, 0): is the process the pidfd
 *                     names still running? A pid read from /proc is only
 *                     trusted when this answers yes AFTER the read.
 *   closeFd(fd)       close(2), for the pidfds above.
 *
 * It is N-API (node_api.h) and nothing more, so one build serves every Node
 * version the image carries, and it holds no state.
 * ---------------------------------------------------------------------------
 */
#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

/* One integer argument, or -1 (with a thrown TypeError) when there is none. */
static int int_arg(napi_env env, napi_callback_info info, int32_t *out) {
  size_t argc = 1;
  napi_value argv[1];
  napi_valuetype type;
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok ||
      argc < 1 || napi_typeof(env, argv[0], &type) != napi_ok ||
      type != napi_number ||
      napi_get_value_int32(env, argv[0], out) != napi_ok) {
    napi_throw_type_error(env, NULL, "expected one integer argument");
    return -1;
  }
  return 0;
}

static napi_value make_int(napi_env env, int64_t value) {
  napi_value out;
  napi_create_int64(env, value, &out);
  return out;
}

static napi_value peer_cred(napi_env env, napi_callback_info info) {
  int32_t fd;
  struct ucred cred;
  socklen_t len = sizeof(cred);
  napi_value result;
  if (int_arg(env, info, &fd) != 0) return NULL;
  memset(&cred, 0, sizeof(cred));
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    napi_throw_error(env, "EPEERCRED", strerror(errno));
    return NULL;
  }
  napi_create_object(env, &result);
  napi_set_named_property(env, result, "pid", make_int(env, cred.pid));
  napi_set_named_property(env, result, "uid", make_int(env, cred.uid));
  napi_set_named_property(env, result, "gid", make_int(env, cred.gid));
  return result;
}

static napi_value peer_pidfd(napi_env env, napi_callback_info info) {
  int32_t fd;
  int pidfd = -1;
  socklen_t len = sizeof(pidfd);
  if (int_arg(env, info, &fd) != 0) return NULL;
  if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) != 0) {
    pidfd = -1;
  }
  return make_int(env, pidfd);
}

static napi_value pidfd_open(napi_env env, napi_callback_info info) {
  int32_t pid;
  long pidfd;
  if (int_arg(env, info, &pid) != 0) return NULL;
  if (pid <= 0) return make_int(env, -1);
  pidfd = syscall(SYS_pidfd_open, (pid_t)pid, 0);
  return make_int(env, pidfd < 0 ? -1 : pidfd);
}

static napi_value pidfd_alive(napi_env env, napi_callback_info info) {
  int32_t pidfd;
  napi_value result;
  if (int_arg(env, info, &pidfd) != 0) return NULL;
  napi_get_boolean(env, pidfd >= 0 &&
                   syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == 0,
                   &result);
  return result;
}

static napi_value close_fd(napi_env env, napi_callback_info info) {
  int32_t fd;
  if (int_arg(env, info, &fd) != 0) return NULL;
  if (fd >= 0) close(fd);
  return NULL;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
    { "peerCred", NULL, peer_cred, NULL, NULL, NULL, napi_enumerable, NULL },
    { "peerPidfd", NULL, peer_pidfd, NULL, NULL, NULL, napi_enumerable, NULL },
    { "pidfdOpen", NULL, pidfd_open, NULL, NULL, NULL, napi_enumerable, NULL },
    { "pidfdAlive", NULL, pidfd_alive, NULL, NULL, NULL, napi_enumerable, NULL },
    { "closeFd", NULL, close_fd, NULL, NULL, NULL, napi_enumerable, NULL }
  };
  napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]),
                         props);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
