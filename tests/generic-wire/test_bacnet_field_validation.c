#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol_runtime.h"

/* Forward declare internal access for inspecting and narrowing model bounds */
#define PMAX 128
#define FMAX 64
#define DMAX 128
typedef struct { char id[64], loc[64]; uint64_t min, max, values[32]; int nv, width, role, mut, little, type, strategies; } pf;
typedef struct { int op, target, source, message, unit, add, algorithm, multiply; } pd;
typedef struct { char id[64]; pf f[FMAX]; pd d[DMAX]; int nf, nd, weight, response; uint8_t *example; size_t size; } pm;
struct proto_engine_internal {
  void *generic;
  int codec, simulating, prefix_state, prefix_valid;
  size_t prefix_count, prefix_bytes;
  size_t prefix_repeats[PMAX];
  pm m[PMAX];
  int nm, ns, nt, initial, max_messages, max_repeat, canonical[PMAX];
  size_t max_bytes;
};

static uint32_t scripted_rng(uint32_t limit) {
  /* Simple deterministic selector: alternate between 0 and limit-1 */
  static uint32_t counter = 0;
  if (!limit) return 0;
  return (counter++) % limit;
}

int main(void) {
  printf("[*] Testing P13 BACnet custom codec field constraint validation...\n");

  char err[512] = {0};
  proto_engine *e = proto_load("protocols/bacnet_ip/protocol_ir.json",
                               "protocols/bacnet_ip/state_ir.json",
                               err, sizeof(err));
  if (!e) {
    fprintf(stderr, "Failed to load BACnet IR: %s\n", err);
    assert(e != NULL);
  }

  struct proto_engine_internal *ei = (struct proto_engine_internal *)e;

  /* Find who_is and read_property models */
  int who_is_idx = -1;
  int rp_idx = -1;
  for (int i = 0; i < ei->nm; i++) {
    if (!strcmp(ei->m[i].id, "who_is")) who_is_idx = i;
    if (!strcmp(ei->m[i].id, "read_property")) rp_idx = i;
  }
  assert(who_is_idx >= 0 && rp_idx >= 0);

  /* Find fields within who_is */
  int who_is_ctrl_idx = -1;
  int who_is_limits_idx = -1;
  for (int f = 0; f < ei->m[who_is_idx].nf; f++) {
    if (!strcmp(ei->m[who_is_idx].f[f].id, "npdu_control")) who_is_ctrl_idx = f;
    if (!strcmp(ei->m[who_is_idx].f[f].id, "limits")) who_is_limits_idx = f;
  }
  assert(who_is_ctrl_idx >= 0 && who_is_limits_idx >= 0);

  /* 1. Valid packets pass proto_validate_message_fields */
  const uint8_t valid_who_is_no_limits[] = {
    0x81, 0x0a, 0x00, 0x08, /* BVLC: type 0x81, func 10, len 8 */
    0x01, 0x00,             /* NPDU: ver 1, control 0 */
    0x10, 0x08              /* APDU: unconfirmed who-is (service 8) */
  };

  const uint8_t valid_who_is_with_limits[] = {
    0x81, 0x0a, 0x00, 0x10, /* BVLC: type 0x81, func 10, len 16 */
    0x01, 0x00,             /* NPDU: ver 1, control 0 */
    0x10, 0x08,             /* APDU: unconfirmed who-is (service 8) */
    0x0b, 0x00, 0x00, 0x01, /* tag 0 (low limit): 1 */
    0x1b, 0x00, 0x00, 0x02  /* tag 1 (high limit): 2 */
  };

  const uint8_t valid_read_property[] = {
    0x81, 0x0a, 0x00, 0x11, /* BVLC: type 0x81, func 10, len 17 */
    0x01, 0x04,             /* NPDU: ver 1, control 4 (expecting reply) */
    0x00, 0x05, 0x01, 0x0c, /* APDU: confirmed, max_apdu=5, invoke=1, service=12 */
    0x0c, 0x02, 0x00, 0x00, 0x01, /* Object ID: Device, 1 */
    0x19, 0x4b              /* Property ID: 75 (Object_Name) */
  };

  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_no_limits,
                                       sizeof(valid_who_is_no_limits), err, sizeof(err)) == 0);
  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_with_limits,
                                       sizeof(valid_who_is_with_limits), err, sizeof(err)) == 0);
  assert(proto_validate_message_fields(e, rp_idx, valid_read_property,
                                       sizeof(valid_read_property), err, sizeof(err)) == 0);

  /* 2. Narrowed npdu.control bounds verification */
  /* Save original bounds */
  uint64_t orig_ctrl_min = ei->m[who_is_idx].f[who_is_ctrl_idx].min;
  uint64_t orig_ctrl_max = ei->m[who_is_idx].f[who_is_ctrl_idx].max;

  /* Narrow control bounds to [0, 0] */
  ei->m[who_is_idx].f[who_is_ctrl_idx].min = 0;
  ei->m[who_is_idx].f[who_is_ctrl_idx].max = 0;

  /* Packet with control = 4 must be rejected */
  uint8_t bad_ctrl_who_is[sizeof(valid_who_is_no_limits)];
  memcpy(bad_ctrl_who_is, valid_who_is_no_limits, sizeof(valid_who_is_no_limits));
  bad_ctrl_who_is[5] = 0x04; /* NPDU control = 4 */

  assert(proto_validate_message_fields(e, who_is_idx, bad_ctrl_who_is,
                                       sizeof(bad_ctrl_who_is), err, sizeof(err)) < 0);
  assert(strstr(err, "outside bounds") != NULL);

  /* 3. Narrowed Who-Is limits variable length verification */
  uint64_t orig_limits_min = ei->m[who_is_idx].f[who_is_limits_idx].min;
  uint64_t orig_limits_max = ei->m[who_is_idx].f[who_is_limits_idx].max;

  /* a) Narrow limits to [8, 8] (mandatory limits) */
  ei->m[who_is_idx].f[who_is_limits_idx].min = 8;
  ei->m[who_is_idx].f[who_is_limits_idx].max = 8;

  /* Who-Is without limits has length 0, must be rejected */
  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_no_limits,
                                       sizeof(valid_who_is_no_limits), err, sizeof(err)) < 0);
  assert(strstr(err, "length 0 outside bounds [8, 8]") != NULL);

  /* Who-Is with 8-byte limits must pass */
  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_with_limits,
                                       sizeof(valid_who_is_with_limits), err, sizeof(err)) == 0);

  /* b) Narrow limits to [0, 0] (forbidden limits) */
  ei->m[who_is_idx].f[who_is_limits_idx].min = 0;
  ei->m[who_is_idx].f[who_is_limits_idx].max = 0;

  /* Who-Is with 8-byte limits must now be rejected */
  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_with_limits,
                                       sizeof(valid_who_is_with_limits), err, sizeof(err)) < 0);
  assert(strstr(err, "length 8 outside bounds [0, 0]") != NULL);

  /* Who-Is without limits must pass */
  assert(proto_validate_message_fields(e, who_is_idx, valid_who_is_no_limits,
                                       sizeof(valid_who_is_no_limits), err, sizeof(err)) == 0);

  /* Restore limits bounds */
  ei->m[who_is_idx].f[who_is_limits_idx].min = orig_limits_min;
  ei->m[who_is_idx].f[who_is_limits_idx].max = orig_limits_max;
  ei->m[who_is_idx].f[who_is_ctrl_idx].min = orig_ctrl_min;
  ei->m[who_is_idx].f[who_is_ctrl_idx].max = orig_ctrl_max;

  /* 4. Verify proto_mutate respects narrowed Who-Is limits and does not bypass */
  /* Encode record with LE32 length prefix */
  uint8_t records[128];
  records[0] = sizeof(valid_who_is_no_limits);
  records[1] = 0; records[2] = 0; records[3] = 0;
  memcpy(records + 4, valid_who_is_no_limits, sizeof(valid_who_is_no_limits));
  size_t rec_len = 4 + sizeof(valid_who_is_no_limits);

  /* AFL candidate with plenty of bytes */
  uint8_t afl_candidate[64];
  memset(afl_candidate, 0x11, sizeof(afl_candidate));

  /* Narrow limits to [8, 8] */
  ei->m[who_is_idx].f[who_is_limits_idx].min = 8;
  ei->m[who_is_idx].f[who_is_limits_idx].max = 8;

  const uint8_t *mut_out = NULL;
  size_t mut_out_len = 0;

  /* Mutate CONTENT layer */
  int status = proto_mutate(e, records, rec_len, afl_candidate, sizeof(afl_candidate),
                            PROTO_VALID, PROTO_CONTENT, scripted_rng,
                            &mut_out, &mut_out_len, err, sizeof(err));
  assert(status == 0);
  assert(mut_out != NULL && mut_out_len > 0);

  /* The resulting mutated message must have 8-byte limits (total size 16 + 4 = 20) */
  assert(mut_out_len == 4 + 16);
  assert(proto_validate_message_fields(e, who_is_idx, mut_out + 4, 16, err, sizeof(err)) == 0);

  /* Now narrow limits to [0, 0] on an input that currently has 8-byte limits */
  ei->m[who_is_idx].f[who_is_limits_idx].min = 0;
  ei->m[who_is_idx].f[who_is_limits_idx].max = 0;

  records[0] = sizeof(valid_who_is_with_limits);
  records[1] = 0; records[2] = 0; records[3] = 0;
  memcpy(records + 4, valid_who_is_with_limits, sizeof(valid_who_is_with_limits));
  rec_len = 4 + sizeof(valid_who_is_with_limits);

  status = proto_mutate(e, records, rec_len, afl_candidate, sizeof(afl_candidate),
                        PROTO_VALID, PROTO_CONTENT, scripted_rng,
                        &mut_out, &mut_out_len, err, sizeof(err));
  assert(status == 0);
  assert(mut_out != NULL);
  /* Mutated message must have resized to 0-byte limits (total size 8 + 4 = 12) */
  assert(mut_out_len == 4 + 8);
  assert(proto_validate_message_fields(e, who_is_idx, mut_out + 4, 8, err, sizeof(err)) == 0);

  /* Restore limits bounds */
  ei->m[who_is_idx].f[who_is_limits_idx].min = orig_limits_min;
  ei->m[who_is_idx].f[who_is_limits_idx].max = orig_limits_max;

  /* 5. Verify proto_before_send rejects packets violating field bounds */
  proto_session_begin(e);

  /* Narrow npdu_control on ReadProperty to [4, 4] */
  int rp_ctrl_idx = -1;
  for (int f = 0; f < ei->m[rp_idx].nf; f++) {
    if (!strcmp(ei->m[rp_idx].f[f].id, "npdu_control")) rp_ctrl_idx = f;
  }
  assert(rp_ctrl_idx >= 0);
  ei->m[rp_idx].f[rp_ctrl_idx].min = 4;
  ei->m[rp_idx].f[rp_ctrl_idx].max = 4;

  uint8_t send_buf[sizeof(valid_read_property)];
  memcpy(send_buf, valid_read_property, sizeof(valid_read_property));

  /* Control = 4 is valid */
  assert(proto_before_send(e, send_buf, sizeof(send_buf), err, sizeof(err)) == 0);

  /* Now set control = 0 in packet (violates [4, 4]) */
  memcpy(send_buf, valid_read_property, sizeof(valid_read_property));
  send_buf[5] = 0x00;
  uint8_t backup[sizeof(send_buf)];
  memcpy(backup, send_buf, sizeof(send_buf));

  assert(proto_before_send(e, send_buf, sizeof(send_buf), err, sizeof(err)) < 0);
  /* Original wire buffer must be preserved untouched */
  assert(memcmp(send_buf, backup, sizeof(send_buf)) == 0);

  proto_free(e);

  printf("[+] P13 BACnet custom codec field constraint validation tests passed successfully!\n");
  return 0;
}
