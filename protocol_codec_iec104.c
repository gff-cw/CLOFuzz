/* Bounded IEC 60870-5-104 APCI and single-object interrogation profile. */
#include "protocol_codecs.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int ie_error(char *err, size_t cap, const char *msg) {
  if (err && cap) snprintf(err, cap, "%s", msg);
  return -1;
}

static int ie_u_control(unsigned c) {
  return c == 0x07 || c == 0x0b || c == 0x13 || c == 0x23 ||
         c == 0x43 || c == 0x83;
}

int pc_iec104_validate(const uint8_t *p, size_t n, char *err, size_t cap) {
  unsigned cause;
  if (!p || n < 6 || n > 255)
    return ie_error(err, cap, "IEC104 APDU size outside 6..255 bytes");
  if (p[0] != 0x68 || p[1] != n - 2)
    return ie_error(err, cap, "IEC104 start/length mismatch");
  if (!(p[2] & 1)) {
    if (p[4] & 1) return ie_error(err, cap, "IEC104 receive sequence bit zero must be clear");
    if (n != 16 || p[6] != 100 || p[7] != 1)
      return ie_error(err, cap, "IEC104 supports one C_IC_NA_1 object with SQ=0");
    cause = p[8] & 0x3f;
    if (cause != 6 && cause != 7 && cause != 10)
      return ie_error(err, cap, "IEC104 interrogation cause unsupported");
    if (p[12] || p[13] || p[14] || p[15] < 20 || p[15] > 36)
      return ie_error(err, cap, "IEC104 interrogation IOA/QOI invalid");
    return 0;
  }
  if (n != 6) return ie_error(err, cap, "IEC104 S/U frames must contain only APCI");
  if ((p[2] & 3) == 1) {
    if (p[2] != 1 || p[3] || (p[4] & 1))
      return ie_error(err, cap, "IEC104 S-format control/sequence invalid");
    return 0;
  }
  if (!ie_u_control(p[2]) || p[3] || p[4] || p[5])
    return ie_error(err, cap, "IEC104 U-format control invalid");
  return 0;
}

static int ie_abs(const char *s, size_t *off) {
  size_t v = 0;
  if (!s || strncmp(s, "abs:", 4) || !s[4]) return 0;
  for (s += 4; *s; ++s) {
    unsigned d = (unsigned char)*s - '0';
    if (d > 9 || v > (SIZE_MAX - d) / 10) return 0;
    v = v * 10 + d;
  }
  *off = v;
  return 1;
}

int pc_iec104_field(const uint8_t *p, size_t n, const char *locator,
                    int type, size_t width, size_t *off, size_t *len,
                    char *err, size_t cap) {
  size_t at;
  if (pc_iec104_validate(p, n, err, cap)) return -1;
  if (!off || !len) return ie_error(err, cap, "Missing IEC104 field output");
  if (!ie_abs(locator, &at)) return 0;
  /* This profile has only explicitly sized scalar fields, never a trailing
   * opaque ASDU field. A bytes locator must not absorb unrelated objects. */
  if (type < PC_UINT8 || type > PC_UINT64 || !width) return 0;
  if (at > n || width > n - at)
    return ie_error(err, cap, "IEC104 field extends beyond APDU");
  *off = at;
  *len = width;
  return 1;
}

int pc_iec104_repair(uint8_t *p, size_t n, char *err, size_t cap) {
  if (!p || n < 6 || n > 255)
    return ie_error(err, cap, "IEC104 repair APDU size invalid");
  p[1] = (uint8_t)(n - 2);
  if (n > 6) {
    if (n != 16 || p[6] != 100)
      return ie_error(err, cap, "IEC104 cannot repair unsupported ASDU layout");
    p[2] &= 0xfe; /* I-format: wire N(S) and N(R) are shifted by one. */
    p[4] &= 0xfe;
    p[7] = 1; /* Exactly one nonsequential interrogation object. */
  } else if ((p[2] & 3) == 1) {
    p[2] = 1;
    p[3] = 0;
    p[4] &= 0xfe;
  }
  return pc_iec104_validate(p, n, err, cap);
}

int pc_iec104_replace(uint8_t *p, size_t *n, size_t capacity,
                      const char *locator, int type, const uint8_t *value,
                      size_t size, char *err, size_t cap) {
  (void)p; (void)n; (void)capacity; (void)locator; (void)type;
  (void)value; (void)size;
  return ie_error(err, cap, "IEC104 profile has no supported variable leaf");
}

int pc_iec104_frame(const uint8_t *p, size_t n, size_t *size,
                    char *err, size_t cap) {
  size_t total;
  if (!size || (!p && n)) return ie_error(err, cap, "Invalid IEC104 frame arguments");
  *size = 0;
  if (!n) return 0;
  if (p[0] != 0x68) return ie_error(err, cap, "IEC104 frame start must be 68");
  if (n < 2) return 0;
  if (p[1] < 4 || p[1] > 253)
    return ie_error(err, cap, "IEC104 frame length outside 4..253");
  total = (size_t)p[1] + 2;
  if (n < total) return 0;
  if (pc_iec104_validate(p, total, err, cap)) return -1;
  *size = total;
  return 1;
}

int pc_iec104_same_kind(const uint8_t *p, size_t n,
                        const uint8_t *example, size_t example_n) {
  if (pc_iec104_validate(p, n, NULL, 0) ||
      pc_iec104_validate(example, example_n, NULL, 0)) return 0;
  if (!(p[2] & 1) && !(example[2] & 1))
    return p[6] == example[6] && (p[8] & 0x7f) == (example[8] & 0x7f);
  if ((p[2] & 3) == 1 && (example[2] & 3) == 1) return 1;
  return (p[2] & 3) == 3 && (example[2] & 3) == 3 && p[2] == example[2];
}
