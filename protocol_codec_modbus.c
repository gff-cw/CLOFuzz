/* Bounded Modbus TCP codec for the supported FC01..06/0F/10 profile. */
#include "protocol_codecs.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MB_MAX_ADU 260u

static int mb_error(char *err, size_t cap, const char *msg) {
  if (err && cap) snprintf(err, cap, "%s", msg);
  return -1;
}

static unsigned mb_u16(const uint8_t *p) {
  return ((unsigned)p[0] << 8) | p[1];
}

static void mb_put16(uint8_t *p, size_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static int mb_function(unsigned f) {
  return (f >= 1 && f <= 6) || f == 15 || f == 16;
}

static int mb_exception(unsigned v) {
  return (v >= 1 && v <= 6) || v == 8 || v == 10 || v == 11;
}

/* Request and response packets share the wire function. There is deliberately
 * no connection/transaction inference here: validation accepts either shape. */
int pc_modbus_validate(const uint8_t *p, size_t n, char *err, size_t cap) {
  unsigned f, q, count;
  if (!p || n < 8 || n > MB_MAX_ADU)
    return mb_error(err, cap, "Modbus ADU size outside 8..260 bytes");
  if (mb_u16(p + 2)) return mb_error(err, cap, "Modbus protocol ID must be zero");
  if (mb_u16(p + 4) != n - 6)
    return mb_error(err, cap, "Modbus MBAP length mismatch");
  f = p[7];
  if (f & 0x80) {
    if (!mb_function(f & 0x7f) || n != 9 || !mb_exception(p[8]))
      return mb_error(err, cap, "Unsupported Modbus exception layout/code");
    return 0;
  }
  if (f >= 1 && f <= 4) {
    /* Exactly twelve bytes can be a read request, or a three-byte bit
     * response. With no direction argument this overlap cannot be resolved. */
    if (n == 12) {
      q = mb_u16(p + 10);
      if (q && q <= (f <= 2 ? 2000u : 125u)) return 0;
    }
    if (n < 10 || p[8] != n - 9 || p[8] > 250 ||
        ((f == 3 || f == 4) && (p[8] & 1)))
      return mb_error(err, cap, "Modbus read quantity/response byte count invalid");
    return 0;
  }
  if (f == 5 || f == 6) {
    if (n != 12) return mb_error(err, cap, "Modbus single-write size invalid");
    if (f == 5 && mb_u16(p + 10) != 0 && mb_u16(p + 10) != 0xff00)
      return mb_error(err, cap, "Modbus coil value must be 0000 or FF00");
    return 0;
  }
  if (f == 15 || f == 16) {
    if (n < 12) return mb_error(err, cap, "Truncated Modbus multiple-write body");
    q = mb_u16(p + 10);
    if (!q || q > (f == 15 ? 1968u : 123u))
      return mb_error(err, cap, "Modbus multiple-write quantity invalid");
    if (n == 12) return 0; /* Normal write acknowledgment. */
    count = f == 15 ? (q + 7) / 8 : q * 2;
    if (n < 14 || p[12] != count || n - 13 != count)
      return mb_error(err, cap, "Modbus multiple-write byte count mismatch");
    if (f == 15 && (q & 7) && (p[n - 1] >> (q & 7)))
      return mb_error(err, cap, "Modbus final coil byte has nonzero padding");
    return 0;
  }
  return mb_error(err, cap, "Unsupported Modbus function");
}

static int mb_abs(const char *s, size_t *off) {
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

int pc_modbus_field(const uint8_t *p, size_t n, const char *locator,
                    int type, size_t width, size_t *off, size_t *len,
                    char *err, size_t cap) {
  size_t at, size;
  unsigned f;
  if (pc_modbus_validate(p, n, err, cap)) return -1;
  if (!off || !len) return mb_error(err, cap, "Missing Modbus field output");
  if (!mb_abs(locator, &at)) return 0;
  if (type != PC_BYTES && type != PC_STRING) {
    if (type < PC_UINT8 || type > PC_UINT64 || !width) return 0;
    size = width;
  } else if (width) {
    size = width;
  } else {
    f = p[7];
    if (at == 13 && (f == 15 || f == 16) && n > 12)
      size = p[12];
    else if (at == 9 && f >= 1 && f <= 4 && n >= 10 && p[8] == n - 9)
      size = p[8];
    else return 0;
  }
  if (at > n || size > n - at)
    return mb_error(err, cap, "Modbus field extends beyond ADU");
  *off = at;
  *len = size;
  return 1;
}

int pc_modbus_repair(uint8_t *p, size_t n, char *err, size_t cap) {
  unsigned f, q;
  size_t count;
  if (!p || n < 8 || n > MB_MAX_ADU)
    return mb_error(err, cap, "Modbus repair ADU size invalid");
  f = p[7];
  mb_put16(p + 4, n - 6);
  if (f >= 1 && f <= 4 && n != 12 && n >= 9) {
    count = n - 9;
    if (count > 250 || !count || (f >= 3 && (count & 1)))
      return mb_error(err, cap, "Modbus read data size cannot be repaired");
    p[8] = (uint8_t)count;
  } else if ((f == 15 || f == 16) && n > 12) {
    count = n - 13;
    if (!count || count > 246 || (f == 16 && (count & 1)))
      return mb_error(err, cap, "Modbus multiple-write data size cannot be repaired");
    p[12] = (uint8_t)count;
    if (f == 16) {
      mb_put16(p + 10, count / 2);
    } else {
      q = mb_u16(p + 10);
      /* Preserve a partial final coil byte when the quantity still fits. */
      if (!q || q > 1968 || (q + 7) / 8 != count) q = (unsigned)count * 8;
      mb_put16(p + 10, q);
      if (q & 7) p[n - 1] &= (uint8_t)((1u << (q & 7)) - 1);
    }
  }
  return pc_modbus_validate(p, n, err, cap);
}

int pc_modbus_replace(uint8_t *p, size_t *n, size_t capacity,
                      const char *locator, int type, const uint8_t *value,
                      size_t size, char *err, size_t cap) {
  uint8_t tmp[MB_MAX_ADU];
  size_t off, old, next;
  unsigned f;
  int found;
  if (!p || !n || *n > capacity || (!value && size))
    return mb_error(err, cap, "Invalid Modbus replacement arguments");
  if (type != PC_BYTES && type != PC_STRING)
    return mb_error(err, cap, "Modbus replacement supports only data bytes");
  found = pc_modbus_field(p, *n, locator, type, 0, &off, &old, err, cap);
  if (found < 0) return -1;
  if (!found) return mb_error(err, cap, "Unsupported Modbus variable leaf");
  f = p[7];
  if (!size || size > (off == 13 ? 246u : 250u) ||
      ((f == 3 || f == 4 || f == 16) && (size & 1)))
    return mb_error(err, cap, "Modbus replacement data size invalid");
  next = *n - old + size;
  if (next > capacity || next > sizeof(tmp))
    return mb_error(err, cap, "Modbus replacement exceeds capacity");
  memcpy(tmp, p, off);
  memcpy(tmp + off, value, size);
  memcpy(tmp + off + size, p + off + old, *n - off - old);
  if (off == 9) tmp[8] = (uint8_t)size;
  if (pc_modbus_repair(tmp, next, err, cap)) return -1;
  memcpy(p, tmp, next);
  *n = next;
  return 0;
}

int pc_modbus_frame(const uint8_t *p, size_t n, size_t *size,
                    char *err, size_t cap) {
  size_t total;
  if (!size || (!p && n)) return mb_error(err, cap, "Invalid Modbus frame arguments");
  *size = 0;
  if (n < 6) return 0;
  if (mb_u16(p + 2)) return mb_error(err, cap, "Modbus frame protocol ID must be zero");
  total = mb_u16(p + 4);
  if (total < 2 || total > MB_MAX_ADU - 6)
    return mb_error(err, cap, "Modbus frame length invalid");
  total += 6;
  if (n < total) return 0;
  if (pc_modbus_validate(p, total, err, cap)) return -1;
  *size = total;
  return 1;
}

static unsigned mb_shapes(const uint8_t *p, size_t n) {
  unsigned f = p[7], shapes = 0;
  if (f >= 1 && f <= 4) {
    if (n == 12 && mb_u16(p + 10) &&
        mb_u16(p + 10) <= (f <= 2 ? 2000u : 125u)) shapes |= 1;
    if (n >= 10 && p[8] == n - 9 && p[8] <= 250 &&
        (f <= 2 || !(p[8] & 1))) shapes |= 2;
    return shapes;
  }
  if (f == 15 || f == 16) return n == 12 ? 2 : 1;
  return 3; /* Single-write request and echo response have identical layouts. */
}

int pc_modbus_same_kind(const uint8_t *p, size_t n,
                        const uint8_t *example, size_t example_n) {
  if (pc_modbus_validate(p, n, NULL, 0) ||
      pc_modbus_validate(example, example_n, NULL, 0)) return 0;
  /* The exception descriptor is generic across all supported functions. */
  if ((p[7] & 0x80) && (example[7] & 0x80)) return 1;
  return p[7] == example[7] &&
         (mb_shapes(p, n) & mb_shapes(example, example_n)) != 0;
}
