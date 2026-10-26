/* Bounded RFC1006 / ISO session / BER codec for the captured MMS profile. */
#include "protocol_codecs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MMS_NODES 256
#define MMS_DEPTH 32
#define MMS_MAX 65535u

typedef struct {
  size_t off, content, len, end, length_off, length_width;
  int parent;
  unsigned tag;
} mms_node;
typedef struct {
  const uint8_t *wire;
  size_t size, presentation, session_end;
  size_t session_body, session_length, session_width;
  size_t user_tag, user_length, user_width;
  int association, kind, count, root, context, initiate, result, invoke;
  int domain, item, data;
  mms_node nodes[MMS_NODES];
  char *error;
  size_t error_size;
} mms_view;

static int mms_error(mms_view *v, const char *message) {
  if (v->error && v->error_size) snprintf(v->error, v->error_size, "%s", message);
  return -1;
}
static int mms_fail(char *error, size_t size, const char *message) {
  if (error && size) snprintf(error, size, "%s", message);
  return -1;
}

/* ISO session uses FF + a 16-bit length, unlike BER's length encoding. */
static int mms_iso_length(mms_view *v, size_t *at, size_t *length,
                          size_t *width) {
  size_t p = *at;
  if (p >= v->size) return mms_error(v, "missing ISO session length");
  *length = v->wire[p++]; *width = 1;
  if (*length == 255) {
    if (v->size - p < 2) return mms_error(v, "truncated ISO session length");
    *length = ((size_t)v->wire[p] << 8) | v->wire[p + 1];
    p += 2; *width = 3;
  }
  *at = p;
  return 0;
}

static int mms_ber_node(mms_view *v, size_t *at, size_t limit, int parent,
                        unsigned depth, int root_override) {
  size_t p = *at, length, width = 1, i;
  int index;
  mms_node *node;
  if (depth > MMS_DEPTH || v->count == MMS_NODES)
    return mms_error(v, "MMS BER nesting/node limit");
  if (p >= limit || limit - p < 2) return mms_error(v, "truncated BER header");
  index = v->count++; node = &v->nodes[index];
  node->off = p; node->tag = v->wire[p++]; node->parent = parent;
  if ((node->tag & 31) == 31) return mms_error(v, "BER high tag outside MMS profile");
  node->length_off = p; length = v->wire[p++];
  if (length & 128) {
    size_t octets = length & 127;
    if (!octets || octets > 4 || octets > limit - p)
      return mms_error(v, "invalid definite BER length");
    width += octets; length = 0;
    for (i = 0; i < octets; ++i) length = (length << 8) | v->wire[p++];
  }
  node->length_width = width; node->content = p;
  if (root_override) length = limit - p;
  if (length > limit - p) return mms_error(v, "truncated BER content");
  node->len = length; node->end = p + length;
  if (node->tag == 2 && (!length || length > 5))
    return mms_error(v, "invalid BER INTEGER width");
  if (node->tag & 32) {
    while (p < node->end)
      if (mms_ber_node(v, &p, node->end, index, depth + 1, 0) < 0) return -1;
  }
  *at = node->end;
  return index;
}

static int mms_children(const mms_view *v, int parent) {
  int i, count = 0;
  if (parent < 0) return 0;
  for (i = parent + 1; i < v->count; ++i) if (v->nodes[i].parent == parent) ++count;
  return count;
}
static int mms_nth(const mms_view *v, int parent, unsigned nth) {
  int i;
  if (parent < 0) return -1;
  for (i = parent + 1; i < v->count; ++i)
    if (v->nodes[i].parent == parent && !nth--) return i;
  return -1;
}
static int mms_child(const mms_view *v, int parent, unsigned tag) {
  int i, found = -1;
  if (parent < 0) return -1;
  for (i = parent + 1; i < v->count; ++i) if (v->nodes[i].parent == parent && v->nodes[i].tag == tag) {
    if (found >= 0) return -1;
    found = i;
  }
  return found;
}
static int mms_tag(const mms_view *v, int node, unsigned tag) {
  return node >= 0 && v->nodes[node].tag == tag;
}
static int mms_unsigned(const mms_view *v, int node, uint32_t *value) {
  size_t i;
  uint32_t result = 0;
  const mms_node *n;
  if (node < 0) return 0;
  n = &v->nodes[node];
  if (!n->len || n->len > 5 || (v->wire[n->content] & 128) ||
      (n->len == 5 && v->wire[n->content])) return 0;
  for (i = 0; i < n->len; ++i) result = (result << 8) | v->wire[n->content + i];
  if (value) *value = result;
  return 1;
}
static int mms_is_uint(const mms_view *v, int node, uint32_t value) {
  uint32_t actual;
  return mms_unsigned(v, node, &actual) && actual == value;
}
static int mms_bytes(const mms_view *v, int node, const uint8_t *bytes, size_t n) {
  return node >= 0 && v->nodes[node].len == n &&
         (!n || !memcmp(v->wire + v->nodes[node].content, bytes, n));
}
static int mms_visible(const mms_view *v, int node, int nonempty) {
  size_t i;
  if (node < 0 || (nonempty && !v->nodes[node].len)) return 0;
  for (i = 0; i < v->nodes[node].len; ++i) {
    unsigned ch = v->wire[v->nodes[node].content + i];
    if (ch < 32 || ch > 126) return 0;
  }
  return 1;
}

static int mms_semantics(mms_view *v) {
  static const uint8_t app_context[] = {0x28, 0xca, 0x22, 0x02, 0x03};
  int root = v->root, normal, data, pdv, payload, pdu, service, response;
  int a, b, c, i;
  uint32_t context;
  if (v->nodes[root].tag == 0x31) {
    if (!v->association || !mms_is_uint(v, mms_child(v, mms_child(v, root, 0xa0), 0x80), 1))
      return mms_error(v, "invalid normal-mode presentation association");
    normal = mms_child(v, root, 0xa2); data = mms_child(v, normal, 0x61);
  } else {
    if (v->association || !mms_tag(v, root, 0x61)) return mms_error(v, "invalid presentation PDU");
    data = root;
  }
  pdv = mms_child(v, data, 0x30);
  v->context = mms_child(v, pdv, 2);
  payload = mms_child(v, pdv, 0xa0);
  if (!mms_unsigned(v, v->context, &context) || mms_children(v, data) != 1 ||
      mms_children(v, pdv) != 2 || mms_children(v, payload) != 1)
    return mms_error(v, "invalid presentation context/PDV list");
  pdu = mms_nth(v, payload, 0);
  if (v->association) {
    response = v->wire[7] == 0x0e;
    if (context != 1 || !mms_tag(v, pdu, response ? 0x61 : 0x60) ||
        !mms_bytes(v, mms_child(v, mms_child(v, pdu, 0xa1), 6), app_context, sizeof(app_context)))
      return mms_error(v, "invalid MMS ACSE application context");
    if (response) {
      v->result = mms_child(v, mms_child(v, pdu, 0xa2), 2);
      if (!mms_is_uint(v, v->result, 0)) return mms_error(v, "unsupported ACSE association result");
    }
    a = mms_child(v, mms_child(v, pdu, 0xbe), 0x28);
    if (!mms_is_uint(v, mms_child(v, a, 2), 3)) return mms_error(v, "invalid MMS EXTERNAL indirect reference");
    v->initiate = mms_child(v, mms_child(v, a, 0xa0), response ? 0xa9 : 0xa8);
    if (v->initiate < 0) return mms_error(v, "missing MMS initiate PDU");
    for (i = 0x80; i <= 0x83; ++i)
      if (!mms_unsigned(v, mms_child(v, v->initiate, (unsigned)i), NULL))
        return mms_error(v, "invalid MMS initiate scalar");
    a = mms_child(v, v->initiate, 0xa4);
    if (!mms_is_uint(v, mms_child(v, a, 0x80), 1)) return mms_error(v, "unsupported MMS version");
    for (i = 0x81; i <= 0x82; ++i) {
      b = mms_child(v, a, (unsigned)i);
      if (b < 0 || v->nodes[b].len < 2 || v->wire[v->nodes[b].content] > 7)
        return mms_error(v, "invalid MMS initiate BIT STRING");
      c = v->wire[v->nodes[b].content];
      if (c && (v->wire[v->nodes[b].end - 1] & ((1u << c) - 1)))
        return mms_error(v, "invalid MMS initiate BIT STRING padding");
    }
    v->kind = 0x100 + response;
    return 0;
  }
  if (v->wire[7] == 9 || v->wire[7] == 10) {
    response = v->wire[7] == 10;
    if (context != 1 || !mms_tag(v, pdu, response ? 0x63 : 0x62) ||
        (!response && !mms_is_uint(v, mms_child(v, pdu, 0x80), 0)))
      return mms_error(v, "invalid ACSE release");
    if (mms_children(v, pdu) != (response ? 0 : 1)) return mms_error(v, "unsupported ACSE release content");
    v->kind = 0x200 + response;
    return 0;
  }
  if (context != 3) return mms_error(v, "invalid MMS presentation context");
  if (v->nodes[pdu].tag == 0x8b || v->nodes[pdu].tag == 0x8c) {
    if (v->nodes[pdu].len) return mms_error(v, "invalid MMS conclude content");
    v->kind = 0x300 + (int)v->nodes[pdu].tag;
    return 0;
  }
  if (!mms_tag(v, pdu, 0xa0) && !mms_tag(v, pdu, 0xa1))
    return mms_error(v, "unsupported MMS PDU choice");
  response = v->nodes[pdu].tag == 0xa1;
  v->invoke = mms_child(v, pdu, 2);
  if (!mms_unsigned(v, v->invoke, NULL) || mms_children(v, pdu) != 2)
    return mms_error(v, "invalid MMS invoke ID");
  service = mms_nth(v, pdu, 1);
  if (service < 0 || (v->nodes[service].tag != 0xa1 && v->nodes[service].tag != 0xa4 && v->nodes[service].tag != 0xa5))
    return mms_error(v, "unsupported MMS confirmed service");
  v->kind = 0x400 + (response << 8) + (int)v->nodes[service].tag;
  if (v->nodes[service].tag == 0xa1) {
    a = mms_child(v, service, 0xa0);
    if (response) {
      b = mms_child(v, service, 0x81);
      if (a < 0 || b < 0 || v->nodes[b].len != 1 ||
          (v->wire[v->nodes[b].content] != 0 && v->wire[v->nodes[b].content] != 255))
        return mms_error(v, "invalid GetNameList response");
      for (i = a + 1; i < v->count; ++i) if (v->nodes[i].parent == a &&
          (!mms_tag(v, i, 0x1a) || !mms_visible(v, i, 0)))
        return mms_error(v, "invalid GetNameList identifier");
    } else if (!mms_is_uint(v, mms_child(v, a, 0x80), 9) ||
               !mms_bytes(v, mms_child(v, mms_child(v, service, 0xa1), 0x80), NULL, 0))
      return mms_error(v, "unsupported GetNameList scope");
  } else if (!response) {
    if (v->nodes[service].tag == 0xa4) a = mms_child(v, mms_child(v, service, 0xa1), 0xa0);
    else a = mms_nth(v, service, 0);
    b = mms_nth(v, a, 0);
    if (!mms_tag(v, a, 0xa0) || mms_children(v, a) != 1 || !mms_tag(v, b, 0x30))
      return mms_error(v, "unsupported MMS variable access");
    a = mms_child(v, mms_child(v, b, 0xa0), 0xa1);
    v->domain = mms_nth(v, a, 0); v->item = mms_nth(v, a, 1);
    if (a < 0 || mms_children(v, a) != 2 || !mms_tag(v, v->domain, 0x1a) ||
        !mms_tag(v, v->item, 0x1a) || !mms_visible(v, v->domain, 1) || !mms_visible(v, v->item, 1))
      return mms_error(v, "invalid MMS domain/item identifiers");
    if (v->nodes[service].tag == 0xa5) {
      a = mms_nth(v, service, 1); v->data = mms_nth(v, a, 0);
      if (mms_children(v, service) != 2 || !mms_tag(v, a, 0xa0) ||
          mms_children(v, a) != 1 || !mms_tag(v, v->data, 0x8a) || !mms_visible(v, v->data, 0))
        return mms_error(v, "unsupported MMS Write data");
    }
  } else if (v->nodes[service].tag == 0xa4) {
    a = mms_child(v, service, 0xa1);
    if (a < 0 || !mms_children(v, a)) return mms_error(v, "missing MMS Read result");
    for (i = a + 1; i < v->count; ++i) if (v->nodes[i].parent == a) {
      unsigned t = v->nodes[i].tag;
      if (t != 0x80 && t != 0x83 && t != 0x85 && t != 0x86 && t != 0x87 && t != 0x89 && t != 0x8a && t != 0x91)
        return mms_error(v, "unsupported MMS Read result choice");
      if (t == 0x8a && !mms_visible(v, i, 0)) return mms_error(v, "invalid MMS Read string");
    }
  } else {
    if (!mms_children(v, service)) return mms_error(v, "missing MMS Write result");
    for (i = service + 1; i < v->count; ++i) if (v->nodes[i].parent == service &&
        (v->nodes[i].tag != 0x80 && (v->nodes[i].tag != 0x81 || v->nodes[i].len)))
      return mms_error(v, "invalid MMS Write result choice");
  }
  return 0;
}

static int mms_parse(mms_view *v, const uint8_t *wire, size_t size,
                     int repair, char *error, size_t error_size) {
  size_t p, length, width, q, param_length, param_width;
  unsigned seen = 0;
  memset(v, 0, sizeof(*v)); v->wire = wire; v->size = size;
  v->error = error; v->error_size = error_size;
  v->root = v->context = v->initiate = v->result = v->invoke = v->domain = v->item = v->data = -1;
  if (!wire || size < 7 || size > MMS_MAX || wire[0] != 3 || wire[1] ||
      (!repair && (((size_t)wire[2] << 8) | wire[3]) != size))
    return mms_error(v, "invalid complete TPKT record");
  if (wire[5] == 0xe0 || wire[5] == 0xd0) {
    if (size < 11 || size > 260 || (!repair && (size_t)wire[4] + 5 != size) || wire[10])
      return mms_error(v, "invalid COTP connection header");
    p = 11;
    while (p < size) {
      unsigned tag;
      if (size - p < 2) return mms_error(v, "truncated COTP parameter");
      tag = wire[p++]; length = wire[p++];
      if (length > size - p) return mms_error(v, "truncated COTP parameter value");
      if (tag == 0xc0) {
        if ((seen & 1) || length != 1 || wire[p] < 7 || wire[p] > 16) return mms_error(v, "invalid COTP TPDU size");
        seen |= 1;
      } else if (tag == 0xc1 || tag == 0xc2) {
        unsigned bit = tag == 0xc1 ? 2u : 4u;
        if ((seen & bit) || !length || length > 32) return mms_error(v, "invalid COTP TSAP parameter");
        seen |= bit;
      } else return mms_error(v, "unsupported COTP parameter");
      p += length;
    }
    if (seen != 7) return mms_error(v, "missing COTP connection parameter");
    v->kind = (int)wire[5];
    return 0;
  }
  if (wire[4] != 2 || wire[5] != 0xf0 || wire[6] != 0x80 || size < 11)
    return mms_error(v, "invalid complete COTP data TPDU");
  if (!memcmp(wire + 7, "\x01\x00\x01\x00", 4)) {
    v->presentation = 11; v->session_end = 11;
  } else {
    unsigned spdu = wire[7];
    if (spdu != 13 && spdu != 14 && spdu != 9 && spdu != 10)
      return mms_error(v, "unsupported ISO session SPDU");
    v->association = spdu == 13 || spdu == 14;
    p = 8; v->session_length = p;
    if (mms_iso_length(v, &p, &length, &width) < 0) return -1;
    v->session_width = width; v->session_body = p;
    if (!repair && length != size - p) return mms_error(v, "ISO session SPDU length mismatch");
    while (p < size) {
      unsigned tag = wire[p++], bit;
      q = p;
      if (mms_iso_length(v, &p, &param_length, &param_width) < 0) return -1;
      if (tag == 0xc1) {
        if (!repair && param_length != size - p) return mms_error(v, "ISO user-data length mismatch");
        v->user_tag = q - 1; v->user_length = q; v->user_width = param_width;
        v->presentation = p; v->session_end = p; seen |= 1;
        break;
      }
      if (param_length > size - p) return mms_error(v, "truncated ISO session parameter");
      if (!v->association) return mms_error(v, "unsupported release session parameter");
      if (tag == 5) {
        static const uint8_t negotiation[] = {0x13,1,0,0x16,1,2};
        bit = 2;
        if (param_length != sizeof(negotiation) || memcmp(wire + p, negotiation, sizeof(negotiation)))
          return mms_error(v, "invalid ISO session negotiation");
      } else if (tag == 0x14) {
        bit = 4;
        if (param_length != 2 || wire[p] || wire[p + 1] != 2) return mms_error(v, "invalid ISO session requirements");
      } else if (tag == 0x33 || tag == 0x34) {
        bit = tag == 0x33 ? 8u : 16u;
        if (!param_length || param_length > 32) return mms_error(v, "invalid ISO session selector");
      } else return mms_error(v, "unsupported ISO session parameter");
      if (seen & bit) return mms_error(v, "duplicate ISO session parameter");
      seen |= bit; p += param_length;
    }
    if (!(seen & 1) || (v->association && (seen & 6) != 6)) return mms_error(v, "missing ISO session parameter");
  }
  p = v->presentation;
  v->root = mms_ber_node(v, &p, size, -1, 0, repair);
  if (v->root < 0) return -1;
  if (p != size) return mms_error(v, "trailing presentation BER data");
  return mms_semantics(v);
}

int pc_mms_validate(const uint8_t *wire, size_t size, char *error, size_t error_size) {
  mms_view v;
  return mms_parse(&v, wire, size, 0, error, error_size);
}

static int mms_locator(const mms_view *v, const char *locator) {
  if (!strcmp(locator, "ber:presentation.context")) return v->context;
  if (!strcmp(locator, "ber:mms.invoke")) return v->invoke;
  if (!strcmp(locator, "ber:mms.domain")) return v->domain;
  if (!strcmp(locator, "ber:mms.item")) return v->item;
  if (!strcmp(locator, "ber:mms.data")) return v->data;
  if (!strcmp(locator, "ber:acse.result")) return v->result;
  if (!strcmp(locator, "ber:initiate.calling")) return mms_child(v, v->initiate, 0x81);
  if (!strcmp(locator, "ber:initiate.called")) return mms_child(v, v->initiate, 0x82);
  if (!strcmp(locator, "ber:initiate.nesting")) return mms_child(v, v->initiate, 0x83);
  if (!strcmp(locator, "ber:initiate.version")) return mms_child(v, mms_child(v, v->initiate, 0xa4), 0x80);
  return -1;
}

static int mms_locator_type(const char *locator) {
  if (!strcmp(locator, "ber:mms.domain") || !strcmp(locator, "ber:mms.item") ||
      !strcmp(locator, "ber:mms.data")) return PC_STRING;
  if (!strcmp(locator, "ber:mms.invoke")) return PC_UINT32;
  if (!strcmp(locator, "ber:initiate.calling") || !strcmp(locator, "ber:initiate.called")) return PC_UINT16;
  return PC_UINT8;
}

int pc_mms_field(const uint8_t *wire, size_t size, const char *locator,
                 int type, size_t width, size_t *offset, size_t *length,
                 char *error, size_t error_size) {
  mms_view v;
  int node;
  if (mms_parse(&v, wire, size, 0, error, error_size) < 0) return -1;
  if (!locator || !offset || !length) return mms_fail(error, error_size, "invalid MMS field arguments");
  if (!strncmp(locator, "abs:", 4)) {
    const char *p = locator + 4;
    size_t at = 0;
    if (!*p) return mms_fail(error, error_size, "invalid absolute locator");
    for (; *p; ++p) {
      if (*p < '0' || *p > '9' || at > (SIZE_MAX - 9) / 10) return mms_fail(error, error_size, "invalid absolute locator");
      at = at * 10 + (unsigned)(*p - '0');
    }
    if (at > size) return 0;
    *offset = at; *length = type >= PC_BYTES ? size - at : width;
    if (*length > size - at) return 0;
    return 1;
  }
  if (!strcmp(locator, "iso:session")) {
    if (!v.presentation || type != PC_BYTES) return 0;
    *offset = 7; *length = v.session_end - 7; return 1;
  }
  if (!strcmp(locator, "ber:presentation")) {
    if (v.root < 0 || type != PC_BER_TLV) return 0;
    *offset = v.presentation; *length = size - v.presentation; return 1;
  }
  node = mms_locator(&v, locator);
  if (node < 0 || type != mms_locator_type(locator)) return 0;
  *offset = v.nodes[node].content; *length = v.nodes[node].len;
  return 1;
}

static int mms_write_length(uint8_t *at, size_t width, size_t length, int iso) {
  size_t i;
  if (width == 1) {
    if (length > (iso ? 254u : 127u)) return -1;
    at[0] = (uint8_t)length; return 0;
  }
  if (iso) {
    if (width != 3 || length > 65535) return -1;
    at[0] = 255; at[1] = (uint8_t)(length >> 8); at[2] = (uint8_t)length;
    return 0;
  }
  if (width < 2 || width > 5 || (width < 5 && length >= ((size_t)1 << ((width - 1) * 8)))) return -1;
  at[0] = (uint8_t)(128 + width - 1);
  for (i = width - 1; i; --i) { at[i] = (uint8_t)length; length >>= 8; }
  return 0;
}

int pc_mms_repair(uint8_t *wire, size_t size, char *error, size_t error_size) {
  mms_view v;
  if (mms_parse(&v, wire, size, 1, error, error_size) < 0) return -1;
  if (v.root >= 0) {
    mms_node *root = &v.nodes[v.root];
    if (mms_write_length(wire + root->length_off, root->length_width, root->len, 0) < 0)
      return mms_fail(error, error_size, "BER repair requires header resize");
    if (v.user_tag) {
      if (mms_write_length(wire + v.session_length, v.session_width, size - v.session_body, 1) < 0 ||
          mms_write_length(wire + v.user_length, v.user_width, size - v.presentation, 1) < 0)
        return mms_fail(error, error_size, "ISO session repair requires header resize");
    }
  } else wire[4] = (uint8_t)(size - 5);
  wire[2] = (uint8_t)(size >> 8); wire[3] = (uint8_t)size;
  return pc_mms_validate(wire, size, error, error_size);
}

static size_t mms_ber_width(size_t n) { return n < 128 ? 1 : n < 256 ? 2 : 3; }
static size_t mms_iso_width(size_t n) { return n < 255 ? 1 : 3; }

static size_t mms_encoded_size(const mms_view *v, int index, int target,
                               size_t replacement, size_t *contents) {
  size_t n = 0;
  int i;
  if (index == target) n = replacement;
  else if (!(v->nodes[index].tag & 32)) n = v->nodes[index].len;
  else for (i = index + 1; i < v->count; ++i) if (v->nodes[i].parent == index) {
    size_t child = mms_encoded_size(v, i, target, replacement, contents);
    if (child > MMS_MAX || n > MMS_MAX - child) return MMS_MAX + 1u;
    n += child;
  }
  if (n > MMS_MAX) return MMS_MAX + 1u;
  contents[index] = n;
  return 1 + mms_ber_width(n) + n;
}

static void mms_emit(const mms_view *v, int index, int target,
                      const uint8_t *replacement, size_t replacement_size,
                      const size_t *contents, uint8_t *out, size_t *at) {
  const mms_node *node = &v->nodes[index];
  size_t width = mms_ber_width(contents[index]);
  int i;
  out[(*at)++] = (uint8_t)node->tag;
  (void)mms_write_length(out + *at, width, contents[index], 0); *at += width;
  if (index == target) { if (replacement_size) memcpy(out + *at, replacement, replacement_size); *at += replacement_size; }
  else if (!(node->tag & 32)) { memcpy(out + *at, v->wire + node->content, node->len); *at += node->len; }
  else for (i = index + 1; i < v->count; ++i) if (v->nodes[i].parent == index)
    mms_emit(v, i, target, replacement, replacement_size, contents, out, at);
}

int pc_mms_replace(uint8_t *wire, size_t *size, size_t capacity,
                   const char *locator, int type, const uint8_t *replacement,
                   size_t replacement_size, char *error, size_t error_size) {
  mms_view v;
  size_t contents[MMS_NODES], presentation_size, body_size = 0, new_size, at;
  uint8_t *out;
  int target;
  if (!size || !locator || (replacement_size && !replacement) || replacement_size > MMS_MAX)
    return mms_fail(error, error_size, "invalid MMS replacement arguments");
  if (*size > capacity) return mms_fail(error, error_size, "MMS replacement input exceeds capacity");
  if (mms_parse(&v, wire, *size, 0, error, error_size) < 0) return -1;
  target = mms_locator(&v, locator);
  if (target < 0 || (v.nodes[target].tag & 32) || type != mms_locator_type(locator))
    return mms_fail(error, error_size, "MMS replacement requires a supported leaf locator");
  presentation_size = mms_encoded_size(&v, v.root, target, replacement_size, contents);
  if (presentation_size > MMS_MAX) return mms_fail(error, error_size, "MMS replacement too large");
  if (v.user_tag) {
    body_size = v.user_tag - v.session_body + 1 + mms_iso_width(presentation_size) + presentation_size;
    new_size = 8 + mms_iso_width(body_size) + body_size;
  } else new_size = 11 + presentation_size;
  if (new_size > MMS_MAX || new_size > capacity) return mms_fail(error, error_size, "MMS replacement exceeds capacity");
  out = malloc(new_size);
  if (!out) return mms_fail(error, error_size, "MMS replacement allocation failed");
  memcpy(out, wire, 7); at = 7;
  if (v.user_tag) {
    size_t prefix = v.user_tag - v.session_body, width = mms_iso_width(body_size);
    out[at++] = wire[7]; (void)mms_write_length(out + at, width, body_size, 1); at += width;
    memcpy(out + at, wire + v.session_body, prefix); at += prefix;
    out[at++] = 0xc1; width = mms_iso_width(presentation_size);
    (void)mms_write_length(out + at, width, presentation_size, 1); at += width;
  } else { memcpy(out + at, wire + 7, 4); at += 4; }
  mms_emit(&v, v.root, target, replacement, replacement_size, contents, out, &at);
  out[2] = (uint8_t)(at >> 8); out[3] = (uint8_t)at;
  if (at != new_size || pc_mms_validate(out, at, error, error_size) < 0) { free(out); return -1; }
  memcpy(wire, out, at); *size = at; free(out);
  return 0;
}

int pc_mms_frame(const uint8_t *wire, size_t size, size_t *frame_size,
                 char *error, size_t error_size) {
  size_t length;
  if (frame_size) *frame_size = 0;
  if ((!wire && size) || !frame_size) return mms_fail(error, error_size, "invalid MMS framing arguments");
  if ((size && wire[0] != 3) || (size > 1 && wire[1])) return mms_fail(error, error_size, "invalid TPKT framing prefix");
  if (size < 4) return 0;
  length = ((size_t)wire[2] << 8) | wire[3];
  if (length < 7) return mms_fail(error, error_size, "invalid TPKT frame length");
  if (size < length) return 0;
  if (pc_mms_validate(wire, length, error, error_size) < 0) return -1;
  *frame_size = length;
  return 1;
}

int pc_mms_same_kind(const uint8_t *wire, size_t size, const uint8_t *example, size_t example_size) {
  mms_view a, b;
  return !mms_parse(&a, wire, size, 0, NULL, 0) &&
         !mms_parse(&b, example, example_size, 0, NULL, 0) && a.kind == b.kind;
}
