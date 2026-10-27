/* Description-only wire trees. No protocol names, codec dispatch or scripts. */
#ifndef STATEAFL_GENERIC_WIRE_H
#define STATEAFL_GENERIC_WIRE_H
#include "native_json.h"
#include <stddef.h>
#include <stdint.h>

#define GW_MAX_WIRE (1024u * 1024u)
typedef struct gw_schema gw_schema;
typedef struct gw_packet gw_packet;
typedef uint32_t (*gw_random)(uint32_t limit);

/* Grammar: struct fields have unique ids. uint widths are 1..8 bytes with
 * explicit big/little byte_order. bytes length is an integer, final "rest", or
 * {"ref":"earlier_uint","add":signed_integer}; add defaults to zero.
 * A derived uint uses {"op":"size_of","target":"field_id"|"$message",
 * "add":signed_integer}. Its target may precede or follow it; size_of counts
 * encoded bytes, not the target integer's value. All bounds are inclusive.
 * The compiled schema owns its field definitions; grammar JSON may be freed
 * after compilation. A schema must outlive its parsed packets. Packets own
 * their tree and input-byte snapshot. */
gw_schema *gw_compile(const nj_value *grammar, char *error, size_t cap);
void gw_free(gw_schema *schema);
int gw_parse(const gw_schema *schema, const uint8_t *wire, size_t length,
             gw_packet **out, char *error, size_t cap);
void gw_packet_free(gw_packet *packet);

/* Encode into caller storage; failure leaves output and packet unchanged and
 * sets *length=0. capacity may exceed GW_MAX_WIRE; encoded size may not.
 * Derived values and offsets are recomputed. The packet keeps its original
 * input ranges for CONTENT projection until it is freed. */
int gw_encode(gw_packet *packet, uint8_t *out, size_t capacity, size_t *length,
              char *error, size_t cap);
/* layer 1 HEAD: enum/boundary/bitflip/arithmetic on declared uints.
 * layer 2 CONTENT: project candidate bytes at the original field range;
 * rest bytes, or bytes referring to a derived uint, may resize within min/max
 * when all dependencies remain valid. Candidate size changes are assigned to
 * the selected leaf, reserving the original suffix length; bytes above max
 * are clipped. Other fields retain their values. Original projection ranges
 * persist across successful edits; gw_field_range reports current ranges.
 * Other layers rejected.
 * On failure packet is unchanged. Successful edits are validated by encode
 * and by parsing the result through this same schema before committing. */
int gw_mutate(gw_packet *packet, int layer, const uint8_t *candidate,
              size_t candidate_length, gw_random random, char *error, size_t cap);
int gw_get_u64(const gw_packet *packet, const char *id, uint64_t *value);
/* Sets a non-fixed scalar; encoding later checks/recomputes all dependencies.
 * Session-bound fields need no role; fixed constants cannot be changed. */
int gw_set_u64(gw_packet *packet, const char *id, uint64_t value,
               char *error, size_t cap);
int gw_field_range(const gw_packet *packet, const char *id,
                   size_t *offset, size_t *length);
#endif
