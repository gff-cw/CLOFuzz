/* Bounded wire codecs used by the declarative protocol runtime. */
#ifndef STATEAFL_PROTOCOL_CODECS_H
#define STATEAFL_PROTOCOL_CODECS_H
#include <stddef.h>
#include <stdint.h>
enum pc_type { PC_UINT8, PC_UINT16, PC_UINT24, PC_UINT32, PC_UINT64,
  PC_BYTES, PC_STRING, PC_BACNET_TAGS, PC_BER_TLV, PC_EPATH, PC_NODEID };
/* field: 1 present, 0 optional/unsupported locator, -1 malformed packet.
 * repair: restore structural lengths in place, then validate. No allocation.
 * replace: replace one supported variable leaf and repair enclosing lengths;
 * unsupported broad containers return -1 rather than copying opaque fuzz data.
 * frame: 0 incomplete, 1 complete (size set), -1 malformed framing. */
#define PC_DECLARE(name) \
int pc_##name##_validate(const uint8_t *, size_t, char *, size_t); \
int pc_##name##_field(const uint8_t *, size_t, const char *, int, size_t, size_t *, size_t *, char *, size_t); \
int pc_##name##_repair(uint8_t *, size_t, char *, size_t); \
int pc_##name##_replace(uint8_t *, size_t *, size_t, const char *, int, const uint8_t *, size_t, char *, size_t); \
int pc_##name##_frame(const uint8_t *, size_t, size_t *, char *, size_t); \
int pc_##name##_same_kind(const uint8_t *, size_t, const uint8_t *, size_t)
PC_DECLARE(modbus);
PC_DECLARE(iec104);
PC_DECLARE(mms);
PC_DECLARE(enip);
PC_DECLARE(opcua);
#undef PC_DECLARE
#endif
