#include "protocol_schedule.h"
#include <inttypes.h>
#include <string.h>

static uint64_t increment(uint64_t value) {
  return value == UINT64_MAX ? value : value + 1;
}

static int layer_index(int layer) {
  return layer == PROTO_HEAD ? 0 : layer == PROTO_CONTENT ? 1 :
         layer == PROTO_SEQUENCE ? 2 : -1;
}

static const proto_schedule_entry *find_entry(const proto_schedule *s,
                                             uint32_t state_id) {
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++)
    if (s->entries[i].used && s->entries[i].state_id == state_id)
      return &s->entries[i];
  return NULL;
}

static proto_schedule_entry *touch_entry(proto_schedule *s, uint32_t state_id) {
  unsigned slot = 0;
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++) {
    if (s->entries[i].used && s->entries[i].state_id == state_id) {
      slot = i;
      goto found;
    }
  }
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++) {
    if (!s->entries[i].used) { slot = i; goto replace; }
    if (s->entries[i].last_used < s->entries[slot].last_used) slot = i;
  }
  s->evictions = increment(s->evictions);
replace:
  memset(&s->entries[slot], 0, sizeof(s->entries[slot]));
  s->entries[slot].state_id = state_id;
  s->entries[slot].used = 1;
found:
  if (s->clock == UINT64_MAX) {
    for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++)
      s->entries[i].last_used >>= 1;
    s->clock >>= 1;
  }
  s->entries[slot].last_used = ++s->clock;
  return &s->entries[slot];
}

int proto_schedule_weights(const proto_schedule *s, uint32_t state_id,
                           int layers, uint32_t weights[3]) {
  if (weights) memset(weights, 0, 3 * sizeof(*weights));
  if (!s || !weights || layers <= 0 || (layers & ~7)) return -1;
  const proto_schedule_entry *entry = find_entry(s, state_id);
  for (unsigned i = 0; i < 3; i++) {
    if (!(layers & (1 << i))) continue;
    weights[i] = 16;
    if (entry && entry->attempts[i])
      weights[i] += 240u * entry->rewards[i] / (15u * entry->attempts[i]);
  }
  return 0;
}

int proto_schedule_choose(proto_schedule *s, uint32_t state_id,
                          int layers, proto_random rng) {
  if (!s || !rng || layers <= 0 || (layers & ~7)) return 0;
  proto_schedule_entry *entry = touch_entry(s, state_id);
  unsigned untried[3], count = 0;
  for (unsigned i = 0; i < 3; i++)
    if ((layers & (1 << i)) && !entry->attempts[i]) untried[count++] = i;
  if (count) return 1 << untried[rng(count) % count];
  uint32_t weights[3], total = 0;
  proto_schedule_weights(s, state_id, layers, weights);
  for (unsigned i = 0; i < 3; i++) total += weights[i];
  uint32_t draw = rng(total) % total;
  for (unsigned i = 0; i < 3; i++) {
    if (draw < weights[i]) return 1 << i;
    draw -= weights[i];
  }
  return 0;
}

void proto_schedule_observe(proto_schedule *s, uint32_t state_id,
                            int layer, unsigned events) {
  int index = layer_index(layer);
  if (!s || index < 0) return;
  proto_schedule_entry *entry = touch_entry(s, state_id);
  uint32_t attempts = 0;
  for (unsigned i = 0; i < 3; i++) attempts += entry->attempts[i];
  if (attempts >= PROTO_SCHEDULE_WINDOW) {
    for (unsigned i = 0; i < 3; i++) {
      entry->attempts[i] = (entry->attempts[i] + 1) / 2;
      entry->rewards[i] /= 2;
    }
  }
  events &= 15;
  unsigned reward = ((events & PROTO_FEEDBACK_QUEUE) ? 2 : 0) +
                    ((events & PROTO_FEEDBACK_MEMORY) ? 4 : 0) +
                    ((events & PROTO_FEEDBACK_CRASH) ? 8 : 0) +
                    ((events & PROTO_FEEDBACK_HANG) ? 1 : 0);
  entry->attempts[index]++;
  entry->rewards[index] += reward;
  s->observations = increment(s->observations);
  if (reward) s->rewarded = increment(s->rewarded);
  for (unsigned i = 0; i < 4; i++)
    if (events & (1u << i)) s->events[i] = increment(s->events[i]);
}

void proto_schedule_write(const proto_schedule *s, FILE *f) {
  if (!s || !f) return;
  fprintf(f, "{\"policy\":\"adaptive\",\"capacity\":%u,\"window_limit\":%u,"
          "\"observations\":%" PRIu64 ",\"rewarded\":%" PRIu64 ","
          "\"queue_events\":%" PRIu64 ",\"memory_events\":%" PRIu64 ","
          "\"crash_events\":%" PRIu64 ",\"hang_events\":%" PRIu64 ","
          "\"evictions\":%" PRIu64 ",\"states\":[",
          (unsigned)PROTO_SCHEDULE_SLOTS, (unsigned)PROTO_SCHEDULE_WINDOW,
          s->observations, s->rewarded, s->events[0], s->events[1],
          s->events[2], s->events[3], s->evictions);
  unsigned written = 0;
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++) {
    const proto_schedule_entry *entry = &s->entries[i];
    if (!entry->used) continue;
    uint32_t weights[3];
    proto_schedule_weights(s, entry->state_id, 7, weights);
    fprintf(f, "%s{\"state_id\":%" PRIu32 ",\"attempts\":[%u,%u,%u],"
            "\"rewards\":[%u,%u,%u],\"weights\":[%u,%u,%u]}",
            written++ ? "," : "", entry->state_id,
            (unsigned)entry->attempts[0], (unsigned)entry->attempts[1],
            (unsigned)entry->attempts[2], (unsigned)entry->rewards[0],
            (unsigned)entry->rewards[1], (unsigned)entry->rewards[2],
            (unsigned)weights[0], (unsigned)weights[1], (unsigned)weights[2]);
  }
  fputs("]}\n", f);
}
