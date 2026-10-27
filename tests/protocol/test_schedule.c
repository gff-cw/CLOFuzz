/* Standalone regression harness. No sockets, protocol codecs or target needed. */
#include "protocol_schedule.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static uint32_t random_state = 1, last_limit;
static uint32_t random_n(uint32_t limit) {
  assert(limit);
  random_state ^= random_state << 13;
  random_state ^= random_state >> 17;
  random_state ^= random_state << 5;
  return random_state % limit;
}
static uint32_t upper(uint32_t limit) { last_limit = limit; return limit - 1; }
static uint32_t exact_draw;
static uint32_t exact(uint32_t limit) { assert(exact_draw < limit); return exact_draw; }

static const proto_schedule_entry *entry_for(const proto_schedule *s, uint32_t id) {
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++)
    if (s->entries[i].used && s->entries[i].state_id == id) return &s->entries[i];
  return NULL;
}

static void masks_and_arguments(void) {
  proto_schedule s = {0}; uint32_t w[3];
  assert(!proto_schedule_choose(NULL, 0, 7, random_n));
  assert(!proto_schedule_choose(&s, 0, 7, NULL));
  for (int mask = -1; mask <= 15; mask++) {
    if (mask <= 0 || mask > 7) {
      assert(!proto_schedule_choose(&s, 0, mask, random_n));
      assert(proto_schedule_weights(&s, 0, mask, w) < 0);
      continue;
    }
    for (unsigned i = 0; i < 64; i++) {
      int layer = proto_schedule_choose(&s, (uint32_t)mask, mask, random_n);
      assert((layer == 1 || layer == 2 || layer == 4) && (layer & mask));
      proto_schedule_observe(&s, (uint32_t)mask, layer, 0);
    }
    assert(!proto_schedule_weights(&s, (uint32_t)mask, mask, w));
    for (unsigned i = 0; i < 3; i++)
      assert((mask & (1 << i)) ? w[i] >= 16 : w[i] == 0);
  }
  uint64_t before = s.observations;
  proto_schedule_observe(&s, 99, 3, 15);
  proto_schedule_observe(NULL, 99, 1, 15);
  proto_schedule_observe_outcome(&s, 99, 3, 31, 128, 9);
  proto_schedule_observe_outcome(NULL, 99, 1, 31, 128, 9);
  assert(s.observations == before);
  assert(proto_schedule_weights(NULL, 0, 7, w) < 0);
  assert(proto_schedule_weights(&s, 0, 7, NULL) < 0);
}

static void rewards_and_isolation(void) {
  proto_schedule s = {0}; uint32_t w[3];
  /* Each enabled layer gets an initial trial even when another is rewarded. */
  for (int expected = 4; expected; expected >>= 1) {
    int layer = proto_schedule_choose(&s, UINT32_MAX, 7, upper);
    assert(layer == expected);
    proto_schedule_observe_outcome(&s, UINT32_MAX, layer,
                                   layer == 1 ? 15 : 0,
                                   layer == 1 ? 128 : 0,
                                   layer == 1 ? 1 : 0);
  }
  assert(last_limit == 1);
  assert(!proto_schedule_weights(&s, UINT32_MAX, 7, w));
  assert(w[0] == 256 && w[1] == 16 && w[2] == 16);
  /* Every enabled layer retains an addressable interval of the draw space. */
  exact_draw = 0; assert(proto_schedule_choose(&s, UINT32_MAX, 7, exact) == 1);
  exact_draw = 256; assert(proto_schedule_choose(&s, UINT32_MAX, 7, exact) == 2);
  exact_draw = 272; assert(proto_schedule_choose(&s, UINT32_MAX, 7, exact) == 4);
  assert(!proto_schedule_weights(&s, 0, 7, w));
  assert(w[0] == 16 && w[1] == 16 && w[2] == 16);
  assert(s.observations == 3 && s.rewarded == 1);
  for (unsigned i = 0; i < 5; i++) assert(s.events[i] == 1);
  proto_schedule_observe(&s, 0, 2, 0x100);
  assert(s.rewarded == 1);
  /* A long failure streak reduces the learned weight without killing it. */
  for (unsigned i = 0; i < 5000; i++)
    proto_schedule_observe(&s, UINT32_MAX, 1, 0);
  proto_schedule_weights(&s, UINT32_MAX, 7, w);
  assert(w[0] < 256 && w[0] >= 16);
}

static void direct_coverage_outcomes(void) {
  proto_schedule s = {0}; uint32_t w[3];
  /* The legacy wrapper retains its event rewards without fabricating tuples. */
  proto_schedule_observe(&s, 0, 1, 31);
  const proto_schedule_entry *entry = entry_for(&s, 0);
  assert(entry && entry->attempts[0] == 1 && entry->rewards[0] == 15);
  assert(s.events[4] == 0 && !s.new_tuples && !s.new_buckets);
  proto_schedule_weights(&s, 0, 7, w);
  assert(w[0] == 166 && w[1] == 16 && w[2] == 16);
  proto_schedule_observe_outcome(&s, 0, 2, PROTO_FEEDBACK_COVERAGE, 0, 0);
  assert(entry->attempts[1] == 1 && entry->rewards[1] == 0);
  assert(!s.events[4]);

  const uint32_t tuples[] = {1, 2, 3, 4, 63, 64, 127, 128, 65536, UINT32_MAX};
  const unsigned rewards[] = {1, 2, 2, 3, 6, 7, 7, 8, 8, 8};
  uint64_t exact_tuples = 0;
  for (unsigned i = 0; i < sizeof(tuples) / sizeof(tuples[0]); i++) {
    proto_schedule_observe_outcome(&s, i + 1, 1, 0, tuples[i], 0);
    entry = entry_for(&s, i + 1);
    assert(entry && entry->rewards[0] == rewards[i]);
    assert(entry->attempts[0] == 1 && !entry->rewards[1] && !entry->rewards[2]);
    exact_tuples += tuples[i];
  }
  assert(s.new_tuples == exact_tuples && s.new_buckets == 0 && s.events[4] == 10);
  proto_schedule_observe_outcome(&s, 20, 2, 0, 0, 1000);
  entry = entry_for(&s, 20);
  assert(entry && entry->rewards[1] == 1);
  assert(s.new_tuples == exact_tuples && s.new_buckets == 1000 && s.events[4] == 11);
  proto_schedule_observe_outcome(&s, 20, 4, 15, 128, 5);
  assert(entry->rewards[2] == PROTO_SCHEDULE_MAX_REWARD);
  assert(s.new_tuples == exact_tuples + 128 && s.new_buckets == 1005);
  assert(s.events[4] == 12);
  proto_schedule_weights(&s, 20, 7, w);
  assert(w[2] == 256 && w[0] == 16);
  /* Direct coverage outcome is stronger than a crash when nine points accrue. */
  proto_schedule_observe_outcome(&s, 21, 1, 0, 128, 1);
  proto_schedule_observe(&s, 21, 2, PROTO_FEEDBACK_CRASH);
  proto_schedule_weights(&s, 21, 7, w);
  assert(w[0] > w[1] && w[2] == 16);
}

static void bounded_storage_and_counters(void) {
  proto_schedule s = {0}; uint32_t w[3];
  for (uint32_t id = 0; id < PROTO_SCHEDULE_SLOTS; id++)
    proto_schedule_observe_outcome(&s, id, 1, 15, 128, 1);
  /* Touch state 0, evict state 1, and retain their exact distinct identities. */
  assert(proto_schedule_choose(&s, 0, 1, upper) == 1);
  proto_schedule_observe(&s, UINT32_MAX, 1, 0);
  assert(s.evictions == 1);
  proto_schedule_weights(&s, 0, 7, w); assert(w[0] == 256);
  proto_schedule_weights(&s, 1, 7, w); assert(w[0] == 16);
  unsigned used = 0;
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++) used += s.entries[i].used != 0;
  assert(used == PROTO_SCHEDULE_SLOTS);
  for (unsigned i = 0; i < 100000; i++)
    proto_schedule_observe_outcome(&s, UINT32_MAX, 4, i % 2 ? 15 : 0,
                                   i % 2 ? UINT32_MAX : 0, i % 2 ? 1 : 0);
  for (unsigned i = 0; i < PROTO_SCHEDULE_SLOTS; i++) {
    uint32_t sum = 0;
    for (unsigned j = 0; j < 3; j++) {
      sum += s.entries[i].attempts[j];
      assert(s.entries[i].rewards[j] <=
             PROTO_SCHEDULE_MAX_REWARD * s.entries[i].attempts[j]);
    }
    assert(sum <= PROTO_SCHEDULE_WINDOW);
  }
  s.clock = UINT64_MAX; s.observations = UINT64_MAX; s.rewarded = UINT64_MAX;
  for (unsigned i = 0; i < 5; i++) s.events[i] = UINT64_MAX;
  s.new_tuples = UINT64_MAX - 5;
  s.new_buckets = UINT64_MAX - 7;
  proto_schedule_observe_outcome(&s, UINT32_MAX, 4, 15, UINT32_MAX, UINT32_MAX);
  assert(s.clock < UINT64_MAX && s.observations == UINT64_MAX && s.rewarded == UINT64_MAX);
  for (unsigned i = 0; i < 5; i++) assert(s.events[i] == UINT64_MAX);
  assert(s.new_tuples == UINT64_MAX && s.new_buckets == UINT64_MAX);
  proto_schedule_weights(&s, UINT32_MAX, 7, w);
  for (unsigned i = 0; i < 3; i++) assert(w[i] >= 16 && w[i] <= 256);
}

static void reproducibility_and_output(void) {
  proto_schedule a = {0}, b = {0}; int first[500];
  random_state = 12345;
  for (unsigned i = 0; i < 500; i++) {
    first[i] = proto_schedule_choose(&a, i % 5, 7, random_n);
    proto_schedule_observe_outcome(&a, i % 5, first[i], i % 17 == 0 ? 3 : 0,
                                   i % 17 == 0 ? 128 : 0, i % 7 == 0 ? 2 : 0);
  }
  random_state = 12345;
  for (unsigned i = 0; i < 500; i++) {
    int layer = proto_schedule_choose(&b, i % 5, 7, random_n);
    assert(first[i] == layer);
    proto_schedule_observe_outcome(&b, i % 5, layer, i % 17 == 0 ? 3 : 0,
                                   i % 17 == 0 ? 128 : 0, i % 7 == 0 ? 2 : 0);
  }
  assert(!memcmp(&a, &b, sizeof(a)));
  FILE *f = tmpfile(); assert(f);
  proto_schedule_write(&a, f); assert(!ferror(f)); rewind(f);
  char output[16384]; size_t n = fread(output, 1, sizeof(output) - 1, f);
  output[n] = 0;
  assert(strstr(output, "\"policy\":\"adaptive\"") && strstr(output, "\"observations\":500"));
  assert(strstr(output, "\"max_reward\":24") && strstr(output, "\"new_tuples\":3840"));
  assert(strstr(output, "\"new_buckets\":144"));
  assert(n > 3 && !strcmp(output + n - 3, "]}\n"));
  fclose(f);
}

int main(void) {
  masks_and_arguments(); rewards_and_isolation();
  direct_coverage_outcomes();
  bounded_storage_and_counters(); reproducibility_and_output();
  puts("Protocol schedule checks passed");
  return 0;
}
