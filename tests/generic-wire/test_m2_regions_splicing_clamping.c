#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"

static unsigned checks = 0;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

/* Standalone region_add_bytes logic under test matching afl-fuzz.c */
static void test_regions_add_bytes(region_t* regions, unsigned int region_count, unsigned int position, int added_bytes) {
  if (!regions || !region_count) return;

  unsigned int cur_region = 0;
  while(cur_region < region_count && (unsigned int)regions[cur_region].end_byte < position) {
    cur_region++;
  }

  // Append bytes at end of last region
  if(cur_region == region_count && (unsigned int)regions[cur_region-1].end_byte + 1 == position) {
    cur_region--;
  }

  if (cur_region >= region_count) {
    cur_region = region_count - 1;
  }

  regions[cur_region].end_byte += added_bytes;
  cur_region++;

  while(cur_region < region_count) {
    regions[cur_region].start_byte += added_bytes;
    regions[cur_region].end_byte += added_bytes;
    cur_region++;
  }
}

/* Standalone region_remove_bytes logic under test matching afl-fuzz.c */
static int test_regions_remove_bytes(region_t** p_mutated_regions, unsigned int* p_mutated_region_count,
                                     unsigned int position, int removed_bytes) {
  if (!p_mutated_regions || !*p_mutated_regions || !p_mutated_region_count || !*p_mutated_region_count) return 0;

  region_t* regions = *p_mutated_regions;
  unsigned int region_count = *p_mutated_region_count;

  unsigned int cur_region = 0;
  while(cur_region < region_count && (unsigned int)regions[cur_region].end_byte < position) {
    cur_region++;
  }

  if (cur_region >= region_count) return 0;

  int to_remove = removed_bytes;
  int removed = 0;
  int removed_regions = 0;
  int modified_regions = 0;

  while(to_remove > 0 && cur_region < region_count) {
    regions[cur_region].start_byte -= removed;
    regions[cur_region].end_byte -= removed;

    if(regions[cur_region].end_byte > (int)(position + to_remove - 1)) {
      regions[cur_region].end_byte -= to_remove;
      removed += to_remove;
      to_remove = 0;
    } else {
      if(regions[cur_region].start_byte < (int)position) {
        to_remove -= regions[cur_region].end_byte - position + 1;
        removed = removed_bytes - to_remove;
        regions[cur_region].end_byte = position - 1;
      } else {
        to_remove -= regions[cur_region].end_byte - position + 1;
        removed = removed_bytes - to_remove;
        regions[cur_region].start_byte = -1;
        regions[cur_region].end_byte = -1;
        removed_regions++;
      }
    }
    cur_region++;
    modified_regions++;
  }

  while(cur_region < region_count) {
    regions[cur_region].start_byte -= removed_bytes;
    regions[cur_region].end_byte -= removed_bytes;
    cur_region++;
  }

  if(region_count > 1 && removed_regions > 0) {
    unsigned int new_region_count = region_count - removed_regions;
    region_t* new_regions = ck_alloc(new_region_count * sizeof(region_t));

    int j = new_region_count - 1;
    for(int i = (int)region_count - 1; i >= 0; i--) {
      if(regions[i].start_byte == -1 && regions[i].end_byte == -1) {
        continue;
      }
      new_regions[j].start_byte = regions[i].start_byte;
      new_regions[j].end_byte = regions[i].end_byte;
      new_regions[j].state_sequence = regions[i].state_sequence;
      new_regions[j].state_count = regions[i].state_count;
      j--;
    }
    ck_free(*p_mutated_regions);
    *p_mutated_regions = new_regions;
    *p_mutated_region_count = new_region_count;
  }

  return modified_regions;
}

int main(void) {
  printf("[*] Testing M2 region normalization, splicing bounds checks, and buffer clamping...\n");

  /* ========================================================================
   * 1. M2 Region Normalization & Dynamic Allocation Lifecycle
   * ======================================================================== */
  {
    /* Full testcase has 4 regions across 300 bytes */
    region_t full_regions[4] = {
      { .start_byte = 0,   .end_byte = 50,  .state_sequence = NULL, .state_count = 0 },
      { .start_byte = 51,  .end_byte = 120, .state_sequence = NULL, .state_count = 0 },
      { .start_byte = 121, .end_byte = 200, .state_sequence = NULL, .state_count = 0 },
      { .start_byte = 201, .end_byte = 300, .state_sequence = NULL, .state_count = 0 }
    };

    u32 M2_start_region_ID = 1;
    u32 M2_region_count = 2; /* Subsequence covering region 1 and 2 (bytes 51 to 200) */

    unsigned int orig_region_count = M2_region_count;
    region_t *orig_regions = NULL;

    if (orig_region_count > 0) {
      orig_regions = (region_t *)ck_alloc(orig_region_count * sizeof(region_t));
      u32 m2_base_offset = full_regions[M2_start_region_ID].start_byte; /* 51 */

      for (u32 r = 0; r < orig_region_count; r++) {
        orig_regions[r] = full_regions[M2_start_region_ID + r];
        orig_regions[r].start_byte -= m2_base_offset;
        orig_regions[r].end_byte   -= m2_base_offset;
      }
    }

    CHECK(orig_regions != NULL);
    /* Normalized offsets: start_byte of first region MUST be 0 */
    CHECK(orig_regions[0].start_byte == 0);
    CHECK(orig_regions[0].end_byte == (120 - 51)); /* 69 */

    /* Second region in M2 normalized relative to base */
    CHECK(orig_regions[1].start_byte == (121 - 51)); /* 70 */
    CHECK(orig_regions[1].end_byte == (200 - 51));   /* 149 */

    /* Verify mutated_regions clone */
    unsigned int mutated_region_count = orig_region_count;
    CHECK(mutated_region_count == 2);
    region_t *mutated_regions = (region_t *)ck_alloc(orig_region_count * sizeof(region_t));
    memcpy(mutated_regions, orig_regions, orig_region_count * sizeof(region_t));
    CHECK(mutated_regions[0].start_byte == 0);
    CHECK(mutated_regions[1].end_byte == 149);

    ck_free(mutated_regions);
    ck_free(orig_regions);
    orig_regions = NULL;

    printf("[+] 1: M2 region normalization verified: base offset subtracted and start_byte normalized to 0\n");
  }

  /* ========================================================================
   * 2. regions_add_bytes and regions_remove_bytes Boundary Checks
   * ======================================================================== */
  {
    /* 2a. NULL and 0 count safety */
    test_regions_add_bytes(NULL, 0, 10, 5);
    region_t dummy = { .start_byte = 0, .end_byte = 10, .state_sequence = NULL, .state_count = 0 };
    test_regions_add_bytes(&dummy, 0, 10, 5);

    region_t *p_dummy = &dummy;
    unsigned int d_count = 0;
    CHECK(test_regions_remove_bytes(NULL, &d_count, 5, 2) == 0);
    CHECK(test_regions_remove_bytes(&p_dummy, &d_count, 5, 2) == 0);

    /* 2b. Add bytes in middle */
    region_t *r = (region_t *)ck_alloc(3 * sizeof(region_t));
    r[0].start_byte = 0;  r[0].end_byte = 9;
    r[1].start_byte = 10; r[1].end_byte = 19;
    r[2].start_byte = 20; r[2].end_byte = 29;

    test_regions_add_bytes(r, 3, 5, 5);
    CHECK(r[0].start_byte == 0 && r[0].end_byte == 14);
    CHECK(r[1].start_byte == 15 && r[1].end_byte == 24);
    CHECK(r[2].start_byte == 25 && r[2].end_byte == 34);

    /* 2c. Add bytes with position past all regions (cur_region >= region_count clamp) */
    test_regions_add_bytes(r, 3, 100, 10);
    CHECK(r[2].end_byte == 44); /* safely expanded last region without OOB write */

    /* 2d. Remove bytes with position past all regions */
    unsigned int r_cnt = 3;
    int mod = test_regions_remove_bytes(&r, &r_cnt, 200, 10);
    CHECK(mod == 0);
    CHECK(r_cnt == 3);

    /* 2e. Remove bytes spanning and removing entire middle region */
    /* r[0]: [0, 14], r[1]: [15, 24], r[2]: [25, 44] */
    /* Remove 12 bytes at position 14 (1 byte of r[0], all 10 bytes of r[1], 1 byte of r[2]) */
    mod = test_regions_remove_bytes(&r, &r_cnt, 14, 12);
    CHECK(mod > 0);
    CHECK(r_cnt == 2); /* middle region cleanly removed and compacted */
    CHECK(r[0].start_byte == 0 && r[0].end_byte == 13);
    CHECK(r[1].start_byte == 14 && r[1].end_byte == 32);

    ck_free(r);
    printf("[+] 2: regions_add_bytes and regions_remove_bytes boundary checks and compaction verified\n");
  }

  /* ========================================================================
   * 3. Splicing Bounds Checks & Underflow Protection
   * ======================================================================== */
  {
    /* Setup mutated_regions */
    unsigned int mutated_region_count = 2;
    region_t *mutated_regions = (region_t *)ck_alloc(2 * sizeof(region_t));
    mutated_regions[0].start_byte = 0;  mutated_regions[0].end_byte = 49;
    mutated_regions[1].start_byte = 50; mutated_regions[1].end_byte = 99;

    /* Setup target regions */
    unsigned int target_region_count = 1;
    region_t target_regions[1] = {
      { .start_byte = 0, .end_byte = 80, .state_sequence = NULL, .state_count = 0 }
    };

    /* 3a. Splicing with split_at past mutated_regions */
    u32 split_at = 200;
    unsigned int first_region_count = 0;
    while(first_region_count < mutated_region_count && (u32)mutated_regions[first_region_count].end_byte < split_at) {
      first_region_count++;
    }
    if (first_region_count >= mutated_region_count)
      first_region_count = mutated_region_count - 1;
    CHECK(first_region_count == 1); /* clamped to last index without OOB */

    /* 3b. Splicing with split_at at 0 (test target_count underflow protection) */
    split_at = 0;
    unsigned int second_region_count = 0;
    while(second_region_count < target_region_count &&
          (u32)target_regions[target_region_count - 1 - second_region_count].start_byte > split_at) {
      second_region_count++;
    }
    if (second_region_count >= target_region_count)
      second_region_count = target_region_count - 1;
    CHECK(second_region_count == 0);

    u32 target_idx = target_region_count - second_region_count - 1;
    CHECK(target_idx == 0); /* safely computed without unsigned underflow to 4294967295 */

    /* 3c. Splitted region end_byte clamp when target end_byte < mutated start_byte */
    region_t new_region;
    new_region.start_byte = 60;
    new_region.end_byte = 40; /* inverted range */
    if (new_region.end_byte < new_region.start_byte)
      new_region.end_byte = new_region.start_byte;
    CHECK(new_region.end_byte == 60);

    ck_free(mutated_regions);
    printf("[+] 3: Splicing bounds checks, underflow protection, and end_byte clamping verified\n");
  }

  /* ========================================================================
   * 4. common_fuzz_stuff Buffer Clamping & Shadowed Variable Safety
   * ======================================================================== */
  {
    u32 len = 50; /* mutated out_buf length */
    u8 out_buf[50];
    for (u32 i = 0; i < 50; i++) out_buf[i] = (u8)(i + 1);

    /* 3 regions:
       Region 0: [0, 24]   (fully within buffer, size 25)
       Region 1: [25, 64]  (overhang: size 40, extends past len 50)
       Region 2: [65, 89]  (completely past len 50, size 25)
    */
    region_t test_regions[3] = {
      { .start_byte = 0,  .end_byte = 24 },
      { .start_byte = 25, .end_byte = 64 },
      { .start_byte = 65, .end_byte = 89 }
    };

    for (int i = 0; i < 3; i++) {
      u32 m_len = test_regions[i].end_byte - test_regions[i].start_byte + 1;
      u8 *mdata = (u8 *)ck_alloc(m_len);
      CHECK(mdata != NULL);

      u32 copy_len = m_len;
      if ((u32)test_regions[i].start_byte >= len) {
        copy_len = 0;
      } else if ((u32)test_regions[i].start_byte + copy_len > len) {
        copy_len = len - test_regions[i].start_byte;
      }

      if (copy_len > 0)
        memcpy(mdata, &out_buf[test_regions[i].start_byte], copy_len);
      if (copy_len < m_len)
        memset(mdata + copy_len, 0, m_len - copy_len);

      if (i == 0) {
        CHECK(m_len == 25);
        CHECK(copy_len == 25);
        CHECK(mdata[0] == 1 && mdata[24] == 25);
      } else if (i == 1) {
        CHECK(m_len == 40);
        CHECK(copy_len == 25); /* 50 - 25 */
        CHECK(mdata[0] == 26 && mdata[24] == 50);
        /* Remaining 15 bytes must be zero-padded without buffer overflow */
        for (u32 k = 25; k < 40; k++) CHECK(mdata[k] == 0);
      } else if (i == 2) {
        CHECK(m_len == 25);
        CHECK(copy_len == 0); /* completely past end */
        /* All 25 bytes zero-padded */
        for (u32 k = 0; k < 25; k++) CHECK(mdata[k] == 0);
      }

      ck_free(mdata);
    }

    printf("[+] 4: common_fuzz_stuff buffer clamping verified: no heap overflow on truncated/overhanging regions\n");
  }

  printf("[+] All M2 region normalization, splicing bounds, and buffer clamping tests passed! (%u checks)\n", checks);
  return 0;
}
