#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "afl-fuzz.h"
#include "mangle.h"

#define NUMBER_OF_MUTATIONS 5

uint8_t          *queue_input;
size_t            queue_input_size;
afl_state_t      *afl_struct;
run_t             run;
honggfuzz_t       global;
struct _dynfile_t dynfile;

typedef struct my_mutator {

  afl_state_t *afl;
  run_t       *run;
  u8          *mutator_buf;
  unsigned int seed;
  unsigned int extras_cnt, a_extras_cnt;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  run.dynfile = &dynfile;
  run.global = &global;
  data->afl = afl;
  data->seed = seed;
  data->run = &run;
  afl_struct = afl;

  run.global->mutate.maxInputSz = MAX_FILE;
  run.global->mutate.mutationsPerRun = NUMBER_OF_MUTATIONS;
  run.mutationsPerRun = NUMBER_OF_MUTATIONS;
  run.global->timing.lastCovUpdate = 6;

  // global->feedback.cmpFeedback
  // global->feedback.cmpFeedbackMap

  return data;

}

/* When a new queue entry is added we check if there are new dictionary
   entries to add to honggfuzz structure */

void afl_custom_queue_new_entry(my_mutator_t  *data,
                                const uint8_t *filename_new_queue,
                                const uint8_t *filename_orig_queue) {

  if (run.global->mutate.dictionaryCnt >= 1024) return;

  while (data->extras_cnt < data->afl->extras_cnt &&
         run.global->mutate.dictionaryCnt < 1024) {

    memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
           data->afl->extras[data->extras_cnt].data,
           data->afl->extras[data->extras_cnt].len);
    run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
        data->afl->extras[data->extras_cnt].len;
    run.global->mutate.dictionaryCnt++;
    data->extras_cnt++;

  }

  while (data->a_extras_cnt < data->afl->a_extras_cnt &&
         run.global->mutate.dictionaryCnt < 1024) {

    memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
           data->afl->a_extras[data->a_extras_cnt].data,
           data->afl->a_extras[data->a_extras_cnt].len);
    run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
        data->afl->a_extras[data->a_extras_cnt].len;
    run.global->mutate.dictionaryCnt++;
    data->a_extras_cnt++;

  }

  return;

}

/* we could set only_printable if is_ascii is set ... let's see
uint8_t afl_custom_queue_get(void *data, const uint8_t *filename) {

  //run.global->cfg.only_printable = ...

}

*/

/* here we run the honggfuzz mutator, which is really good */

#ifdef HONGGFUZZ_2B_CHUNKED
typedef uint16_t chunk_size;
const chunk_size chunk_size_mask = 0x7ff;

typedef struct fuzz_packet {
  chunk_size size;
  uint16_t mut;
  uint8_t* buf;
} fuzz_packet_t;

void read_fuzz_packets(uint8_t *buf, size_t buf_size, fuzz_packet_t* out, size_t* out_size, size_t max_packets) {
  size_t remain = buf_size;
  uint8_t* cur = buf;
  *out_size = 0;

  while(1) {
    if (remain < sizeof(chunk_size) + 1) {
      // Minimum length required to proceed
      return;
    }

    if (*out_size >= max_packets) {
      return;
    }

    out[*out_size].mut = 0;
    out[*out_size].size = *(chunk_size*)cur & chunk_size_mask; // Only interpret lower bits for size
    cur += sizeof(chunk_size); remain -= sizeof(chunk_size);
  
    if (remain < out[*out_size].size) {
      // Truncate last input, if remaining data too small
      out[*out_size].size = remain;
    }

    out[*out_size].buf = cur;
    cur += out[*out_size].size; remain -= out[*out_size].size;

    *out_size += 1;
  }
}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  fuzz_packet_t packet_out[64];
  size_t packet_size = 0;

  fuzz_packet_t packet_out_add[64];
  size_t packet_size_add = 0;

  read_fuzz_packets(buf, buf_size, packet_out, &packet_size, 64);

  if (!packet_size) {
    *out_buf = buf;
    return buf_size;
  }

  if (add_buf) {
    read_fuzz_packets(add_buf, add_buf_size, packet_out_add, &packet_size_add, 64);
  }

  int num_mutations = rand() % 5 + 1;
  

  for (int i = 0; i < num_mutations; ++i) {
    if (add_buf && packet_size_add > 0 && (rand() % 2)) {
      // Splice one index
      packet_out[rand() % packet_size].mut = 1;
    } else {
      // Mutate one index
      packet_out[rand() % packet_size].mut = 2;
    }
  }

  size_t written = 0;

  *out_buf = data->mutator_buf;
  uint8_t* cur = data->mutator_buf;

  for (size_t idx = 0; idx < packet_size; ++idx) {
    chunk_size* size_out = (chunk_size*)cur;

    if (packet_out[idx].mut == 1) {
      // Splice
      size_t splice_idx = rand() % packet_size_add;

      if (written + sizeof(chunk_size) + packet_out_add[splice_idx].size >= max_size) {
        return written;
      }

      memcpy(cur + sizeof(chunk_size), packet_out_add[splice_idx].buf, packet_out_add[splice_idx].size);
      *size_out = packet_out_add[splice_idx].size;
    } else {
      if (written + sizeof(chunk_size) + packet_out[idx].size >= max_size) {
        return written;
      }

      memcpy(cur + sizeof(chunk_size), packet_out[idx].buf, packet_out[idx].size);
      if (packet_out[idx].mut == 2) {
        // Mutate
        run.dynfile->data = data->mutator_buf + sizeof(chunk_size);
        run.dynfile->size = packet_out[idx].size;

        queue_input = run.dynfile->data;
        queue_input_size = run.dynfile->size;

	run.global->mutate.maxInputSz = MAX_FILE - written - sizeof(chunk_size);

	mangle_mangleContent(&run, NUMBER_OF_MUTATIONS);

	// Truncate output
	if (run.dynfile->size > chunk_size_mask) {
		run.dynfile->size = chunk_size_mask;
	}

	if (run.dynfile->data != data->mutator_buf + sizeof(chunk_size)) {
		abort();
	}

        packet_out[idx].size = run.dynfile->size;
      }

      *size_out = packet_out[idx].size;
    }

    cur += *size_out + sizeof(chunk_size);
    written += *size_out + sizeof(chunk_size);
  }

  /* return size of mutated data */
  return written;
}

#else

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  /* set everything up, costly ... :( */
  memcpy(data->mutator_buf, buf, buf_size);
  queue_input = data->mutator_buf;
  run.dynfile->data = data->mutator_buf;
  queue_input_size = buf_size;
  run.dynfile->size = buf_size;
  *out_buf = data->mutator_buf;

  /* the mutation */
  mangle_mangleContent(&run, NUMBER_OF_MUTATIONS);

  /* return size of mutated data */
  return run.dynfile->size;

}

#endif

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

