#include "../include/bloomfilter.h"

#include <cgreen/cgreen.h>

Describe(BF);
BeforeEach(BF) {}
AfterEach(BF) {}

Ensure(BF, add) {
  const uint8_t input1[2] = {'P', 'a'};
  const uint8_t input2[2] = {'P', 'b'};
  const uint8_t input3[2] = {'P', 'c'};

  bloomfilter_t bloom = bloomfilter_init(300, 0.001);
  bloomfilter_add(&bloom, input1, sizeof(input1));
  bloomfilter_add(&bloom, input2, sizeof(input2));

  assert_true(bloomfilter_maybe_contains(bloom, input1, sizeof(input1)));
  assert_true(bloomfilter_maybe_contains(bloom, input2, sizeof(input2)));
  assert_false(bloomfilter_maybe_contains(bloom, input3, sizeof(input3)));

  bloomfilter_clean(&bloom);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BF, add);
  return run_test_suite(suite, create_text_reporter());
}
