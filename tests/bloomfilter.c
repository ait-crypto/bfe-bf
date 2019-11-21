#include "../include/bloomfilter.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

Describe(BF);
BeforeEach(BF) {}
AfterEach(BF) {}

Ensure(BF, add) {
  ep_t p1, p2, p3;
  ep_null(p1);
  ep_null(p2);
  ep_null(p3);

  ep_new(p1);
  ep_new(p2);
  ep_new(p3);

  ep_rand(p1);
  ep_rand(p2);
  ep_rand(p3);

  bloomfilter_t bloom = bf_init(300, 0.001);
  bf_add(&bloom, p1);
  bf_add(&bloom, p2);

  assert_true(bf_maybe_contains(&bloom, p1));
  assert_true(bf_maybe_contains(&bloom, p2));
  assert_false(bf_maybe_contains(&bloom, p3));

  bloomfilter_clear(&bloom);
  ep_free(p3);
  ep_free(p2);
  ep_free(p1);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BF, add);
  return run_test_suite(suite, create_text_reporter());
}
