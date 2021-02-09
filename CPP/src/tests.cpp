#define BOOST_TEST_MODULE CipherTests
#include <boost/test/unit_test.hpp>
#include <string>

std::string substitute(std::string orig, std::string key);

BOOST_AUTO_TEST_CASE(SubstituteTestCase){
  std::string original_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ'abcdefghijklmnopqrstuvwxyz";
  std::string substitute_key = "XYZABCDEFGHIJKLMNOPQRSTUVW";
  std::string substituted_string = substitute(original_string,substitute_key);

  BOOST_CHECK_EQUAL(substituted_string,"XYZABCDEFGHIJKLMNOPQRSTUVW'xyzabcdefghijklmqopqrstuvw");
}
