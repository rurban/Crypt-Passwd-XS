#include "des.h"
#include <stdio.h>

int main (int argc, char **argv) {
  const char *password = "test1234";
  const char *salt = "12345";
  const char *expected = "12UoCqI1ykfQI";
  char *got;
  got = crypt_des(password, salt);
  printf("Got: %s\nExpected: %s\n", got, expected);
  return 0;
}
