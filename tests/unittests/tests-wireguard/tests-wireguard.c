/*
 * Copyright (c) 2016 Ken Bannister. All rights reserved.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */
#include <stdint.h>

#include "embUnit.h"
#include "net/wireguard/crypto.h"
#include "net/wireguard/messages.h"

#include "tests-wireguard.h"

static uint8_t alice_private_key[NOISE_PRIVATE_KEY_LEN] = {
    119, 7,  109, 10,  115, 24,  165, 125, 60,  22,  193,
    114, 81, 178, 102, 69,  223, 76,  47,  135, 235, 192,
    153, 42, 177, 119, 251, 165, 29,  185, 44,  42};

static const uint8_t alice_public_key[NOISE_PUBLIC_KEY_LEN] = {
    133, 32,  240, 9,   137, 48,  167, 84,  116, 139, 125,
    220, 180, 62,  247, 90,  13,  191, 58,  13,  38,  56,
    26,  244, 235, 164, 169, 142, 170, 155, 78,  106};

static uint8_t bob_private_key[NOISE_PRIVATE_KEY_LEN] = {
    93,  171, 8,   126, 98,  74,  138, 75,  121, 225, 127,
    139, 131, 128, 14,  230, 111, 59,  177, 41,  38,  24,
    182, 253, 28,  47,  139, 39,  255, 136, 224, 235};

static const uint8_t bob_public_key[NOISE_PUBLIC_KEY_LEN] = {
    222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97,
    194, 236, 228, 53,  55,  63,  131, 67,  200, 91, 120,
    103, 77,  173, 252, 126, 20,  111, 136, 43,  79};

static const uint8_t shared_secret[NOISE_SYMMETRIC_KEY_LEN] = {
    74,  93,  157, 91,  164, 206, 45,  225, 114, 142, 59,
    244, 128, 53,  15,  37,  224, 126, 33,  201, 71,  209,
    158, 51,  118, 240, 155, 60,  30,  22,  23,  66};

static uint8_t zerobuf[NOISE_PUBLIC_KEY_LEN] = {0};

static uint8_t abuf[NOISE_PUBLIC_KEY_LEN];
static uint8_t bbuf[NOISE_PUBLIC_KEY_LEN];
static uint8_t asbuf[NOISE_SYMMETRIC_KEY_LEN];
static uint8_t bsbuf[NOISE_SYMMETRIC_KEY_LEN];

static void test_wireguard_crypto_ecdh(void) {
  dh_clamp_private_key(alice_private_key);
  dh_clamp_private_key(bob_private_key);
  TEST_ASSERT(dh_generate_public_key(abuf, alice_private_key));
  TEST_ASSERT_EQUAL_INT(0,
                        memcmp(abuf, alice_public_key, NOISE_PUBLIC_KEY_LEN));
  TEST_ASSERT(dh_generate_public_key(bbuf, bob_private_key));
  TEST_ASSERT_EQUAL_INT(0, memcmp(bbuf, bob_public_key, NOISE_PUBLIC_KEY_LEN));
  TEST_ASSERT(dh_agree(asbuf, alice_private_key, bbuf));
  TEST_ASSERT_EQUAL_INT(0,
                        memcmp(asbuf, shared_secret, NOISE_SYMMETRIC_KEY_LEN));
  TEST_ASSERT(dh_agree(bsbuf, bob_private_key, abuf));
  TEST_ASSERT_EQUAL_INT(0,
                        memcmp(bsbuf, shared_secret, NOISE_SYMMETRIC_KEY_LEN));
  TEST_ASSERT(!dh_agree(asbuf, alice_private_key, zerobuf));
}

Test *tests_wireguard_crypto_tests(void) {
  EMB_UNIT_TESTFIXTURES(fixtures){
      new_TestFixture(test_wireguard_crypto_ecdh),

  };

  EMB_UNIT_TESTCALLER(ecdh_test, NULL, NULL, fixtures);

  return (Test *)&ecdh_test;
}

void tests_wireguard(void) { TESTS_RUN(tests_wireguard_crypto_tests()); }
/** @} */
