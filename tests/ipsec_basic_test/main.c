/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Testing application for ipsec module
 *
 * @author      NguyenLe1605 <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include <stdio.h>

int main(void) {
  puts("Generated RIOT application: 'ipsec_basic_test'");
  ipsec_init();
  return 0;
}
