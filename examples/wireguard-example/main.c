/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       An example to test wireguard
 *
 * @author      NguyenLe1605 <lhdnguyen2002@gmail.com>
 *
 * @}
 */

#include "net/wireguard.h"
#include <stdio.h>

int main(void) {
  puts("Generated RIOT application: 'wireguard-example'");
  wireguard_init();
  return 0;
}
