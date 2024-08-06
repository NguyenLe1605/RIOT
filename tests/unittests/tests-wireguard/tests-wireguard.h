/*
 * Copyright (c) 2024 Nguyen Le Hoang Dang. All rights reserved.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @addtogroup  unittests
 * @{
 *
 * @file
 * @brief       Unit tests for the crypto of wireguard module
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */
#ifndef TESTS_WIREGUARD_H
#define TESTS_WIREGUARD_H

#include "embUnit.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   The entry point of this test suite.
 *
 * Incl.
 */
void tests_wireguard(void);

#ifdef __cplusplus
}
#endif

#endif /* TESTS_WIREGUARD_H */
/** @} */
