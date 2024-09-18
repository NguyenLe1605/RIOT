/*
 * Copyright (C) 2024 NguyenLe1605
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_wireguard
 *
 * @{
 * @file
 * @brief       Default configuration
 *
 * @author      Nguyen Le Hoang Dang <lhdnguyen2002@gmail.com>
 */

#ifndef WIREGUARD_PARAMS_H
#define WIREGUARD_PARAMS_H

#include "board.h"
#include "wireguard.h"
#include "wireguard_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name    Set default configuration parameters
 * @{
 */
#ifndef WIREGUARD_PARAM_PARAM1
#define WIREGUARD_PARAM_PARAM1
#endif

#ifndef WIREGUARD_PARAMS
#define WIREGUARD_PARAMS
#endif
/**@}*/

/**
 * @brief   Configuration struct
 */
// static const wireguard_params_t wireguard_params[] =
// {
//     WIREGUARD_PARAMS
// };
//
#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_PARAMS_H */
/** @} */
