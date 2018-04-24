/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Adaptive LLSEC driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AKES_MAC_H_
#define AKES_MAC_H_

#include "net/mac/mac.h"
#include "net/security/akes/akes-nbr.h"
#include "net/mac/csl/csl.h"
#include "lib/ccm-star.h"
#include "lib/aes-128.h"

#ifdef AKES_MAC_CONF_DECORATED_FRAMER
#define AKES_MAC_DECORATED_FRAMER AKES_MAC_CONF_DECORATED_FRAMER
#else /* AKES_MAC_CONF_DECORATED_FRAMER */
#define AKES_MAC_DECORATED_FRAMER csl_framer
#endif /* AKES_MAC_CONF_DECORATED_FRAMER */

#ifdef AKES_MAC_CONF_DECORATED_MAC
#define AKES_MAC_DECORATED_MAC AKES_MAC_CONF_DECORATED_MAC
#else /* AKES_MAC_CONF_DECORATED_MAC */
#define AKES_MAC_DECORATED_MAC csl_driver
#endif /* AKES_MAC_CONF_DECORATED_MAC */

#ifdef AKES_MAC_CONF_UNICAST_SEC_LVL
#define AKES_MAC_UNICAST_SEC_LVL AKES_MAC_CONF_UNICAST_SEC_LVL
#else /* AKES_MAC_CONF_UNICAST_SEC_LVL */
#define AKES_MAC_UNICAST_SEC_LVL 2
#endif /* AKES_MAC_CONF_UNICAST_SEC_LVL */

#ifdef AKES_MAC_CONF_UNICAST_MIC_LEN
#define AKES_MAC_UNICAST_MIC_LEN AKES_MAC_CONF_UNICAST_MIC_LEN
#else /* AKES_MAC_CONF_UNICAST_MIC_LEN */
#define AKES_MAC_UNICAST_MIC_LEN LLSEC802154_MIC_LEN(AKES_MAC_UNICAST_SEC_LVL)
#endif /* AKES_MAC_CONF_UNICAST_MIC_LEN */

#ifdef AKES_MAC_CONF_BROADCAST_SEC_LVL
#define AKES_MAC_BROADCAST_SEC_LVL AKES_MAC_CONF_BROADCAST_SEC_LVL
#else /* AKES_MAC_CONF_BROADCAST_SEC_LVL */
#define AKES_MAC_BROADCAST_SEC_LVL AKES_MAC_UNICAST_SEC_LVL
#endif /* AKES_MAC_CONF_BROADCAST_SEC_LVL */

#ifdef AKES_MAC_CONF_BROADCAST_MIC_LEN
#define AKES_MAC_BROADCAST_MIC_LEN AKES_MAC_CONF_BROADCAST_MIC_LEN
#else /* AKES_MAC_CONF_BROADCAST_MIC_LEN */
#define AKES_MAC_BROADCAST_MIC_LEN LLSEC802154_MIC_LEN(AKES_MAC_BROADCAST_SEC_LVL)
#endif /* AKES_MAC_CONF_BROADCAST_MIC_LEN */

#ifdef AKES_MAC_CONF_STRATEGY
#define AKES_MAC_STRATEGY AKES_MAC_CONF_STRATEGY
#else /* AKES_MAC_CONF_STRATEGY */
#define AKES_MAC_STRATEGY noncoresec_strategy
#endif /* AKES_MAC_CONF_STRATEGY */

enum akes_mac_verify {
  AKES_MAC_VERIFY_SUCCESS,
  AKES_MAC_VERIFY_INAUTHENTIC,
};

/**
 * Structure of a strategy regarding compromise resilience
 */
struct akes_mac_strategy {

  /** Sets the CCM* nonce */
  void (* set_nonce)(uint8_t *nonce, int forward);

  /** Secures outgoing frames */
  void (* send)(mac_callback_t sent, void *ptr);

  /** Called when the frame was created */
  int (* on_frame_created)(void);

  /** 0 <-> Success */
  enum akes_mac_verify (* verify)(struct akes_nbr *sender);

  uint8_t (* get_overhead)(void);

  /** Initializes */
  void (* init)(void);
};

extern const struct framer AKES_MAC_DECORATED_FRAMER;
extern const struct mac_driver AKES_MAC_DECORATED_MAC;
extern const struct akes_mac_kes AKES_MAC_KES;
extern const struct akes_mac_strategy AKES_MAC_STRATEGY;
extern const struct mac_driver akes_mac_driver;
extern const struct framer akes_mac_framer;

clock_time_t akes_mac_random_clock_time(clock_time_t min, clock_time_t max);
uint8_t akes_mac_get_cmd_id(void);
int akes_mac_is_hello(void);
int akes_mac_is_helloack(void);
int akes_mac_is_ack(void);
uint8_t akes_mac_get_sec_lvl(void);
uint8_t *akes_mac_prepare_command(uint8_t cmd_id, const linkaddr_t *dest);
void akes_mac_send_command_frame(void);
uint8_t akes_mac_mic_len(void);
void akes_mac_aead(uint8_t *key, int shall_encrypt, uint8_t *result, int forward);
int akes_mac_verify(uint8_t *key);
#if MAC_CONF_WITH_CSMA
void akes_mac_input_from_csma(void);
#endif /* MAC_CONF_WITH_CSMA */

#endif /* AKES_MAC_H_ */
