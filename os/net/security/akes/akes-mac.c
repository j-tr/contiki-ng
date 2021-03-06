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

#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes-trickle.h"
#include "net/security/akes/akes.h"
#include "net/mac/csma/csma-ccm-inputs.h"
#include "net/mac/contikimac/contikimac-ccm-inputs.h"
#include "net/mac/contikimac/ilos.h"
#include "net/mac/csl/csl-ccm-inputs.h"
#include "net/mac/csl/csl-framer.h"
#include "net/mac/cmd-broker.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "lib/csprng.h"
#include "lib/random.h"
#include "dev/watchdog.h"
#include "sys/cc.h"
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES-MAC"
#define LOG_LEVEL LOG_LEVEL_MAC

#if AKES_NBR_WITH_GROUP_KEYS
uint8_t akes_mac_group_key[AES_128_KEY_LENGTH];
#endif /* AKES_NBR_WITH_GROUP_KEYS */

/*---------------------------------------------------------------------------*/
clock_time_t
akes_mac_random_clock_time(clock_time_t min, clock_time_t max)
{
  clock_time_t range;
  uint8_t highest_bit;
  clock_time_t random;
  clock_time_t mask;

  range = max - min;
  if(!range) {
    return min;
  }

  highest_bit = (sizeof(clock_time_t) * 8) - 1;
  if((1 << highest_bit) & range) {
    memset(&mask, 0xFF, sizeof(clock_time_t));
  } else {
    do {
      highest_bit--;
    } while(!((1 << highest_bit) & range));
    mask = (1 << (highest_bit + 1)) - 1;
  }

  do {
    random = random_rand() & mask;
  } while(random > range);

  return min + random;
}
/*---------------------------------------------------------------------------*/
uint8_t
akes_mac_get_cmd_id(void)
{
  return ((uint8_t *)packetbuf_dataptr())[0];
}
/*---------------------------------------------------------------------------*/
int
akes_mac_is_hello(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return 0;
  }
  return akes_mac_get_cmd_id() == AKES_HELLO_IDENTIFIER;
}
/*---------------------------------------------------------------------------*/
int
akes_mac_is_helloack(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return 0;
  }

  switch(akes_mac_get_cmd_id()) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    return 1;
  default:
    return 0;
  }
}
/*---------------------------------------------------------------------------*/
int
akes_mac_is_ack(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return 0;
  }
  return akes_mac_get_cmd_id() == AKES_ACK_IDENTIFIER;
}
/*---------------------------------------------------------------------------*/
uint8_t
akes_mac_get_sec_lvl(void)
{
  switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
  case FRAME802154_CMDFRAME:
    switch(akes_mac_get_cmd_id()) {
    case AKES_HELLO_IDENTIFIER:
      return AKES_MAC_BROADCAST_SEC_LVL & 3;
    case AKES_HELLOACK_IDENTIFIER:
    case AKES_HELLOACK_P_IDENTIFIER:
    case AKES_ACK_IDENTIFIER:
      return AKES_ACKS_SEC_LVL;
    case AKES_UPDATE_IDENTIFIER:
#if AKES_DELETE_WITH_UPDATEACKS
    case AKES_UPDATEACK_IDENTIFIER:
#endif /* AKES_DELETE_WITH_UPDATEACKS */
      return AKES_UPDATES_SEC_LVL;
    }
    break;
  case FRAME802154_DATAFRAME:
    return packetbuf_holds_broadcast()
        ? AKES_MAC_BROADCAST_SEC_LVL
        : AKES_MAC_UNICAST_SEC_LVL;
    break;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
#if LLSEC802154_USES_FRAME_COUNTER
void
akes_mac_add_security_header(struct akes_nbr *receiver)
{
  if(!anti_replay_set_counter(receiver ? &receiver->anti_replay_info : NULL)) {
    watchdog_reboot();
  }
#if !ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, akes_mac_get_sec_lvl());
#endif /* !ANTI_REPLAY_WITH_SUPPRESSION */
}
#endif /* LLSEC802154_USES_FRAME_COUNTER */
/*---------------------------------------------------------------------------*/
uint8_t *
akes_mac_prepare_command(uint8_t cmd_id, const linkaddr_t *dest)
{
  uint8_t *payload;

  /* reset packetbuf */
  packetbuf_clear();
  payload = packetbuf_dataptr();

  /* create frame */
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, dest);
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_CMDFRAME);
  payload[0] = cmd_id;

  return payload + 1;
}
/*---------------------------------------------------------------------------*/
void
akes_mac_send_command_frame(void)
{
  AKES_MAC_DECORATED_MAC.send(NULL, NULL);
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  struct akes_nbr_entry *entry;
  struct akes_nbr *receiver;

  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_DATAFRAME);
  if(packetbuf_holds_broadcast()) {
    if(!akes_nbr_count(AKES_NBR_PERMANENT)) {
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
    receiver = NULL;
  } else {
    entry = akes_nbr_get_receiver_entry();
    if(!entry || !entry->permanent) {
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
    receiver = entry->permanent;
#if ANTI_REPLAY_WITH_SUPPRESSION
    packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, akes_nbr_index_of(entry->permanent));
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if MAC_CONF_WITH_CSL
    csl_framer_set_seqno(receiver);
#endif /* MAC_CONF_WITH_CSL */
  }

#if ILOS_ENABLED
  if(receiver) {
    potr_set_seqno(receiver);
  }
#elif POTR_ENABLED
  if(receiver) {
    potr_set_seqno(receiver);
  } else {
    akes_mac_add_security_header(receiver);
    anti_replay_suppress_counter();
  }
#elif LLSEC802154_USES_FRAME_COUNTER
  akes_mac_add_security_header(receiver);
  anti_replay_suppress_counter();
#endif /* LLSEC802154_USES_FRAME_COUNTER */

  AKES_MAC_STRATEGY.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static int
create(void)
{
  int result;

#if POTR_ENABLED && !ILOS_ENABLED
  if(!packetbuf_holds_broadcast()) {
    /* increment frame counter of unicasts in each transmission and retransmission */
    akes_mac_add_security_header(akes_mac_is_helloack()
        ? akes_nbr_get_receiver_entry()->tentative
        : akes_nbr_get_receiver_entry()->permanent);
  }
#endif /* POTR_ENABLED && !ILOS_ENABLED */

  if(akes_mac_is_hello()) {
    akes_create_hello();
  } else if(akes_mac_is_helloack()) {
    if(!akes_create_helloack()) {
      LOG_ERR("HELLOACK creation failed\n");
      return FRAMER_FAILED;
    }
  } else if(akes_mac_is_ack()) {
    akes_create_ack();
  }

  result = AKES_MAC_DECORATED_FRAMER.create();
  if(result == FRAMER_FAILED) {
    LOG_ERR("AKES_MAC_DECORATED_FRAMER failed\n");
    return FRAMER_FAILED;
  }
  if(!AKES_MAC_STRATEGY.on_frame_created()) {
    LOG_ERR("AKES_MAC_STRATEGY failed\n");
    return FRAMER_FAILED;
  }
  return result;
}
/*---------------------------------------------------------------------------*/
static int
parse(void)
{
  return AKES_MAC_DECORATED_FRAMER.parse();
}
/*---------------------------------------------------------------------------*/
uint8_t
akes_mac_mic_len(void)
{
  return packetbuf_holds_broadcast() ? AKES_MAC_BROADCAST_MIC_LEN : AKES_MAC_UNICAST_MIC_LEN;
}
/*---------------------------------------------------------------------------*/
void
akes_mac_aead(uint8_t *key, int shall_encrypt, uint8_t *result, int forward)
{
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  uint8_t *m;
  uint8_t m_len;
  uint8_t *a;
  uint8_t a_len;

  AKES_MAC_STRATEGY.set_nonce(nonce, forward);
  a = packetbuf_hdrptr();
  if(shall_encrypt) {
#if AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES
    a_len = packetbuf_hdrlen() + packetbuf_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES);
#else /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */
    a_len = packetbuf_hdrlen();
#endif /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */
    m = a + a_len;
    m_len = packetbuf_totlen() - a_len;
  } else {
    a_len = packetbuf_totlen();
    m = NULL;
    m_len = 0;
  }

  AES_128_GET_LOCK();
#if MAC_CONF_WITH_CONTIKIMAC
  contikimac_ccm_inputs_set_derived_key(key);
#else /* MAC_CONF_WITH_CONTIKIMAC */
  CCM_STAR.set_key(key);
#endif /* MAC_CONF_WITH_CONTIKIMAC */
  CCM_STAR.aead(nonce,
      m, m_len,
      a, a_len,
      result, akes_mac_mic_len(),
      forward);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
int
akes_mac_verify(uint8_t *key)
{
  int shall_decrypt;
  uint8_t generated_mic[MAX(AKES_MAC_UNICAST_MIC_LEN, AKES_MAC_BROADCAST_MIC_LEN)];

  shall_decrypt = akes_mac_get_sec_lvl() & (1 << 2);
  packetbuf_set_datalen(packetbuf_datalen() - akes_mac_mic_len());
  akes_mac_aead(key, shall_decrypt, generated_mic, 0);

  return memcmp(generated_mic,
      ((uint8_t *) packetbuf_dataptr()) + packetbuf_datalen(),
      akes_mac_mic_len());
}
/*---------------------------------------------------------------------------*/
#if MAC_CONF_WITH_CSMA
static void
input(void)
{
  /* redirect input calls from radio drivers to CSMA */
  csma_driver.input();
}
void
akes_mac_input_from_csma(void)
#else /* MAC_CONF_WITH_CSMA */
static void
input(void)
#endif /* MAC_CONF_WITH_CSMA */
{
  struct akes_nbr_entry *entry;

#if LLSEC802154_USES_AUX_HEADER && POTR_ENABLED
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, akes_mac_get_sec_lvl());
#endif /* LLSEC802154_USES_AUX_HEADER && POTR_ENABLED */

  switch(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE)) {
  case FRAME802154_CMDFRAME:
    cmd_broker_publish();
    break;
  case FRAME802154_DATAFRAME:
    entry = akes_nbr_get_sender_entry();
    if(!entry || !entry->permanent) {
      LOG_ERR("ignored incoming frame\n");
      return;
    }

#if ANTI_REPLAY_WITH_SUPPRESSION && !POTR_ENABLED
    anti_replay_restore_counter(&entry->permanent->anti_replay_info);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION && !POTR_ENABLED */

#if !MAC_CONF_WITH_CSL
    if(
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
        packetbuf_holds_broadcast() &&
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
        AKES_MAC_STRATEGY.verify(entry->permanent) != AKES_MAC_VERIFY_SUCCESS) {
      return;
    }
#endif /* !MAC_CONF_WITH_CSL */

#if MAC_CONF_WITH_CSL
    if(csl_framer_received_duplicate()) {
      LOG_ERR("duplicate\n");
      return;
    }
#else /* MAC_CONF_WITH_CSL */
#if POTR_ENABLED
    if(potr_received_duplicate()) {
      LOG_ERR("duplicate\n");
      return;
    }
#endif /* POTR_ENABLED */
#if !ILOS_ENABLED
    akes_nbr_prolong(entry->permanent);
#endif /* !ILOS_ENABLED */
#endif /* MAC_CONF_WITH_CSL */

    NETSTACK_NETWORK.input();
    break;
  }
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  AKES_MAC_DECORATED_MAC.init();
  cmd_broker_init();
#if AKES_NBR_WITH_GROUP_KEYS
  csprng_rand(akes_mac_group_key, AES_128_KEY_LENGTH);
#endif /* AKES_NBR_WITH_GROUP_KEYS */
  AKES_MAC_STRATEGY.init();
  akes_init();
}
/*---------------------------------------------------------------------------*/
static int
length(void)
{
  return AKES_MAC_DECORATED_FRAMER.length()
#if !ANTI_REPLAY_WITH_SUPPRESSION && !MAC_CONF_WITH_CSL && !POTR_ENABLED
      + 5
#endif /* !ANTI_REPLAY_WITH_SUPPRESSION && !MAC_CONF_WITH_CSL && !POTR_ENABLED */
      + AKES_MAC_STRATEGY.get_overhead();
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  return AKES_MAC_DECORATED_MAC.on();
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  return AKES_MAC_DECORATED_MAC.off();
}
/*---------------------------------------------------------------------------*/
const struct mac_driver akes_mac_driver = {
#if MAC_CONF_WITH_CSL
  "AKES/CSL",
#elif MAC_CONF_WITH_CONTIKIMAC
  "AKES/ContikiMAC",
#else
  "AKES/CSMA",
#endif
  init,
  send,
  input,
  on,
  off,
};
/*---------------------------------------------------------------------------*/
const struct framer akes_mac_framer = {
  length,
  create,
  parse,
};
/*---------------------------------------------------------------------------*/
