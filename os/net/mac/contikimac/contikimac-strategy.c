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
 *         Uses group session keys for securing frames.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/contikimac-strategy.h"
#include "net/mac/contikimac/contikimac-ccm-inputs.h"
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-mac.h"
#include "net/mac/framer/anti-replay.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ContikiMAC-strategy"
#define LOG_LEVEL LOG_LEVEL_DBG

/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  AKES_MAC_DECORATED_MAC.send(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static int
on_frame_created(void)
{
  uint8_t sec_lvl;
  struct akes_nbr_entry *entry;
  uint8_t *key;
#if ILOS_ENABLED
  struct contikimac_phase *phase;
#endif /* ILOS_ENABLED */
  uint8_t datalen;

  sec_lvl = akes_mac_get_sec_lvl();
  if(sec_lvl) {
    entry = akes_nbr_get_receiver_entry();
    if(akes_get_receiver_status() == AKES_NBR_TENTATIVE) {
      if(!entry || !entry->tentative) {
        LOG_ERR_("%02x isn't tentative\n", packetbuf_addr(PACKETBUF_ADDR_RECEIVER)->u8[7]);
        return 0;
      }
      key = entry->tentative->tentative_pairwise_key;
#if ILOS_ENABLED
      phase = NULL;
#endif /* ILOS_ENABLED */
    } else {
#if ILOS_ENABLED
      key = packetbuf_holds_broadcast() ? akes_mac_group_key : entry->permanent->group_key;
      phase = (entry && entry->permanent) ? &entry->permanent->phase : NULL;
#else /* ILOS_ENABLED */
      key = akes_mac_group_key;
#endif /* ILOS_ENABLED */
    }

    datalen = packetbuf_datalen();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    contikimac_cache_unsecured_frame(key
#if ILOS_ENABLED
        , phase
#endif /* ILOS_ENABLED */
    );
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    {
      uint8_t *dataptr;
      dataptr = packetbuf_dataptr();
      akes_mac_aead(key, sec_lvl & (1 << 2), dataptr + datalen, 1);
    }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    packetbuf_set_datalen(datalen + akes_mac_mic_len());
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static enum akes_mac_verify
verify(struct akes_nbr *sender)
{
#if ANTI_REPLAY_WITH_SUPPRESSION
  if(!packetbuf_holds_broadcast()) {
    packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, sender->foreign_index);
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(akes_mac_verify(
#if ILOS_ENABLED
      packetbuf_holds_broadcast()
          ? sender->group_key
          : akes_mac_group_key)) {
#else /* ILOS_ENABLED */
      sender->group_key)) {
#endif /* ILOS_ENABLED */
    LOG_ERR("inauthentic frame\n");
    return AKES_MAC_VERIFY_INAUTHENTIC;
  }

#if !POTR_ENABLED
  if(anti_replay_was_replayed(&sender->anti_replay_info)) {
    LOG_ERR("replayed\n");
    return AKES_MAC_VERIFY_REPLAYED;
  }
#endif /* !POTR_ENABLED */

  return AKES_MAC_VERIFY_SUCCESS;
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_overhead(void)
{
  return akes_mac_mic_len();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
}
/*---------------------------------------------------------------------------*/
const struct akes_mac_strategy contikimac_strategy = {
  contikimac_ccm_inputs_set_nonce,
  send,
  on_frame_created,
  verify,
  get_overhead,
  init
};
/*---------------------------------------------------------------------------*/
