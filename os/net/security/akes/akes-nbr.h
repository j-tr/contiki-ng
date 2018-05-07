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
 *         Neighbor management.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef AKES_NBR_H_
#define AKES_NBR_H_

#include "net/mac/framer/anti-replay.h"
#include "net/linkaddr.h"
#include "net/nbr-table.h"
#include "lib/aes-128.h"
#include "sys/clock.h"
#include "sys/ctimer.h"
#include "net/mac/csl/csl.h"
#include "net/mac/contikimac/contikimac.h"
#include "net/mac/contikimac/ilos.h"
#include "net/mac/contikimac/potr.h"

#ifdef AKES_NBR_CONF_MAX_TENTATIVES
#define AKES_NBR_MAX_TENTATIVES AKES_NBR_CONF_MAX_TENTATIVES
#else /* AKES_NBR_CONF_MAX_TENTATIVES */
#define AKES_NBR_MAX_TENTATIVES 5
#endif /* AKES_NBR_CONF_MAX_TENTATIVES */

#ifdef AKES_NBR_CONF_MAX
#define AKES_NBR_MAX AKES_NBR_CONF_MAX
#else /* AKES_NBR_CONF_MAX */
#define AKES_NBR_MAX (NBR_TABLE_MAX_NEIGHBORS + 1)
#endif /* AKES_NBR_CONF_MAX */

#ifdef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_WITH_PAIRWISE_KEYS AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#else /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */
#define AKES_NBR_WITH_PAIRWISE_KEYS 0
#endif /* AKES_NBR_CONF_WITH_PAIRWISE_KEYS */

#ifdef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_WITH_GROUP_KEYS AKES_NBR_CONF_WITH_GROUP_KEYS
#else /* AKES_NBR_CONF_WITH_GROUP_KEYS */
#define AKES_NBR_WITH_GROUP_KEYS 1
#endif /* AKES_NBR_CONF_WITH_GROUP_KEYS */

#ifdef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_WITH_INDICES AKES_NBR_CONF_WITH_INDICES
#else /* AKES_NBR_CONF_WITH_INDICES */
#define AKES_NBR_WITH_INDICES ANTI_REPLAY_WITH_SUPPRESSION
#endif /* AKES_NBR_CONF_WITH_INDICES */

#ifndef AKES_NBR_CONF_WITH_LOCKING
#define AKES_NBR_CONF_WITH_LOCKING 0
#endif /* AKES_NBR_CONF_WITH_LOCKING */
#if AKES_NBR_CONF_WITH_LOCKING
volatile int akes_nbr_locked;
#define AKES_NBR_GET_LOCK() akes_nbr_locked++
#define AKES_NBR_RELEASE_LOCK() akes_nbr_locked--
#else /* AKES_NBR_CONF_WITH_LOCKING */
#define AKES_NBR_GET_LOCK()
#define AKES_NBR_RELEASE_LOCK()
#endif /* AKES_NBR_CONF_WITH_LOCKING */

#define AKES_NBR_CHALLENGE_LEN 8
#define AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN 2
#define AKES_NBR_UNINITIALIZED_DRIFT INT32_MIN

enum akes_nbr_status {
  AKES_NBR_PERMANENT = 0,
  AKES_NBR_TENTATIVE = 1
};

struct akes_nbr_entry {
  union {
    struct akes_nbr *refs[2];
    struct {
      struct akes_nbr *permanent;
      struct akes_nbr *tentative;
    };
  };
};

struct akes_nbr_tentative {
  struct ctimer wait_timer;
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  uint8_t has_wait_timer;
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
#if MAC_CONF_WITH_CSL
  uint8_t q[AKES_NBR_CHALLENGE_LEN];
  rtimer_clock_t helloack_sfd_timestamp;
  wake_up_counter_t predicted_wake_up_counter;
#endif /* MAC_CONF_WITH_CSL */
#if POTR_ENABLED
  potr_otp_t helloack_otp;
  potr_otp_t ack_otp;
#endif /* POTR_ENABLED */
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  uint8_t q[CONTIKIMAC_Q_LEN];
  rtimer_clock_t t1;
  uint8_t strobe_index;
  int was_helloack_sent;
#if ILOS_ENABLED
  unsigned long expiration_time;
#endif /* ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
};

struct akes_nbr {
#if MAC_CONF_WITH_CSL
  struct csl_sync_data sync_data;
#elif !ILOS_ENABLED
  struct anti_replay_info anti_replay_info;
  unsigned long expiration_time;
#endif /* MAC_CONF_WITH_CSL */
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
  struct contikimac_phase phase;
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */

  union {
    /* permanent */
    struct {
#if AKES_NBR_WITH_PAIRWISE_KEYS
      uint8_t pairwise_key[AES_128_KEY_LENGTH];
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
#if AKES_NBR_WITH_GROUP_KEYS
      uint8_t group_key[AES_128_KEY_LENGTH];
#endif /* AKES_NBR_WITH_GROUP_KEYS */
#if AKES_DELETE_WITH_UPDATEACKS
      uint8_t sent_authentic_hello;
#else /* AKES_DELETE_WITH_UPDATEACKS */
      uint8_t sent_authentic_hello:1;
      uint8_t is_receiving_update:1;
#endif /* AKES_DELETE_WITH_UPDATEACKS */
#if !AKES_NBR_WITH_PAIRWISE_KEYS && !POTR_ENABLED
      uint8_t helloack_challenge[AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN];
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS && !POTR_ENABLED */
#if MAC_CONF_WITH_CSL || POTR_ENABLED
      uint8_t my_unicast_seqno;
      uint8_t his_unicast_seqno;
#endif /* MAC_CONF_WITH_CSL || POTR_ENABLED */
#if ANTI_REPLAY_WITH_SUPPRESSION
      uint8_t last_was_broadcast;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if AKES_NBR_WITH_INDICES
      uint8_t foreign_index;
#endif /* AKES_NBR_WITH_INDICES */
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
      struct contikimac_phase phase;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#if MAC_CONF_WITH_CSL
      int32_t drift;
      struct csl_sync_data historical_sync_data;
#endif /* MAC_CONF_WITH_CSL */
    };

    /* tentative */
    struct {
      union {
        struct {
          uint8_t challenge[AKES_NBR_CHALLENGE_LEN];
        };

        struct {
          uint8_t tentative_pairwise_key[AES_128_KEY_LENGTH];
        };
      };

      struct akes_nbr_tentative *meta;
    };
  };
};

uint8_t akes_nbr_index_of(struct akes_nbr *nbr);
struct akes_nbr *akes_nbr_get_nbr(uint8_t index);
struct akes_nbr_entry *akes_nbr_get_entry_of(struct akes_nbr *nbr);
void akes_nbr_free_tentative_metadata(struct akes_nbr *nbr);
void akes_nbr_copy_challenge(uint8_t *dest, uint8_t *source);
void akes_nbr_copy_key(uint8_t *dest, uint8_t *source);
linkaddr_t *akes_nbr_get_addr(struct akes_nbr_entry *entry);
struct akes_nbr_entry *akes_nbr_head(void);
struct akes_nbr_entry *akes_nbr_next(struct akes_nbr_entry *current);
int akes_nbr_count(enum akes_nbr_status status);
int akes_nbr_free_slots(void);
struct akes_nbr_entry *akes_nbr_new(enum akes_nbr_status status);
#if !MAC_CONF_WITH_CSL && !ILOS_ENABLED
void akes_nbr_do_prolong(struct akes_nbr *nbr, uint16_t seconds);
void akes_nbr_prolong(struct akes_nbr *nbr);
#endif /* !MAC_CONF_WITH_CSL && !ILOS_ENABLED */
struct akes_nbr_entry *akes_nbr_get_entry(const linkaddr_t *addr);
struct akes_nbr_entry *akes_nbr_get_sender_entry(void);
struct akes_nbr_entry *akes_nbr_get_receiver_entry(void);
void akes_nbr_delete(struct akes_nbr_entry *entry, enum akes_nbr_status status);
int akes_nbr_is_expired(struct akes_nbr_entry *entry, enum akes_nbr_status status);
void akes_nbr_delete_expired_tentatives(void);
void akes_nbr_init(void);
#if POTR_ENABLED
/* declared here to avoid compilation errors */
void potr_set_seqno(struct akes_nbr *receiver);
#endif /* POTR_ENABLED */

#endif /* AKES_NBR_H_ */
