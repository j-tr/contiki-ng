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

#include "net/mac/framer/frame802154.h"
#include "net/mac/llsec802154.h"
#include "net/security/akes/akes-nbr.h"
#include "net/security/akes/akes.h"
#include "net/mac/contikimac/contikimac.h"
#include "net/packetbuf.h"
#include "lib/memb.h"
#include "lib/list.h"

#ifdef AKES_NBR_CONF_LIFETIME
#define LIFETIME AKES_NBR_CONF_LIFETIME
#else /* AKES_NBR_CONF_LIFETIME */
#define LIFETIME (60 * 5) /* seconds */
#endif /* AKES_NBR_CONF_LIFETIME */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES-nbr"
#define LOG_LEVEL LOG_LEVEL_MAC

NBR_TABLE(struct akes_nbr_entry, entries_table);
MEMB(nbrs_memb, struct akes_nbr, AKES_NBR_MAX);
MEMB(tentatives_memb, struct akes_nbr_tentative, AKES_NBR_MAX_TENTATIVES);

/*---------------------------------------------------------------------------*/
uint8_t
akes_nbr_index_of(struct akes_nbr *nbr)
{
  return nbr - (struct akes_nbr *)nbrs_memb.mem;
}
/*---------------------------------------------------------------------------*/
struct akes_nbr *
akes_nbr_get_nbr(uint8_t index)
{
  if(index >= AKES_NBR_MAX) {
    return NULL;
  }
  return &((struct akes_nbr *)nbrs_memb.mem)[index];
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_entry_of(struct akes_nbr *nbr)
{
  struct akes_nbr_entry *next;

  next = akes_nbr_head();
  while(next) {
    if((next->tentative == nbr) || (next->permanent == nbr)) {
      return next;
    }
    next = akes_nbr_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_free_tentative_metadata(struct akes_nbr *nbr)
{
  memb_free(&tentatives_memb, nbr->meta);
  nbr->meta = NULL;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_challenge(uint8_t *dest, uint8_t *source)
{
  memcpy(dest, source, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_copy_key(uint8_t *dest, uint8_t *source)
{
  memcpy(dest, source, AES_128_KEY_LENGTH);
}
/*---------------------------------------------------------------------------*/
linkaddr_t *
akes_nbr_get_addr(struct akes_nbr_entry *entry)
{
  return nbr_table_get_lladdr(entries_table, entry);
}
/*---------------------------------------------------------------------------*/
static void
on_entry_change(struct akes_nbr_entry *entry)
{
  if(!entry->permanent && !entry->tentative) {
    nbr_table_remove(entries_table, entry);
  }
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_head(void)
{
  return nbr_table_head(entries_table);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_next(struct akes_nbr_entry *current)
{
  return nbr_table_next(entries_table, current);
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_count(enum akes_nbr_status status)
{
  uint8_t count;
  struct akes_nbr_entry *next;

  count = 0;
  next = akes_nbr_head();
  while(next) {
    if(next->refs[status]) {
      count++;
    }
    next = akes_nbr_next(next);
  }

  return count;
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_free_slots(void)
{
  return memb_numfree(&nbrs_memb);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_new(enum akes_nbr_status status)
{
  struct akes_nbr_entry *entry;

  if(status && (akes_nbr_count(AKES_NBR_TENTATIVE) >= AKES_NBR_MAX_TENTATIVES)) {
    LOG_WARN("too many tentative neighbors\n");
    return NULL;
  }

  entry = akes_nbr_get_sender_entry();
  if(!entry) {
    entry = nbr_table_add_lladdr(entries_table,
        packetbuf_addr(PACKETBUF_ADDR_SENDER),
        NBR_TABLE_REASON_LLSEC,
        NULL);
    if(!entry) {
      LOG_WARN("nbr-table is full\n");
      return NULL;
    }
  }

  AKES_NBR_GET_LOCK();
  entry->refs[status] = memb_alloc(&nbrs_memb);
  if(!entry->refs[status]) {
    LOG_WARN("RAM is running low\n");
    on_entry_change(entry);
    AKES_NBR_RELEASE_LOCK();
    return NULL;
  }
  nbr_table_lock(entries_table, entry);
#if LLSEC802154_USES_FRAME_COUNTER
  anti_replay_init_info(&entry->refs[status]->anti_replay_info);
#endif /* LLSEC802154_USES_FRAME_COUNTER */
  if(status) {
    entry->refs[status]->meta = memb_alloc(&tentatives_memb);
    if(!entry->refs[status]->meta) {
      LOG_WARN("tentatives_memb full\n");
      akes_nbr_delete(entry, status);
      return NULL;
    }
  }
#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
  entry->refs[status]->phase.t = 0;
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
  AKES_NBR_RELEASE_LOCK();
  return entry;
}
/*---------------------------------------------------------------------------*/
#if !MAC_CONF_WITH_CSL && !ILOS_ENABLED
void
akes_nbr_do_prolong(struct akes_nbr *nbr, uint16_t seconds)
{
  nbr->expiration_time = clock_seconds() + seconds;
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_prolong(struct akes_nbr *nbr)
{
#if ANTI_REPLAY_WITH_SUPPRESSION
  int is_broadcast;

  is_broadcast = packetbuf_holds_broadcast();
  if(!is_broadcast && !nbr->last_was_broadcast) {
    return;
  }
  if(is_broadcast && nbr->last_was_broadcast) {
    return;
  }
  nbr->last_was_broadcast = is_broadcast;
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  akes_nbr_do_prolong(nbr, LIFETIME);
}
#endif /* !MAC_CONF_WITH_CSL && !ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_entry(const linkaddr_t *addr)
{
  return nbr_table_get_from_lladdr(entries_table, addr);
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_sender_entry(void)
{
  return akes_nbr_get_entry(packetbuf_addr(PACKETBUF_ADDR_SENDER));
}
/*---------------------------------------------------------------------------*/
struct akes_nbr_entry *
akes_nbr_get_receiver_entry(void)
{
  return akes_nbr_get_entry(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_delete(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
  AKES_NBR_GET_LOCK();
  if(status) {
    akes_nbr_free_tentative_metadata(entry->refs[status]);
  }
  memb_free(&nbrs_memb, entry->refs[status]);
  entry->refs[status] = NULL;
  on_entry_change(entry);
  AKES_NBR_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
int
akes_nbr_is_expired(struct akes_nbr_entry *entry, enum akes_nbr_status status)
{
#if MAC_CONF_WITH_CSL
  rtimer_clock_t delta;

  delta = rtimer_delta(entry->refs[status]->sync_data.t, RTIMER_NOW());
  return delta > (RTIMER_ARCH_SECOND * (status
      ? (AKES_MAX_WAITING_PERIOD + 1 /* leeway */)
      : (entry->permanent->drift != AKES_NBR_UNINITIALIZED_DRIFT
          ? CSL_SUBSEQUENT_UPDATE_THRESHOLD
          : CSL_INITIAL_UPDATE_THRESHOLD)));
#else /* MAC_CONF_WITH_CSL */
#if ILOS_ENABLED
  if(status) {
    return entry->tentative->meta->expiration_time < clock_seconds();
  }
#else /* ILOS_ENABLED */
  if(entry->refs[status]->expiration_time < clock_seconds()) {
    return 1;
  }
#endif /* ILOS_ENABLED */
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#if !ILOS_ENABLED
  if(status) {
    return 0;
  }
#endif /* !ILOS_ENABLED */
  return rtimer_delta(entry->refs[status]->phase.t, RTIMER_NOW())
      >= (LIFETIME * RTIMER_ARCH_SECOND);
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  return 0;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#endif /* MAC_CONF_WITH_CSL */
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_delete_expired_tentatives(void)
{
  struct akes_nbr_entry *next;
  struct akes_nbr_entry *current;

  next = akes_nbr_head();
  while(next) {
    current = next;
    next = akes_nbr_next(current);
    if(current->tentative && akes_nbr_is_expired(current, AKES_NBR_TENTATIVE)) {
      akes_nbr_delete(current, AKES_NBR_TENTATIVE);
    }
  }
}
/*---------------------------------------------------------------------------*/
void
akes_nbr_init(void)
{
  memb_init(&nbrs_memb);
  nbr_table_register(entries_table, NULL);
  memb_init(&tentatives_memb);
}
/*---------------------------------------------------------------------------*/
