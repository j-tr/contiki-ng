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
 *         Adaptive Key Establishment Scheme (AKES).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/security/akes/akes.h"
#include "net/security/akes/akes-delete.h"
#include "net/security/akes/akes-trickle.h"
#include "net/security/akes/akes-mac.h"
#include "net/mac/cmd-broker.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "lib/csprng.h"
#include "lib/memb.h"
#include "lib/leaky-bucket.h"
#include "net/mac/csl/csl.h"
#include "net/mac/csl/csl-framer.h"
#include <string.h>

#ifdef AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS
#else /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */
#define MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS (1)
#endif /* AKES_CONF_MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS */

#ifdef AKES_CONF_MAX_RETRANSMISSION_BACK_OFF
#define MAX_RETRANSMISSION_BACK_OFF AKES_CONF_MAX_RETRANSMISSION_BACK_OFF
#else /* AKES_CONF_MAX_RETRANSMISSION_BACK_OFF */
#define MAX_RETRANSMISSION_BACK_OFF (2) /* seconds */
#endif /* AKES_CONF_MAX_RETRANSMISSION_BACK_OFF */

#ifdef AKES_CONF_MAX_HELLO_RATE
#define MAX_HELLO_RATE AKES_CONF_MAX_HELLO_RATE
#else /* AKES_CONF_MAX_HELLO_RATE */
#define MAX_HELLO_RATE (5 * 60) /* 1 HELLO per 5min */
#endif /* AKES_CONF_MAX_HELLO_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOS
#define MAX_CONSECUTIVE_HELLOS AKES_CONF_MAX_CONSECUTIVE_HELLOS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */
#define MAX_CONSECUTIVE_HELLOS (10)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */

#ifdef AKES_CONF_MAX_HELLOACK_RATE
#define MAX_HELLOACK_RATE AKES_CONF_MAX_HELLOACK_RATE
#else /* AKES_CONF_MAX_HELLOACK_RATE */
#define MAX_HELLOACK_RATE (150) /* 1 HELLOACK per 150s */
#endif /* AKES_CONF_MAX_HELLOACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#define MAX_CONSECUTIVE_HELLOACKS AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */
#define MAX_CONSECUTIVE_HELLOACKS (20)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */

#ifdef AKES_CONF_MAX_ACK_RATE
#define MAX_ACK_RATE AKES_CONF_MAX_ACK_RATE
#else /* AKES_CONF_MAX_ACK_RATE */
#define MAX_ACK_RATE MAX_HELLOACK_RATE
#endif /* AKES_CONF_MAX_ACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_ACKS
#define MAX_CONSECUTIVE_ACKS AKES_CONF_MAX_CONSECUTIVE_ACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_ACKS */
#define MAX_CONSECUTIVE_ACKS MAX_CONSECUTIVE_HELLOACKS
#endif /* AKES_CONF_MAX_CONSECUTIVE_ACKS */

#define MAX_HELLOACK_DELAY ((AKES_MAX_WAITING_PERIOD * CLOCK_SECOND) \
    - (MAX_RETRANSMISSION_BACK_OFF * CLOCK_SECOND))

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "AKES"
#define LOG_LEVEL LOG_LEVEL_MAC

static void on_hello_sent(void *ptr, int status, int transmissions);
static void on_hello_done(void *ptr);
static void send_helloack(void *ptr);
static void send_ack(struct akes_nbr_entry *entry, int is_new);
static void on_ack_sent(void *ptr, int status, int transmissions);

/* A random challenge, which will be attached to HELLO commands */
static uint8_t hello_challenge[AKES_NBR_CHALLENGE_LEN];
static int is_awaiting_helloacks;
static struct ctimer hello_timer;
static struct cmd_broker_subscription subscription;
static struct leaky_bucket hello_bucket;
static struct leaky_bucket helloack_bucket;
static struct leaky_bucket ack_bucket;
static uint8_t q[AKES_NBR_CHALLENGE_LEN];
static rtimer_clock_t phi_2;

/*---------------------------------------------------------------------------*/
static void
prepare_update_command(uint8_t cmd_id,
    struct akes_nbr_entry *entry,
    enum akes_nbr_status status)
{
  uint8_t *payload;
  uint8_t payload_len;

  payload = akes_mac_prepare_command(cmd_id, akes_nbr_get_addr(entry));
  if(cmd_id == AKES_UPDATE_IDENTIFIER) {
    csl_framer_set_seqno(entry->permanent);
  }

  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS,
        MAX_RETRANSMISSIONS_OF_HELLOACKS_AND_ACKS + 1);
    break;
  default:
    break;
  }

  /* write payload */
  if(status) {
    akes_nbr_copy_challenge(payload, entry->tentative->challenge);
    payload += AKES_NBR_CHALLENGE_LEN;
    payload += CSL_FRAMER_HELLOACK_PIGGYBACK_LEN;
  }

  if(cmd_id == AKES_ACK_IDENTIFIER) {
    csl_framer_write_phase(payload, phi_2);
    payload += CSL_FRAMER_PHASE_LEN;
    akes_nbr_copy_challenge(payload, q);
    payload += AKES_NBR_CHALLENGE_LEN;
  }

  payload[0] = akes_nbr_index_of(entry->refs[status]);
  payload++;

  payload_len = payload - ((uint8_t *)packetbuf_hdrptr());
  packetbuf_set_datalen(payload_len);
}
/*---------------------------------------------------------------------------*/
static void
process_update_command(struct akes_nbr *nbr, uint8_t *data, int cmd_id)
{
  switch(cmd_id) {
  case AKES_ACK_IDENTIFIER:
    nbr->sync_data.his_wake_up_counter_at_t = nbr->meta->predicted_wake_up_counter;
    nbr->sync_data.t = nbr->meta->helloack_sfd_timestamp
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_parse_phase(data));
    data += CSL_FRAMER_ACK_PIGGYBACK_LEN;
    nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
    nbr->historical_sync_data = nbr->sync_data;
    akes_nbr_free_tentative_metadata(nbr);
    nbr->sent_authentic_hello = 1;
    break;
  case AKES_HELLOACK_IDENTIFIER:
    nbr->sync_data.t = csl_get_last_sfd_timestamp()
        - (WAKE_UP_COUNTER_INTERVAL - csl_framer_parse_phase(data));
    data += CSL_FRAMER_PHASE_LEN;
    nbr->sync_data.his_wake_up_counter_at_t = wake_up_counter_parse(data);
    data +=  WAKE_UP_COUNTER_LEN;
    akes_nbr_copy_challenge(q, data);
    data += AKES_NBR_CHALLENGE_LEN;
    phi_2 = csl_get_phase(csl_get_last_sfd_timestamp());
    nbr->drift = AKES_NBR_UNINITIALIZED_DRIFT;
    nbr->sent_authentic_hello = 0;
    break;
  }

  nbr->foreign_index = data[0];
  data++;

  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    nbr->my_unicast_seqno = 0;
    nbr->his_unicast_seqno = 0;
    break;
  default:
    break;
  }
}
/*---------------------------------------------------------------------------*/
/*
 * We use AES-128 as a key derivation function (KDF). This is possible due to
 * simple circumstances. Speaking in terms of the extract-then-expand paradigm
 * [RFC 5869], we can skip over the extraction step since we already have a
 * uniformly-distributed key which we want to expand into session keys. For
 * implementing the expansion step, we may just use AES-128 [Paar and Pelzl,
 * Understanding Cryptography].
 */
static void
generate_pairwise_key(uint8_t *result, uint8_t *shared_secret)
{
  AES_128_GET_LOCK();
  AES_128.set_key(shared_secret);
  AES_128.encrypt(result);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
static void
change_hello_challenge(void)
{
  csprng_rand(hello_challenge, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_broadcast_hello(void)
{
  uint8_t *payload;

  if(is_awaiting_helloacks) {
    LOG_WARN("still waiting for HELLOACKs\n");
    return;
  }

  if(leaky_bucket_is_full(&hello_bucket)) {
    LOG_WARN("HELLO bucket is full\n");
    return;
  }
  leaky_bucket_pour(&hello_bucket);

  payload = akes_mac_prepare_command(AKES_HELLO_IDENTIFIER, &linkaddr_null);

  /* write payload */
  akes_nbr_copy_challenge(payload, hello_challenge);
  payload += AKES_NBR_CHALLENGE_LEN;

  packetbuf_set_datalen(AKES_HELLO_DATALEN);

  LOG_INFO("broadcasting HELLO\n");
  AKES_MAC_STRATEGY.send(on_hello_sent, NULL);
}
/*---------------------------------------------------------------------------*/
void
akes_create_hello(void)
{
  uint8_t *dataptr;

  dataptr = packetbuf_dataptr();
  wake_up_counter_write(dataptr + 1 + AKES_NBR_CHALLENGE_LEN,
      csl_get_wake_up_counter(csl_get_payload_frames_shr_end()));
}
/*---------------------------------------------------------------------------*/
static void
on_hello_sent(void *ptr, int status, int transmissions)
{
  is_awaiting_helloacks = 1;
  ctimer_set(&hello_timer,
      AKES_MAX_WAITING_PERIOD * CLOCK_SECOND,
      on_hello_done,
      NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_hello_done(void *ptr)
{
  is_awaiting_helloacks = 0;
  change_hello_challenge();
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_hello(void)
{
  struct akes_nbr_entry *entry;

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();

  return (entry && entry->permanent)
      || (!(entry && entry->tentative)
      && !leaky_bucket_is_full(&helloack_bucket)
      && (akes_nbr_count(AKES_NBR_TENTATIVE) < AKES_NBR_MAX_TENTATIVES)
      && akes_nbr_free_slots());
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_hello(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  clock_time_t waiting_period;

  LOG_INFO("received HELLO\n");

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();

  if(entry && entry->permanent) {
    switch(AKES_MAC_STRATEGY.verify(entry->permanent)) {
    case AKES_MAC_VERIFY_SUCCESS:
      leaky_bucket_effuse(&csl_hello_inc_bucket);
      akes_trickle_on_fresh_authentic_hello(entry->permanent);
      return CMD_BROKER_CONSUMED;
    case AKES_MAC_VERIFY_INAUTHENTIC:
      LOG_INFO("starting new session with permanent neighbor\n");
      break;
    }
  }

  if(leaky_bucket_is_full(&helloack_bucket)) {
    LOG_WARN("HELLOACK bucket is full\n");
    return CMD_BROKER_ERROR;
  }

  if(entry && entry->tentative) {
    LOG_WARN("received HELLO from tentative neighbor\n");
    return CMD_BROKER_ERROR;
  }

  /* Create tentative neighbor */
  entry = akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry) {
    LOG_WARN("HELLO flood?\n");
    return CMD_BROKER_ERROR;
  }

  leaky_bucket_pour(&helloack_bucket);

  akes_nbr_copy_challenge(entry->tentative->challenge, payload);
  waiting_period = akes_mac_random_clock_time(0, MAX_HELLOACK_DELAY);
  entry->tentative->sync_data.t = csl_get_last_sfd_timestamp()
      - (WAKE_UP_COUNTER_INTERVAL / 2);
  entry->tentative->sync_data.his_wake_up_counter_at_t =
      wake_up_counter_parse(payload + AKES_NBR_CHALLENGE_LEN);
  ctimer_set(&entry->tentative->meta->wait_timer,
      waiting_period,
      send_helloack,
      entry);
  LOG_INFO("will send HELLOACK in %lus\n", waiting_period / CLOCK_SECOND);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(void *ptr)
{
  struct akes_nbr_entry *entry;
  uint8_t challenges[2 * AKES_NBR_CHALLENGE_LEN];
  uint8_t *secret;

  LOG_INFO("sending HELLOACK\n");

  entry = (struct akes_nbr_entry *)ptr;
  akes_nbr_copy_challenge(challenges, entry->tentative->challenge);
  csprng_rand(challenges + AKES_NBR_CHALLENGE_LEN, AKES_NBR_CHALLENGE_LEN);
  akes_nbr_copy_challenge(entry->tentative->challenge, challenges + AKES_NBR_CHALLENGE_LEN);

  /* write payload */
  prepare_update_command(entry->permanent ? AKES_HELLOACK_P_IDENTIFIER : AKES_HELLOACK_IDENTIFIER,
      entry,
      AKES_NBR_TENTATIVE);

  /* generate pairwise key */
  secret = AKES_SCHEME.get_secret_with_hello_sender(akes_nbr_get_addr(entry));
  if(!secret) {
    LOG_ERR("no secret with HELLO sender\n");
    return;
  }
  generate_pairwise_key(challenges, secret);
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, challenges);

  akes_mac_send_command_frame();
}
/*---------------------------------------------------------------------------*/
int
akes_create_helloack(void)
{
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;
  uint8_t *dataptr;

  entry = akes_nbr_get_receiver_entry();
  if(!entry || !((nbr = entry->tentative))) {
    return 0;
  }

  dataptr = packetbuf_dataptr();
  entry->tentative->meta->helloack_sfd_timestamp = csl_get_payload_frames_shr_end();
  csprng_rand(nbr->meta->q, AKES_NBR_CHALLENGE_LEN);
  nbr->meta->predicted_wake_up_counter = csl_predict_wake_up_counter();

  dataptr += 1 + AKES_NBR_CHALLENGE_LEN;
  csl_framer_write_phase(dataptr,
      csl_get_phase(entry->tentative->meta->helloack_sfd_timestamp));
  dataptr += CSL_FRAMER_PHASE_LEN;
  wake_up_counter_write(dataptr,
      csl_get_wake_up_counter(entry->tentative->meta->helloack_sfd_timestamp));
  dataptr += WAKE_UP_COUNTER_LEN;
  akes_nbr_copy_challenge(dataptr, nbr->meta->q);
  return 1;
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_helloack(void)
{
  if(!is_awaiting_helloacks
      || leaky_bucket_is_full(&ack_bucket)) {
    LOG_ERR("unacceptable ACK\n");
    return 0;
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_helloack(uint8_t *payload, int p_flag)
{
  struct akes_nbr_entry *entry;
  uint8_t *secret;
  uint8_t key[AKES_NBR_CHALLENGE_LEN * 2];
  int is_new;

  LOG_INFO("received HELLOACK\n");

  if(!akes_is_acceptable_helloack()) {
    return CMD_BROKER_ERROR;
  }

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();
  if(entry && entry->permanent && p_flag) {
    LOG_INFO("no need to start a new session\n");
    return CMD_BROKER_ERROR;
  }

  secret = AKES_SCHEME.get_secret_with_helloack_sender(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  if(!secret) {
    LOG_ERR("no secret with HELLOACK sender\n");
    return CMD_BROKER_ERROR;
  }

  /* copy challenges and generate key */
  akes_nbr_copy_challenge(key, hello_challenge);
  akes_nbr_copy_challenge(key + AKES_NBR_CHALLENGE_LEN, payload);
  generate_pairwise_key(key, secret);

  if(akes_mac_verify(key)) {
    LOG_ERR("invalid HELLOACK\n");
    return CMD_BROKER_ERROR;
  }

  is_new = 1;
  if(entry) {
    if(entry->permanent) {
      if(!memcmp(key, entry->permanent->pairwise_key, AES_128_KEY_LENGTH)) {
        LOG_ERR("replayed HELLOACK\n");
        return CMD_BROKER_ERROR;
      } else {
        akes_nbr_delete(entry, AKES_NBR_PERMANENT);
        is_new = 0;
      }
    }

    if(entry->tentative) {
      if(ctimer_expired(&entry->tentative->meta->wait_timer)) {
        LOG_WARN("awaiting ACK\n");
        leaky_bucket_effuse(&csl_helloack_inc_bucket);
        return CMD_BROKER_ERROR;
      } else {
        LOG_INFO("skipping HELLOACK\n");
        ctimer_stop(&entry->tentative->meta->wait_timer);
        akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
      }
    }
  }
  leaky_bucket_effuse(&csl_helloack_inc_bucket);

  entry = akes_nbr_new(AKES_NBR_PERMANENT);
  if(!entry) {
    return CMD_BROKER_ERROR;
  }

  akes_nbr_copy_key(entry->permanent->pairwise_key, key);
  process_update_command(entry->permanent,
      payload + AKES_NBR_CHALLENGE_LEN,
      AKES_HELLOACK_IDENTIFIER);
  send_ack(entry, is_new);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct akes_nbr_entry *entry, int is_new)
{
  LOG_INFO("sending ACK\n");
  leaky_bucket_pour(&ack_bucket);
  prepare_update_command(AKES_ACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  AKES_MAC_DECORATED_MAC.send(on_ack_sent, is_new ? entry : NULL);
}
/*---------------------------------------------------------------------------*/
void
akes_create_ack(void)
{
}
/*---------------------------------------------------------------------------*/
static void
on_ack_sent(void *is_new, int status, int transmissions)
{
  struct akes_nbr_entry *entry;

  if(status == MAC_TX_DEFERRED) {
    return;
  }

  entry = akes_nbr_get_receiver_entry();
  if(!entry
      || (!entry->permanent)) {
    LOG_ERR("this should never happen\n");
    return;
  }
  if(status != MAC_TX_OK) {
    LOG_ERR("ACK was not acknowledged\n");
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return;
  }
  if(is_new) {
    akes_trickle_on_new_nbr();
  }
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_ack(struct akes_nbr_entry *entry)
{
  return entry
      && entry->tentative
      && ctimer_expired(&entry->tentative->meta->wait_timer);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_ack(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  int is_new;

  LOG_INFO("received ACK\n");

  entry = akes_nbr_get_sender_entry();

  if(entry->permanent) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    is_new = 0;
  } else {
    is_new = 1;
  }
  entry->permanent = entry->tentative;
  entry->tentative = NULL;
  process_update_command(entry->permanent, payload, AKES_ACK_IDENTIFIER);
  if(is_new) {
    akes_trickle_on_new_nbr();
  }

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
void
akes_send_update(struct akes_nbr_entry *entry)
{
  prepare_update_command(AKES_UPDATE_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  AKES_MAC_DECORATED_MAC.send(akes_delete_on_update_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_update(uint8_t cmd_id, uint8_t *payload)
{
  LOG_INFO("received %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");

  if(csl_framer_received_duplicate()) {
    LOG_ERR("duplicated UPDATE\n");
    return CMD_BROKER_ERROR;
  }

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    return on_hello(payload);
  case AKES_HELLOACK_IDENTIFIER:
    return on_helloack(payload, 0);
  case AKES_HELLOACK_P_IDENTIFIER:
    return on_helloack(payload, 1);
  case AKES_ACK_IDENTIFIER:
    return on_ack(payload);
  case AKES_UPDATE_IDENTIFIER:
    return on_update(cmd_id, payload);
  default:
    return CMD_BROKER_UNCONSUMED;
  }
}
/*---------------------------------------------------------------------------*/
enum akes_nbr_status
akes_get_receiver_status(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return AKES_NBR_PERMANENT;
  }

  switch(akes_mac_get_cmd_id()) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    return AKES_NBR_TENTATIVE;
  default:
    return AKES_NBR_PERMANENT;
  }
}
/*---------------------------------------------------------------------------*/
void
akes_init(void)
{
  leaky_bucket_init(&hello_bucket, MAX_CONSECUTIVE_HELLOS, MAX_HELLO_RATE);
  leaky_bucket_init(&helloack_bucket, MAX_CONSECUTIVE_HELLOACKS, MAX_HELLOACK_RATE);
  leaky_bucket_init(&ack_bucket, MAX_CONSECUTIVE_ACKS, MAX_ACK_RATE);
  subscription.on_command = on_command;
  cmd_broker_subscribe(&subscription);
  akes_nbr_init();
  AKES_SCHEME.init();
  akes_delete_init();
  change_hello_challenge();
  akes_trickle_start();
}
/*---------------------------------------------------------------------------*/
