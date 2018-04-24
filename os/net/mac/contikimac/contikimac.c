/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
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
 *         A denial-of-sleep-resilient version of ContikiMAC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/contikimac.h"
#include "net/mac/contikimac/contikimac-ccm-inputs.h"
#include "net/mac/mac.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/mac/contikimac/contikimac-framer.h"
#include "net/mac/contikimac/potr.h"
#include "net/mac/framer/streamer-802154.h"
#include "net/security/akes/akes-mac.h"
#include "net/security/akes/akes.h"
#include "net/security/akes/akes-nbr.h"
#include "net/nbr-table.h"
#include "lib/aes-128.h"
#ifdef LPM_CONF_ENABLE
#include "lpm.h"
#endif /* LPM_CONF_ENABLE */
#include "lib/random.h"

#ifdef CONTIKIMAC_CONF_FLOOR_NOISE
#define FLOOR_NOISE CONTIKIMAC_CONF_FLOOR_NOISE
#else /* CONTIKIMAC_CONF_FLOOR_NOISE */
#define FLOOR_NOISE (-85)
#endif /* CONTIKIMAC_CONF_FLOOR_NOISE */

#ifdef CONTIKIMAC_CONF_SIGNAL_NOISE_DIFF
#define SIGNAL_NOISE_DIFF CONTIKIMAC_CONF_SIGNAL_NOISE_DIFF
#else /* CONTIKIMAC_CONF_SIGNAL_NOISE_DIFF */
#define SIGNAL_NOISE_DIFF (5)
#endif /* CONTIKIMAC_CONF_SIGNAL_NOISE_DIFF */

#ifdef CONTIKIMAC_CONF_CCA_HYSTERESIS
#define CCA_HYSTERESIS CONTIKIMAC_CONF_CCA_HYSTERESIS
#else /* CONTIKIMAC_CONF_CCA_HYSTERESIS */
#define CCA_HYSTERESIS (12)
#endif /* CONTIKIMAC_CONF_CCA_HYSTERESIS */

#ifdef CONTIKIMAC_CONF_MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS CONTIKIMAC_CONF_MAX_RETRANSMISSIONS
#else /* CONTIKIMAC_CONF_MAX_RETRANSMISSIONS */
#define MAX_RETRANSMISSIONS 5
#endif /* CONTIKIMAC_CONF_MAX_RETRANSMISSIONS */

#ifdef CONTIKIMAC_CONF_WITH_DOZING
#define WITH_DOZING CONTIKIMAC_CONF_WITH_DOZING
#else /* CONTIKIMAC_CONF_WITH_DOZING */
#define WITH_DOZING 1
#endif /* CONTIKIMAC_CONF_WITH_DOZING */

#ifdef CONTIKIMAC_CONF_PHASE_LOCK_FREQ_TOLERANCE
#define PHASE_LOCK_FREQ_TOLERANCE CONTIKIMAC_CONF_PHASE_LOCK_FREQ_TOLERANCE
#else /* CONTIKIMAC_CONF_PHASE_LOCK_FREQ_TOLERANCE */
#define PHASE_LOCK_FREQ_TOLERANCE (1)
#endif /* CONTIKIMAC_CONF_PHASE_LOCK_FREQ_TOLERANCE */

#ifdef CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#define WITH_INTRA_COLLISION_AVOIDANCE CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#else /* CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */
#define WITH_INTRA_COLLISION_AVOIDANCE 1
#endif /* CONTIKIMAC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */

#ifdef CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#define WITH_INTER_COLLISION_AVOIDANCE CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#else /* CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE */
#define WITH_INTER_COLLISION_AVOIDANCE 1
#endif /* CONTIKIMAC_CONF_WITH_INTER_COLLISION_AVOIDANCE */

#define WITH_COLLISION_AVOIDANCE (WITH_INTRA_COLLISION_AVOIDANCE || WITH_INTER_COLLISION_AVOIDANCE)

#ifdef CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#define ACKNOWLEDGEMENT_WINDOW_MAX CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#else /* CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */
#define ACKNOWLEDGEMENT_WINDOW_MAX US_TO_RTIMERTICKS(427)
#endif /* CONTIKIMAC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */

/* TODO handle these CC2538-specific adjustments in rtimer.c */
#define LPM_SWITCHING (1)
#define LPM_DEEP_SWITCHING (1)
#ifdef LPM_CONF_ENABLE
#if LPM_CONF_ENABLE
#if (LPM_CONF_MAX_PM == LPM_PM1)
#undef LPM_SWITCHING
#define LPM_SWITCHING (9)
#undef LPM_DEEP_SWITCHING
#define LPM_DEEP_SWITCHING (9)
#elif (LPM_CONF_MAX_PM == LPM_PM2)
#undef LPM_SWITCHING
#define LPM_SWITCHING (9)
#undef LPM_DEEP_SWITCHING
#define LPM_DEEP_SWITCHING (13)
#else
#warning unsupported power mode
#endif
#endif /* LPM_CONF_ENABLE */
#endif /* LPM_CONF_ENABLE */

#define MIN_BACK_OFF_EXPONENT 3
#define MAX_BACK_OFF_EXPONENT 5
#define INTER_FRAME_PERIOD (US_TO_RTIMERTICKS(1068))
#define MAX_CCAS (2)
#define MAX_NOISE (US_TO_RTIMERTICKS(4256) + 1)
#define INTER_CCA_PERIOD (INTER_FRAME_PERIOD - RADIO_ASYNC_RECEIVE_CALIBRATION_TIME)
#define SILENCE_CHECK_PERIOD (US_TO_RTIMERTICKS(250))
#define DOZING_PERIOD (INTER_FRAME_PERIOD \
    - RADIO_ASYNC_RECEIVE_CALIBRATION_TIME \
    - RADIO_ASYNC_CCA_TIME)
#define ACKNOWLEDGEMENT_WINDOW_MIN (US_TO_RTIMERTICKS(336))
#define ACKNOWLEDGEMENT_WINDOW (ACKNOWLEDGEMENT_WINDOW_MAX \
    - ACKNOWLEDGEMENT_WINDOW_MIN \
    + 1)
#define PHASE_LOCK_GUARD_TIME (CONTIKIMAC_WITH_SECURE_PHASE_LOCK \
    ? (2 /* some tolerance */ \
        + ACKNOWLEDGEMENT_WINDOW /* allow for pulse-delay attacks */) \
    : (US_TO_RTIMERTICKS(1000)))
#define FIFOP_THRESHOLD (POTR_ENABLED \
    ? (POTR_HEADER_LEN - POTR_OTP_LEN) \
    : (STREAMER_802154_MIN_BYTES_FOR_FILTERING))

#if WITH_INTRA_COLLISION_AVOIDANCE
#define INTRA_COLLISION_AVOIDANCE_DURATION ((2 * (RADIO_ASYNC_RECEIVE_CALIBRATION_TIME + RADIO_ASYNC_CCA_TIME)) + INTER_CCA_PERIOD)
#else /* WITH_INTRA_COLLISION_AVOIDANCE */
#define INTRA_COLLISION_AVOIDANCE_DURATION (0)
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */

#if POTR_ENABLED
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#define ACKNOWLEDGEMENT_LEN (2 + AKES_MAC_UNICAST_MIC_LEN)
#define HELLOACK_ACKNOWLEDGEMENT_LEN (1)
#define ACK_ACKNOWLEDGEMENT_LEN (ACKNOWLEDGEMENT_LEN + ILOS_WAKE_UP_COUNTER_LEN)
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#define ACKNOWLEDGEMENT_LEN 2
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
#define ACKNOWLEDGEMENT_LEN 3
#endif /* POTR_ENABLED */

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#define EXPECTED_ACKNOWLEDGEMENT_LEN u.strobe.acknowledgement_len
#define MAX_ACKNOWLEDGEMENT_LEN MAX(MAX(ACKNOWLEDGEMENT_LEN, HELLOACK_ACKNOWLEDGEMENT_LEN), ACK_ACKNOWLEDGEMENT_LEN)
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#define EXPECTED_ACKNOWLEDGEMENT_LEN ACKNOWLEDGEMENT_LEN
#define MAX_ACKNOWLEDGEMENT_LEN ACKNOWLEDGEMENT_LEN
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "ContikiMAC"
#define LOG_LEVEL LOG_LEVEL_MAC

enum cca_reason {
  TRANSMISSION_DETECTION,
  SILENCE_DETECTION,
  COLLISION_AVOIDANCE
};

struct buffered_frame {
  struct buffered_frame *next;
  struct queuebuf *qb;
  mac_callback_t sent;
  int transmissions;
  rtimer_clock_t next_attempt;
  void *ptr;
};

static void schedule_duty_cycle(rtimer_clock_t time);
static void duty_cycle_wrapper(struct rtimer *t, void *ptr);
static char duty_cycle(void);
static void on_sfd(void);
static void on_fifop(void);
static void prepare_acknowledgement(void);
static void on_final_fifop(void);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static void create_acknowledgement_mic(void);
static int received_authentic_unicast(void);
static int is_valid_ack(struct akes_nbr_entry *entry);
static int parse_unicast_frame(void);
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
static void on_txdone(void);
static struct buffered_frame *select_next_frame_to_transmit(void);
#if CONTIKIMAC_WITH_PHASE_LOCK
static struct contikimac_phase *obtain_phase_lock_data(void);
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
#if !ILOS_ENABLED
static void strobe_soon(void);
#endif /* !ILOS_ENABLED */
static void schedule_strobe(rtimer_clock_t time);
static void strobe_wrapper(struct rtimer *rt, void *ptr);
static char strobe(void);
static int should_strobe_again(void);
static int transmit(void);
static int is_valid_acknowledgement(void);
static void on_strobed(void);
static void try_skip_to_send(void);
static void queue_frame(mac_callback_t sent, void *ptr);

static union {
  struct {
    int cca_count;
    rtimer_clock_t silence_timeout;
    volatile int got_shr;
    volatile int waiting_for_shr;
    volatile int rejected_frame;
    struct packetbuf local_packetbuf;
    struct packetbuf *actual_packetbuf;
    int shall_send_acknowledgement;
    int got_frame;
    uint8_t acknowledgement[1 /* Frame Length */ + MAX_ACKNOWLEDGEMENT_LEN];
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    int read_and_parsed;
    int is_helloack;
    int is_ack;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  } duty_cycle;

  struct {
    int is_waiting_for_acknowledgement_shr;
    int got_acknowledgement_shr;
    uint8_t prepared_frame[1 /* Frame Length */ + RADIO_ASYNC_MAX_FRAME_LEN];
    int is_broadcast;
    int result;
    rtimer_clock_t next_transmission;
    rtimer_clock_t timeout;
    struct buffered_frame *bf;
    int sent_once_more;
    uint8_t acknowledgement[MAX_ACKNOWLEDGEMENT_LEN];
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    uint8_t acknowledgement_key[AES_128_KEY_LENGTH];
    int is_helloack;
    int is_ack;
    uint8_t acknowledgement_len;
    rtimer_clock_t uncertainty;
    rtimer_clock_t t1[2];
#if ILOS_ENABLED
    wake_up_counter_t receivers_wake_up_counter;
    rtimer_clock_t strobe_start;
#endif /* ILOS_ENABLED */
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    rtimer_clock_t t0[2];
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    uint8_t strobes;
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    uint8_t nonce[13];
    uint8_t shall_encrypt;
    uint8_t a_len;
    uint8_t m_len;
    uint8_t mic_len;
    uint8_t totlen;
    uint8_t unsecured_frame[RADIO_ASYNC_MAX_FRAME_LEN];
    uint8_t key[AES_128_KEY_LENGTH];
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    uint8_t seqno;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  } strobe;
} u;

static int8_t rssi_of_last_transmission;
static struct rtimer timer;
static rtimer_clock_t duty_cycle_next;
static struct pt pt;
static volatile int is_duty_cycling;
static volatile int is_strobing;
static volatile int can_skip;
static volatile int skipped;
PROCESS(post_processing, "post processing");
MEMB(buffered_frames_memb, struct buffered_frame, QUEUEBUF_NUM);
LIST(buffered_frames_list);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static volatile rtimer_clock_t sfd_timestamp;
#if ILOS_ENABLED
static wake_up_counter_t my_wake_up_counter;
static rtimer_clock_t my_wake_up_counter_last_increment;
#endif /* ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

/*---------------------------------------------------------------------------*/
static int
channel_clear(enum cca_reason reason)
{
  int8_t rssi;

  rssi = NETSTACK_RADIO_ASYNC.get_rssi();
  switch(reason) {
  case TRANSMISSION_DETECTION:
    if(rssi < FLOOR_NOISE + SIGNAL_NOISE_DIFF) {
      return 1;
    } else {
      rssi_of_last_transmission = rssi;
      return 0;
    }
  case SILENCE_DETECTION:
    return rssi <= rssi_of_last_transmission - SIGNAL_NOISE_DIFF;
#if WITH_COLLISION_AVOIDANCE
  case COLLISION_AVOIDANCE:
    return rssi < FLOOR_NOISE + CCA_HYSTERESIS;
#endif /* WITH_COLLISION_AVOIDANCE */
  default:
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
static rtimer_clock_t
shift_to_future(rtimer_clock_t time)
{
  /* this assumes that WAKE_UP_COUNTER_INTERVAL is a power of 2 */
  time = (RTIMER_NOW() & (~(WAKE_UP_COUNTER_INTERVAL - 1)))
      | (time & (WAKE_UP_COUNTER_INTERVAL - 1));
  while(!rtimer_is_schedulable(time, RTIMER_GUARD_TIME + 1)) {
    time += WAKE_UP_COUNTER_INTERVAL;
  }

  return time;
}
/*---------------------------------------------------------------------------*/
static void
disable_and_reset_radio(void)
{
  NETSTACK_RADIO_ASYNC.off();
  NETSTACK_RADIO_ASYNC.flushrx();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  LOG_INFO("t_i = %lu\n", INTER_FRAME_PERIOD);
  LOG_INFO("t_c = %lu\n", INTER_CCA_PERIOD);
  LOG_INFO("t_w = %i\n", WAKE_UP_COUNTER_INTERVAL);
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  LOG_INFO("t_a = %lu\n", ACKNOWLEDGEMENT_WINDOW);
  LOG_INFO("t_s = %lu\n", PHASE_LOCK_GUARD_TIME);
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  memb_init(&buffered_frames_memb);
  list_init(buffered_frames_list);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_TXDONE_CALLBACK, on_txdone, 0);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_SFD_CALLBACK, on_sfd, 0);
  process_start(&post_processing, NULL);
  PT_INIT(&pt);
  duty_cycle_next = RTIMER_NOW() + WAKE_UP_COUNTER_INTERVAL;
  schedule_duty_cycle(duty_cycle_next - LPM_DEEP_SWITCHING);
}
/*---------------------------------------------------------------------------*/
static void
schedule_duty_cycle(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, duty_cycle_wrapper, NULL) != RTIMER_OK) {
    LOG_ERR("rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
duty_cycle_wrapper(struct rtimer *rt, void *ptr)
{
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static char
duty_cycle(void)
{
  PT_BEGIN(&pt);

  can_skip = 0;
  is_duty_cycling = 1;
#ifdef LPM_CONF_ENABLE
  lpm_set_max_pm(LPM_PM1);
#endif /* LPM_CONF_ENABLE */
  if(skipped) {
    skipped = 0;
  } else {
#if ILOS_ENABLED
    my_wake_up_counter = contikimac_get_wake_up_counter(contikimac_get_last_wake_up_time());
    my_wake_up_counter_last_increment = contikimac_get_last_wake_up_time();
#endif /* ILOS_ENABLED */

    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
        on_fifop,
        FIFOP_THRESHOLD);

    /* if we come from PM0, we will be too early */
    while(!rtimer_has_timed_out(duty_cycle_next));

    /* CCAs */
    while(1) {
      NETSTACK_RADIO_ASYNC.on();
      if(channel_clear(TRANSMISSION_DETECTION)) {
        NETSTACK_RADIO_ASYNC.off();
        if(++u.duty_cycle.cca_count != MAX_CCAS) {
          schedule_duty_cycle(RTIMER_NOW() + INTER_CCA_PERIOD - LPM_SWITCHING);
          PT_YIELD(&pt);
          /* if we come from PM0, we will be too early */
          while(!rtimer_has_timed_out(timer.time));
          continue;
        }
      } else {
        u.duty_cycle.silence_timeout = RTIMER_NOW() + MAX_NOISE;
      }
      break;
    }

    /* fast-sleep optimization */
    if(u.duty_cycle.silence_timeout) {
      while(1) {

        /* look for silence period */
#if WITH_DOZING
        disable_and_reset_radio();
        schedule_duty_cycle(RTIMER_NOW() + DOZING_PERIOD - LPM_SWITCHING - 2);
        PT_YIELD(&pt);
        NETSTACK_RADIO_ASYNC.on();
#else /* WITH_DOZING */
        schedule_duty_cycle(RTIMER_NOW() + SILENCE_CHECK_PERIOD);
        PT_YIELD(&pt);
#endif /* WITH_DOZING */
        if(channel_clear(SILENCE_DETECTION)) {
#if WITH_DOZING
          /* strangely, this improves reliability */
          NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_SHR_SEARCH, 1);
#else /* WITH_DOZING */
          NETSTACK_RADIO_ASYNC.flushrx();
#endif /* WITH_DOZING */

          /* wait for SHR */
          u.duty_cycle.waiting_for_shr = 1;
          schedule_duty_cycle(RTIMER_NOW()
              + INTER_FRAME_PERIOD
              + RADIO_ASYNC_SHR_TIME
              + 1 /* some tolerance */);
          PT_YIELD(&pt); /* wait until timeout */
          u.duty_cycle.waiting_for_shr = 0;
          if(!u.duty_cycle.got_shr) {
            disable_and_reset_radio();
            LOG_WARN("no SHR detected\n");
          } else {
            PT_YIELD(&pt); /* wait for on_fifop */
            if(!u.duty_cycle.rejected_frame) {
              PT_YIELD(&pt); /* wait for on_final_fifop or on_txdone */
            }
          }
          break;
        } else if(rtimer_has_timed_out(u.duty_cycle.silence_timeout)) {
          disable_and_reset_radio();
          LOG_WARN("noise too long\n");
          break;
        }
      }
    }

    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);
  }

  is_duty_cycling = 0;
  process_poll(&post_processing);

  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
/**
 * Here, we assume that rtimer and radio interrupts have equal priorities,
 * such that they do not preempt each other.
 */
static void
on_sfd(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  rtimer_clock_t now;

  now = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

  if(is_duty_cycling && u.duty_cycle.waiting_for_shr) {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = now;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    u.duty_cycle.got_shr = 1;
  } else if(is_strobing) {
    if(u.strobe.is_waiting_for_acknowledgement_shr) {
      u.strobe.got_acknowledgement_shr = 1;
    }
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = now;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  }
}
/*---------------------------------------------------------------------------*/
static void
enable_local_packetbuf(void)
{
  u.duty_cycle.actual_packetbuf = packetbuf;
  packetbuf = &u.duty_cycle.local_packetbuf;
}
/*---------------------------------------------------------------------------*/
static void
disable_local_packetbuf(void)
{
  packetbuf = u.duty_cycle.actual_packetbuf;
}
/*---------------------------------------------------------------------------*/
#if POTR_ENABLED
static int
is_anything_locked(void)
{
  return aes_128_locked || akes_nbr_locked || nbr_table_locked;
}
#endif /* !POTR_ENABLED */
/*---------------------------------------------------------------------------*/
static void
on_fifop(void)
{
  if(!u.duty_cycle.got_shr) {
    return;
  }

  /* avoid that on_fifop is called twice if FIFOP_THRESHOLD is very low */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 127);
  enable_local_packetbuf();
  if(0
#if POTR_ENABLED
      || is_anything_locked()
#endif /* !POTR_ENABLED */
      || (NETSTACK_RADIO_ASYNC.read_phy_header_and_set_datalen() < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE)
      || !NETSTACK_RADIO_ASYNC.read_payload(FIFOP_THRESHOLD)
#if POTR_ENABLED
      || (potr_parse_and_validate() == FRAMER_FAILED)
#else /* !POTR_ENABLED */
      || (streamer_802154_filter() == FRAMER_FAILED)
#endif /* !POTR_ENABLED */
      ) {
    disable_and_reset_radio();
    LOG_ERR("rejected frame of length %i\n", packetbuf_datalen());
    u.duty_cycle.rejected_frame = 1;
  } else {
    u.duty_cycle.shall_send_acknowledgement = !packetbuf_holds_broadcast();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    u.duty_cycle.is_helloack = akes_mac_is_helloack();
    u.duty_cycle.is_ack = akes_mac_is_ack();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

    if(u.duty_cycle.shall_send_acknowledgement) {
      prepare_acknowledgement();
    }
    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
        on_final_fifop,
        NETSTACK_RADIO_ASYNC.remaining_payload_bytes() + RADIO_ASYNC_CHECKSUM_LEN);
  }
  disable_local_packetbuf();
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static void
prepare_acknowledgement(void)
{
#if POTR_ENABLED
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK

  /* zero */
  memset(u.duty_cycle.acknowledgement, 0, 1 + MAX_ACKNOWLEDGEMENT_LEN);

  /* read strobe index */
  NETSTACK_RADIO_ASYNC.read_payload(1);

  /* create header */
  u.duty_cycle.acknowledgement[1] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  if(u.duty_cycle.is_helloack) {
    u.duty_cycle.acknowledgement[0] = HELLOACK_ACKNOWLEDGEMENT_LEN + RADIO_ASYNC_CHECKSUM_LEN;
  } else {
    u.duty_cycle.acknowledgement[2] = contikimac_get_last_delta();
    if(u.duty_cycle.is_ack) {
#if ILOS_ENABLED
      wake_up_counter_write(u.duty_cycle.acknowledgement + 3, contikimac_get_wake_up_counter(RTIMER_NOW()));
#endif /* ILOS_ENABLED */
      u.duty_cycle.acknowledgement[0] = ACK_ACKNOWLEDGEMENT_LEN + RADIO_ASYNC_CHECKSUM_LEN;
    } else {
      u.duty_cycle.acknowledgement[0] = ACKNOWLEDGEMENT_LEN + RADIO_ASYNC_CHECKSUM_LEN;
      create_acknowledgement_mic();
    }
  }
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  u.duty_cycle.acknowledgement[0] = ACKNOWLEDGEMENT_LEN + RADIO_ASYNC_CHECKSUM_LEN;
  u.duty_cycle.acknowledgement[1] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  u.duty_cycle.acknowledgement[2] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xFF;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
  u.duty_cycle.acknowledgement[0] = ACKNOWLEDGEMENT_LEN + RADIO_ASYNC_CHECKSUM_LEN;
  u.duty_cycle.acknowledgement[1] = FRAME802154_ACKFRAME;
  u.duty_cycle.acknowledgement[2] = 0;
  u.duty_cycle.acknowledgement[3] = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* POTR_ENABLED */
  NETSTACK_RADIO_ASYNC.prepare(u.duty_cycle.acknowledgement);
}
/*---------------------------------------------------------------------------*/
static void
on_final_fifop(void)
{
  /* avoid that on_final_fifop is called twice */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);

  u.duty_cycle.got_frame = 1;
  if(!u.duty_cycle.shall_send_acknowledgement) {
    NETSTACK_RADIO_ASYNC.off();
    duty_cycle();
    return;
  }

  NETSTACK_RADIO_ASYNC.transmit();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(!received_authentic_unicast()) {
    disable_and_reset_radio();
    u.duty_cycle.got_frame = 0;
    LOG_ERR("flushing unicast frame\n");
    duty_cycle();
  } else if(u.duty_cycle.is_ack) {
    enable_local_packetbuf();
    create_acknowledgement_mic();
    NETSTACK_RADIO_ASYNC.reprepare(u.duty_cycle.acknowledgement[0] - RADIO_ASYNC_CHECKSUM_LEN - AKES_MAC_UNICAST_MIC_LEN,
        u.duty_cycle.acknowledgement + 1 + u.duty_cycle.acknowledgement[0] - RADIO_ASYNC_CHECKSUM_LEN - AKES_MAC_UNICAST_MIC_LEN,
        AKES_MAC_UNICAST_MIC_LEN);
    disable_local_packetbuf();
  }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
static void
create_acknowledgement_mic(void)
{
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];

  AES_128_GET_LOCK();
  if(!u.duty_cycle.is_ack) {
    contikimac_ccm_inputs_set_derived_key(akes_nbr_get_sender_entry()->permanent->group_key);
  }
  contikimac_ccm_inputs_set_nonce(nonce, 0);
  contikimac_ccm_inputs_to_acknowledgement_nonce(nonce);
  CCM_STAR.aead(nonce,
      NULL, 0,
      u.duty_cycle.acknowledgement + 1,
      u.duty_cycle.acknowledgement[0] - RADIO_ASYNC_CHECKSUM_LEN - AKES_MAC_UNICAST_MIC_LEN,
      u.duty_cycle.acknowledgement + 1 + u.duty_cycle.acknowledgement[0] - RADIO_ASYNC_CHECKSUM_LEN - AKES_MAC_UNICAST_MIC_LEN,
      AKES_MAC_UNICAST_MIC_LEN,
      1);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
static int
received_authentic_unicast(void)
{
  struct akes_nbr_entry *entry;

  if(u.duty_cycle.is_helloack) {
    /* HELLOACKs are parsed and verified later */
    return 1;
  }

  enable_local_packetbuf();

  u.duty_cycle.read_and_parsed = !is_anything_locked()
      && NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes())
      && parse_unicast_frame()
      && ((entry = akes_nbr_get_sender_entry()))
      && ((!u.duty_cycle.is_ack
          && entry->permanent
          && !AKES_MAC_STRATEGY.verify(entry->permanent))
      || (u.duty_cycle.is_ack
          && is_valid_ack(entry)));

  disable_local_packetbuf();
  return u.duty_cycle.read_and_parsed;
}
/*---------------------------------------------------------------------------*/
static int
is_valid_ack(struct akes_nbr_entry *entry)
{
  uint8_t *payload;

  payload = packetbuf_dataptr();
  payload++;

#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[CONTIKIMAC_Q_LEN + 1 + 1]);
  anti_replay_parse_counter(payload + CONTIKIMAC_Q_LEN + 1 + 1 + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
      packetbuf_datalen() - AES_128_KEY_LENGTH - AKES_MAC_UNICAST_MIC_LEN);

  if((payload[ILOS_WAKE_UP_COUNTER_LEN + CONTIKIMAC_Q_LEN] != entry->tentative->meta->strobe_index)
      || memcmp(payload + ILOS_WAKE_UP_COUNTER_LEN, entry->tentative->meta->q, CONTIKIMAC_Q_LEN)
      || akes_mac_verify(entry->tentative->tentative_pairwise_key)) {
    LOG_ERR("invalid ACK\n");
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return 0;
  } else {
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
static int
parse_unicast_frame(void)
{
  if(NETSTACK_FRAMER.parse() == FRAMER_FAILED) {
    return 0;
  }
#if LLSEC802154_USES_AUX_HEADER && POTR_ENABLED
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, akes_mac_get_sec_lvl());
#endif /* LLSEC802154_USES_AUX_HEADER && POTR_ENABLED */
  return 1;
}
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
on_txdone(void)
{
  if(is_duty_cycling) {
    NETSTACK_RADIO_ASYNC.off();
    duty_cycle();
  } else if(is_strobing) {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
    u.strobe.t1[0] = u.strobe.t1[1];
    u.strobe.t1[1] = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    strobe();
  }
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
contikimac_get_last_wake_up_time(void)
{
  return duty_cycle_next + RADIO_ASYNC_RECEIVE_CALIBRATION_TIME;
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
uint8_t
contikimac_get_last_delta(void)
{
  return sfd_timestamp
      - contikimac_get_last_wake_up_time()
      - INTER_FRAME_PERIOD
      - RADIO_ASYNC_SHR_TIME;
}
/*---------------------------------------------------------------------------*/
uint8_t
contikimac_get_last_strobe_index(void)
{
  return u.strobe.strobes;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
contikimac_get_last_but_one_t1(void)
{
  return u.strobe.t1[0];
}
/*---------------------------------------------------------------------------*/
#if ILOS_ENABLED
rtimer_clock_t
contikimac_get_next_strobe_start(void)
{
  return u.strobe.strobe_start;
}
#endif /* ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(post_processing, ev, data)
{
  int just_received_broadcast;
  struct buffered_frame *next;
#if CONTIKIMAC_WITH_PHASE_LOCK
  struct contikimac_phase *phase;
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    just_received_broadcast = 0;

    /* read received frame */
    if(u.duty_cycle.got_frame) {
      enable_local_packetbuf();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
      if(!u.duty_cycle.read_and_parsed
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
      if(1
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
          && ((!NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes())
              || (NETSTACK_FRAMER.parse() == FRAMER_FAILED)))) {
        LOG_ERR("something went wrong while reading\n");
      } else {
        NETSTACK_RADIO_ASYNC.read_footer();
        just_received_broadcast = packetbuf_holds_broadcast();
        NETSTACK_MAC.input();
      }
      disable_local_packetbuf();
      NETSTACK_RADIO_ASYNC.flushrx();
    }

    /* send queued frames */
    if(!just_received_broadcast) {
      while((next = select_next_frame_to_transmit())) {
        memset(&u.strobe, 0, sizeof(u.strobe));
        u.strobe.bf = next;
        queuebuf_to_packetbuf(u.strobe.bf->qb);
        u.strobe.is_broadcast = packetbuf_holds_broadcast();

#if ILOS_ENABLED
        if(u.strobe.is_broadcast) {
          u.strobe.strobe_start = shift_to_future(contikimac_get_last_wake_up_time())
              - (WAKE_UP_COUNTER_INTERVAL / 2)
              - LPM_SWITCHING
              - INTRA_COLLISION_AVOIDANCE_DURATION
              - RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME;
          if(!(contikimac_get_wake_up_counter(u.strobe.strobe_start).u32 & 1)) {
            u.strobe.strobe_start += WAKE_UP_COUNTER_INTERVAL;
          }
          while(!rtimer_is_schedulable(u.strobe.strobe_start, ILOS_MIN_TIME_TO_STROBE + 1)) {
            u.strobe.strobe_start += 2 * WAKE_UP_COUNTER_INTERVAL;
          }
        } else if(akes_mac_is_helloack()) {
          u.strobe.is_helloack = 1;
          u.strobe.acknowledgement_len = HELLOACK_ACKNOWLEDGEMENT_LEN;
          u.strobe.strobe_start = RTIMER_NOW() + ILOS_MIN_TIME_TO_STROBE;
        } else if(akes_mac_is_ack()) {
          contikimac_ccm_inputs_derive_key(u.strobe.acknowledgement_key, akes_nbr_get_receiver_entry()->tentative->tentative_pairwise_key);
          u.strobe.is_ack = 1;
          u.strobe.acknowledgement_len = ACK_ACKNOWLEDGEMENT_LEN;
          phase = obtain_phase_lock_data();
          if(!phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
          u.strobe.strobe_start = RTIMER_NOW() + ILOS_MIN_TIME_TO_STROBE;
        } else {
          contikimac_ccm_inputs_derive_key(u.strobe.acknowledgement_key, akes_mac_group_key);
          u.strobe.acknowledgement_len = ACKNOWLEDGEMENT_LEN;
          phase = obtain_phase_lock_data();
          if(!phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }

          u.strobe.uncertainty = PHASE_LOCK_GUARD_TIME
              + (PHASE_LOCK_FREQ_TOLERANCE
              * (RTIMERTICKS_TO_S(rtimer_delta(phase->t, RTIMER_NOW())) + 1));
          if(u.strobe.uncertainty >= (WAKE_UP_COUNTER_INTERVAL / 2)) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }

          u.strobe.timeout = shift_to_future(phase->t + u.strobe.uncertainty);
          u.strobe.strobe_start = shift_to_future(phase->t
              - LPM_SWITCHING
              - INTRA_COLLISION_AVOIDANCE_DURATION
              - RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME
              - u.strobe.uncertainty);

          while(!rtimer_is_schedulable(u.strobe.strobe_start, ILOS_MIN_TIME_TO_STROBE + 1)) {
            u.strobe.strobe_start += WAKE_UP_COUNTER_INTERVAL;
          }
          u.strobe.receivers_wake_up_counter.u32 = phase->his_wake_up_counter_at_t.u32
              + wake_up_counter_increments(rtimer_delta(phase->t, u.strobe.strobe_start), NULL)
              + 1;
        }
#endif /* ILOS_ENABLED */

        /* create frame */
#if !POTR_ENABLED
        packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
#endif /* !POTR_ENABLED */
        if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
          u.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }

        /* is this a broadcast? */
#if !CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#if POTR_ENABLED
        u.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xFF;
#else /* POTR_ENABLED */
        u.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* POTR_ENABLED */
#endif /* !CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

        /* move frame to radio */
        u.strobe.prepared_frame[0] = packetbuf_totlen() + RADIO_ASYNC_CHECKSUM_LEN;
        memcpy(u.strobe.prepared_frame + 1, packetbuf_hdrptr(), packetbuf_totlen());
        NETSTACK_RADIO_ASYNC.prepare(u.strobe.prepared_frame);

        /* starting to strobe */
#if ILOS_ENABLED
        if(!rtimer_is_schedulable(u.strobe.strobe_start, RTIMER_GUARD_TIME + 1)) {
          LOG_ERR("strobe starts too early\n");
          u.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }
        schedule_strobe(u.strobe.strobe_start);
#elif CONTIKIMAC_WITH_PHASE_LOCK
        if(u.strobe.is_broadcast) {
          /* strobe broadcast frames immediately */
          strobe_soon();
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
        } else if(akes_mac_is_helloack()) {
          u.strobe.is_helloack = 1;
          u.strobe.acknowledgement_len = HELLOACK_ACKNOWLEDGEMENT_LEN;
          strobe_soon();
        } else if(akes_mac_is_ack()) {
          u.strobe.is_ack = 1;
          contikimac_ccm_inputs_derive_key(u.strobe.acknowledgement_key, akes_nbr_get_receiver_entry()->tentative->tentative_pairwise_key);
          u.strobe.acknowledgement_len = ACK_ACKNOWLEDGEMENT_LEN;
          phase = obtain_phase_lock_data();
          if(!phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
          strobe_soon();
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
        } else {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
          contikimac_ccm_inputs_derive_key(u.strobe.acknowledgement_key, akes_mac_group_key);
          u.strobe.acknowledgement_len = ACKNOWLEDGEMENT_LEN;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
          phase = obtain_phase_lock_data();
          if(!phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
          u.strobe.uncertainty = PHASE_LOCK_GUARD_TIME
              + (PHASE_LOCK_FREQ_TOLERANCE
              * ((rtimer_delta(phase->t, RTIMER_NOW()) / RTIMER_ARCH_SECOND) + 1));
          if(u.strobe.uncertainty >= (WAKE_UP_COUNTER_INTERVAL / 2)) {
            /* uncertainty too high */
            u.strobe.uncertainty = 0;
            strobe_soon();
          } else {
            u.strobe.timeout = shift_to_future(phase->t + u.strobe.uncertainty);
            is_strobing = 1;
            schedule_strobe(shift_to_future(phase->t
                - LPM_SWITCHING
                - INTRA_COLLISION_AVOIDANCE_DURATION
                - RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME
                - u.strobe.uncertainty));
          }
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
          if(!phase->t) {
            /* no phase-lock information stored, yet */
            strobe_soon();
          } else {
            schedule_strobe(shift_to_future(phase->t
                  - LPM_SWITCHING
                  - INTRA_COLLISION_AVOIDANCE_DURATION
                  - RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME
                  - PHASE_LOCK_GUARD_TIME));
          }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
        }
#else /* CONTIKIMAC_WITH_PHASE_LOCK */
        strobe_soon();
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */

        /* process strobe result */
        PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
        u.strobe.bf->transmissions++;
        on_strobed();
      }
    }
#ifdef LPM_CONF_ENABLE
    lpm_set_max_pm(LPM_CONF_MAX_PM);
#endif /* LPM_CONF_ENABLE */

    /* prepare next duty cycle */
    memset(&u.duty_cycle, 0, sizeof(u.duty_cycle));
    duty_cycle_next = shift_to_future(duty_cycle_next);
    while(!rtimer_is_schedulable(duty_cycle_next - LPM_DEEP_SWITCHING, RTIMER_GUARD_TIME + 1)) {
      duty_cycle_next += WAKE_UP_COUNTER_INTERVAL;
    }
    schedule_duty_cycle(duty_cycle_next - LPM_DEEP_SWITCHING);
    can_skip = 1;
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
static struct buffered_frame *
select_next_frame_to_transmit(void)
{
  rtimer_clock_t now;
  struct buffered_frame *next;

  now = RTIMER_NOW();
  next = list_head(buffered_frames_list);
  while(next) {
    if(rtimer_smaller_or_equal(next->next_attempt, now)) {
      if(next->transmissions) {
        LOG_INFO("retransmission %i\n", next->transmissions);
      }
      return next;
    }
    next = list_item_next(next);
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
void
contikimac_cache_unsecured_frame(uint8_t *key
#if ILOS_ENABLED
, struct contikimac_phase *phase
#endif /* ILOS_ENABLED */
)
{
  contikimac_ccm_inputs_set_nonce(u.strobe.nonce, 1);
  u.strobe.shall_encrypt = akes_mac_get_sec_lvl() & (1 << 2);
  if(u.strobe.shall_encrypt) {
    u.strobe.a_len = packetbuf_hdrlen() + packetbuf_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES);
    u.strobe.m_len = packetbuf_totlen() - u.strobe.a_len;
  } else {
    u.strobe.a_len = packetbuf_totlen();
    u.strobe.m_len = 0;
  }
  u.strobe.mic_len = akes_mac_mic_len();
  u.strobe.totlen = packetbuf_totlen();
  memcpy(u.strobe.unsecured_frame, packetbuf_hdrptr(), packetbuf_totlen());
  contikimac_ccm_inputs_derive_key(u.strobe.key, key);
}
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
#if CONTIKIMAC_WITH_PHASE_LOCK
static struct contikimac_phase *
obtain_phase_lock_data(void)
{
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;

  entry = akes_nbr_get_receiver_entry();
  if(!entry) {
    LOG_ERR("no entry found\n");
    return NULL;
  }
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  nbr = entry->permanent;
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  nbr = entry->refs[akes_get_receiver_status()];
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  if(!nbr) {
    LOG_ERR("could not obtain phase-lock data\n");
    return NULL;
  }
  return &nbr->phase;
}
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
#if !ILOS_ENABLED
static void
strobe_soon(void)
{
  schedule_strobe(RTIMER_NOW());
}
#endif /* !ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
static void
schedule_strobe(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, strobe_wrapper, NULL) != RTIMER_OK) {
    LOG_ERR("rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
strobe_wrapper(struct rtimer *rt, void *ptr)
{
  strobe();
}
/*---------------------------------------------------------------------------*/
static char
strobe(void)
{
  PT_BEGIN(&pt);

  is_strobing = 1;

#if WITH_INTRA_COLLISION_AVOIDANCE
  /* enable RX to make a CCA before transmitting */
  u.strobe.next_transmission = RTIMER_NOW() + INTRA_COLLISION_AVOIDANCE_DURATION;
  NETSTACK_RADIO_ASYNC.on();
#else /* WITH_INTRA_COLLISION_AVOIDANCE */
  u.strobe.next_transmission = RTIMER_NOW();
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.uncertainty) {
    /* if we come from PM0, we will be too early */
    while(!rtimer_has_timed_out(timer.time));
  } else
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  {
    u.strobe.timeout = u.strobe.next_transmission + RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME + WAKE_UP_COUNTER_INTERVAL;
  }
  while(1) {
    if(!u.strobe.strobes) {
#if WITH_INTRA_COLLISION_AVOIDANCE
      if(!channel_clear(COLLISION_AVOIDANCE)) {
        LOG_INFO("collision\n");
        u.strobe.result = MAC_TX_COLLISION;
        break;
      }
      NETSTACK_RADIO_ASYNC.off();
      /* do second CCA before starting a burst */
      schedule_strobe(RTIMER_NOW() + INTER_CCA_PERIOD - LPM_SWITCHING);
      PT_YIELD(&pt);
      /* if we come from PM0, we will be too early */
      while(!rtimer_has_timed_out(timer.time));
      NETSTACK_RADIO_ASYNC.on();
      if(!channel_clear(COLLISION_AVOIDANCE)) {
        LOG_INFO("collision\n");
        u.strobe.result = MAC_TX_COLLISION;
        break;
      }
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */
    } else {
#if WITH_INTER_COLLISION_AVOIDANCE
    if(!channel_clear(COLLISION_AVOIDANCE)) {
      LOG_INFO("collision\n");
      u.strobe.result = MAC_TX_COLLISION;
      break;
    }
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
    }

    /* busy waiting for better timing */
    while(!rtimer_has_timed_out(u.strobe.next_transmission));

    if(transmit() != RADIO_TX_OK) {
      LOG_ERR("NETSTACK_RADIO_ASYNC.transmit failed\n");
      u.strobe.result = MAC_TX_ERR;
      break;
    }
    PT_YIELD(&pt);
    u.strobe.next_transmission = RTIMER_NOW()
        + INTER_FRAME_PERIOD
        - RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME
        + 1;

    if(u.strobe.is_broadcast || !u.strobe.strobes /* little tweak */) {
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_OK;
        break;
      }
      NETSTACK_RADIO_ASYNC.off();
      schedule_strobe(u.strobe.next_transmission
#if WITH_INTER_COLLISION_AVOIDANCE
          - RADIO_ASYNC_RECEIVE_CALIBRATION_TIME
          - RADIO_ASYNC_CCA_TIME
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
          - LPM_SWITCHING);
      PT_YIELD(&pt);
#if WITH_INTER_COLLISION_AVOIDANCE
      NETSTACK_RADIO_ASYNC.on();
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
    } else {
      /* wait for acknowledgement */
      schedule_strobe(RTIMER_NOW() + ACKNOWLEDGEMENT_WINDOW_MAX);
      u.strobe.is_waiting_for_acknowledgement_shr = 1;
      PT_YIELD(&pt);
      u.strobe.is_waiting_for_acknowledgement_shr = 0;
      if(u.strobe.got_acknowledgement_shr) {
        if(NETSTACK_RADIO_ASYNC.read_phy_header() != EXPECTED_ACKNOWLEDGEMENT_LEN) {
          LOG_ERR("unexpected frame\n");
          u.strobe.result = MAC_TX_COLLISION;
          break;
        }

        /* read acknowledgement */
        NETSTACK_RADIO_ASYNC.read_raw(u.strobe.acknowledgement, EXPECTED_ACKNOWLEDGEMENT_LEN);
        NETSTACK_RADIO_ASYNC.flushrx();
        if(is_valid_acknowledgement()) {
          u.strobe.result = MAC_TX_OK;
          break;
        }
      }

      /* schedule next transmission */
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_NOACK;
        break;
      }
      if(rtimer_is_schedulable(u.strobe.next_transmission - LPM_SWITCHING, RTIMER_GUARD_TIME + 1)) {
        schedule_strobe(u.strobe.next_transmission - LPM_SWITCHING);
        PT_YIELD(&pt);
      }
    }
    u.strobe.strobes++;
  }

  disable_and_reset_radio();
  is_strobing = 0;
  process_poll(&post_processing);
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
should_strobe_again(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.strobes == 0xFF) {
    LOG_ERR("strobe index reached maximum\n");
    return 0;
  }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  return rtimer_smaller_or_equal(u.strobe.next_transmission + RADIO_ASYNC_TRANSMIT_CALIBRATION_TIME, u.strobe.timeout)
      || !u.strobe.sent_once_more++;
}
/*---------------------------------------------------------------------------*/
static int
transmit(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  uint8_t secured_frame[RADIO_ASYNC_MAX_FRAME_LEN];
  uint8_t *m;
  uint8_t offset;
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

#if CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK
  u.strobe.t0[0] = u.strobe.t0[1];
  u.strobe.t0[1] = RTIMER_NOW();
#endif /* CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK */
  NETSTACK_RADIO_ASYNC.transmit();

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.strobes && u.strobe.is_broadcast) {
    return RADIO_TX_OK;
  }

  if(aes_128_locked) {
    return RADIO_TX_ERR;
  }

  if(!u.strobe.is_broadcast) {
    /* set strobe index */
    u.strobe.unsecured_frame[POTR_HEADER_LEN] = u.strobe.strobes;
    u.strobe.nonce[8] = u.strobe.strobes;
    NETSTACK_RADIO_ASYNC.reprepare(POTR_HEADER_LEN, &u.strobe.strobes, 1);
  }

  memcpy(secured_frame, u.strobe.unsecured_frame, u.strobe.totlen);
  m = u.strobe.shall_encrypt ? (secured_frame + u.strobe.a_len) : NULL;
  AES_128_GET_LOCK();
  CCM_STAR.set_key(u.strobe.key);
  CCM_STAR.aead(u.strobe.nonce,
      m, u.strobe.m_len,
      secured_frame, u.strobe.a_len,
      secured_frame + u.strobe.totlen, u.strobe.mic_len,
      1);
  AES_128_RELEASE_LOCK();
  offset = potr_length_of(u.strobe.unsecured_frame[0]) + CONTIKIMAC_FRAMER_HEADER_LEN;
  NETSTACK_RADIO_ASYNC.reprepare(offset,
      secured_frame + offset,
      u.strobe.totlen + u.strobe.mic_len - offset);
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
static int
is_valid_acknowledgement(void)
{
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  uint8_t expected_mic[AKES_MAC_UNICAST_MIC_LEN];
  rtimer_clock_t diff;

  diff = rtimer_delta(u.strobe.t1[1], sfd_timestamp);
  if((diff < ACKNOWLEDGEMENT_WINDOW_MIN)
      || (diff > ACKNOWLEDGEMENT_WINDOW_MAX)) {
    LOG_ERR("acknowledgement frame wasn't timely\n");
    return 0;
  }
  if(u.strobe.is_helloack) {
    return 1;
  }
  if(aes_128_locked) {
    LOG_WARN("could not validate acknowledgement frame\n");
    return 0;
  }

  memcpy(nonce, u.strobe.nonce, CCM_STAR_NONCE_LENGTH);
  AES_128_GET_LOCK();
  CCM_STAR.set_key(u.strobe.acknowledgement_key);
  contikimac_ccm_inputs_to_acknowledgement_nonce(nonce);
  CCM_STAR.aead(nonce,
      NULL, 0,
      u.strobe.acknowledgement, EXPECTED_ACKNOWLEDGEMENT_LEN - AKES_MAC_UNICAST_MIC_LEN,
      expected_mic, AKES_MAC_UNICAST_MIC_LEN,
      0);
  AES_128_RELEASE_LOCK();
  if(memcmp(expected_mic, u.strobe.acknowledgement + EXPECTED_ACKNOWLEDGEMENT_LEN - AKES_MAC_UNICAST_MIC_LEN, AKES_MAC_UNICAST_MIC_LEN)) {
    LOG_ERR("inauthentic acknowledgement frame\n");
    return 0;
  }
  return 1;
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
  return u.strobe.seqno == u.strobe.acknowledgement[ACKNOWLEDGEMENT_LEN - 1];
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
static void
on_strobed(void)
{
  linkaddr_t *receiver;
  struct buffered_frame *next;
  rtimer_clock_t next_attempt;
  uint8_t back_off_exponent;
  uint8_t back_off_periods;
#if CONTIKIMAC_WITH_PHASE_LOCK
  struct contikimac_phase *phase;
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */

  if(LOG_INFO_ENABLED && !u.strobe.is_broadcast) {
    LOG_INFO("strobed %i times with %s\n",
        u.strobe.strobes + 1,
        (u.strobe.result == MAC_TX_OK) ? "success" : "error");
  }

  switch(u.strobe.result) {
  case MAC_TX_COLLISION:
  case MAC_TX_NOACK:
    if(u.strobe.bf->transmissions
        >= queuebuf_attr(u.strobe.bf->qb, PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
      /* intentionally no break; */
    } else {
      /* delay any frames to that receiver */
      back_off_exponent = MIN(u.strobe.bf->transmissions + MIN_BACK_OFF_EXPONENT,  MAX_BACK_OFF_EXPONENT);
      back_off_periods = ((1 << back_off_exponent) - 1) & random_rand();
      next_attempt = RTIMER_NOW() + (WAKE_UP_COUNTER_INTERVAL * back_off_periods);

      receiver = queuebuf_addr(u.strobe.bf->qb, PACKETBUF_ADDR_RECEIVER);
      next = list_head(buffered_frames_list);
      while(next) {
        if(linkaddr_cmp(receiver, queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
          next->next_attempt = next_attempt;
        }
        next = list_item_next(next);
      }
      break;
    }
  case MAC_TX_OK:
  case MAC_TX_ERR:
  case MAC_TX_ERR_FATAL:
    queuebuf_to_packetbuf(u.strobe.bf->qb);
    queuebuf_free(u.strobe.bf->qb);

#if CONTIKIMAC_WITH_PHASE_LOCK
    if(!u.strobe.is_broadcast
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
        && !u.strobe.is_helloack
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
        && ((phase = obtain_phase_lock_data()))
        && (u.strobe.result == MAC_TX_OK)) {
#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#if ILOS_ENABLED
      if(u.strobe.is_ack) {
        phase->his_wake_up_counter_at_t = wake_up_counter_parse(u.strobe.acknowledgement + 2);
      } else {
        phase->his_wake_up_counter_at_t = wake_up_counter_parse(u.strobe.nonce + 9);
        phase->his_wake_up_counter_at_t.u32 -= 0x40000000;
      }
#endif /* ILOS_ENABLED */
      phase->t = u.strobe.t1[0] - u.strobe.acknowledgement[1];
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
      phase->t = u.strobe.t0[0];
      if(!phase->t) {
        /* zero is reserved for uninitialized phase-lock data */
        phase->t = -WAKE_UP_COUNTER_INTERVAL;
      }
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
    }
#endif /* CONTIKIMAC_WITH_PHASE_LOCK */

    mac_call_sent_callback(u.strobe.bf->sent,
        u.strobe.bf->ptr,
        u.strobe.result,
        u.strobe.bf->transmissions);
    list_remove(buffered_frames_list, u.strobe.bf);
    memb_free(&buffered_frames_memb, u.strobe.bf);
    break;
  }
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  queue_frame(sent, ptr);
  try_skip_to_send();
}
/*---------------------------------------------------------------------------*/
static void
try_skip_to_send(void)
{
  if(!skipped
      && can_skip
      && rtimer_is_schedulable(timer.time, RTIMER_GUARD_TIME + 1)) {
    skipped = 1;
    rtimer_arch_schedule(RTIMER_NOW());
  }
}
/*---------------------------------------------------------------------------*/
static void
queue_frame(mac_callback_t sent, void *ptr)
{
  struct buffered_frame *bf;
  struct buffered_frame *next;

  if(!packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS)) {
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, MAX_RETRANSMISSIONS + 1);
  }

  bf = memb_alloc(&buffered_frames_memb);
  if(!bf) {
    LOG_ERR("buffer is full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }
  bf->qb = queuebuf_new_from_packetbuf();
  if(!bf->qb) {
    LOG_ERR("queubuf is full\n");
    memb_free(&buffered_frames_memb, bf);
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }

  bf->ptr = ptr;
  bf->sent = sent;
  bf->transmissions = 0;
  bf->next_attempt = RTIMER_NOW();
  /* do not send earlier than other frames for that receiver */
  next = list_head(buffered_frames_list);
  while(next) {
    if(linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
        queuebuf_addr(next->qb, PACKETBUF_ADDR_RECEIVER))) {
      bf->next_attempt = next->next_attempt;
      break;
    }
    next = list_item_next(next);
  }
  list_add(buffered_frames_list, bf);
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  /* we operate in polling mode throughout */
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  /* TODO implement if needed */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  /* TODO implement if needed  */
  return 1;
}
/*---------------------------------------------------------------------------*/
#if ILOS_ENABLED
wake_up_counter_t
contikimac_get_wake_up_counter(rtimer_clock_t t)
{
  rtimer_clock_t delta;
  wake_up_counter_t wuc;

  delta = rtimer_delta(my_wake_up_counter_last_increment, t);
  wuc = my_wake_up_counter;
  wuc.u32 += wake_up_counter_increments(delta, NULL);

  return wuc;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
contikimac_predict_wake_up_counter(void)
{
  return u.strobe.receivers_wake_up_counter;
}
/*---------------------------------------------------------------------------*/
wake_up_counter_t
contikimac_restore_wake_up_counter(void)
{
  struct akes_nbr_entry *entry;
  rtimer_clock_t delta;
  uint32_t increments;
  uint32_t mod;
  wake_up_counter_t wuc;

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    wuc.u32 = 0;
    LOG_ERR("could not restore wake-up counter\n");
    return wuc;
  }

  delta = contikimac_get_last_wake_up_time() - entry->permanent->phase.t;
  increments = wake_up_counter_increments(delta, &mod);
  wuc.u32 = entry->permanent->phase.his_wake_up_counter_at_t.u32 + increments;

  if(wuc.u32 & 1) {
    /* odd --> we need to round */
    if(mod < (WAKE_UP_COUNTER_INTERVAL / 2)) {
      wuc.u32--;
    } else  {
      wuc.u32++;
    }
  }

  return wuc;
}
#endif /* ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
const struct mac_driver contikimac_driver = {
  "ContikiMAC",
  init,
  send,
  input,
  on,
  off
};
/*---------------------------------------------------------------------------*/
