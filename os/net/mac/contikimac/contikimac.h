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

#ifndef CONTIKIMAC_H_
#define CONTIKIMAC_H_

#include "net/mac/mac.h"
#include "net/mac/contikimac/potr.h"
#include "sys/rtimer.h"
#include "net/netstack.h"
#include "net/mac/contikimac/ilos.h"

#if !MAC_CONF_WITH_CONTIKIMAC || !POTR_ENABLED
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK 0
#else /* !POTR_ENABLED */
#ifdef CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK
#else /* CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK */
#define CONTIKIMAC_WITH_SECURE_PHASE_LOCK 1
#endif /* CONTIKIMAC_CONF_WITH_SECURE_PHASE_LOCK */
#endif /* !POTR_ENABLED */

#if !MAC_CONF_WITH_CONTIKIMAC || CONTIKIMAC_WITH_SECURE_PHASE_LOCK
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK 0
#else /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */
#ifdef CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK
#else /* CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#define CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK 0
#endif /* CONTIKIMAC_CONF_WITH_ORIGINAL_PHASE_LOCK */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

#define CONTIKIMAC_WITH_PHASE_LOCK (CONTIKIMAC_WITH_SECURE_PHASE_LOCK || CONTIKIMAC_WITH_ORIGINAL_PHASE_LOCK)
#define CONTIKIMAC_Q_LEN (CONTIKIMAC_WITH_SECURE_PHASE_LOCK ? 4 : 0)

#if CONTIKIMAC_WITH_SECURE_PHASE_LOCK
uint8_t contikimac_get_last_delta(void);
uint8_t contikimac_get_last_strobe_index(void);
rtimer_clock_t contikimac_get_last_but_one_t1(void);
void contikimac_cache_unsecured_frame(uint8_t *key
#if ILOS_ENABLED
    , struct contikimac_phase *phase
#endif /* ILOS_ENABLED */
);
int potr_has_strobe_index(enum potr_frame_type type);
rtimer_clock_t contikimac_get_last_wake_up_time(void);
#if ILOS_ENABLED
rtimer_clock_t contikimac_get_next_strobe_start(void);
wake_up_counter_t contikimac_get_wake_up_counter(rtimer_clock_t t);
wake_up_counter_t contikimac_predict_wake_up_counter(void);
wake_up_counter_t contikimac_restore_wake_up_counter(void);
#endif /* ILOS_ENABLED */
#endif /* CONTIKIMAC_WITH_SECURE_PHASE_LOCK */

extern const struct mac_driver contikimac_driver;

#endif /* CONTIKIMAC_H_ */
