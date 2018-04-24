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
 *         Autoconfigures the akes_mac_driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

/* configure Contiki */
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC akes_mac_driver
#undef NETSTACK_CONF_FRAMER
#define NETSTACK_CONF_FRAMER akes_mac_framer
#undef CSMA_CONF_WITH_AKES
#define CSMA_CONF_WITH_AKES 1
#undef NBR_TABLE_CONF_WITH_FIND_REMOVABLE
#define NBR_TABLE_CONF_WITH_FIND_REMOVABLE 0
#undef SICSLOWPAN_CONF_INIT_QUEUEBUF
#define SICSLOWPAN_CONF_INIT_QUEUEBUF 0
#undef LLSEC802154_CONF_USES_FRAME_COUNTER
#define LLSEC802154_CONF_USES_FRAME_COUNTER 1
#undef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 1
#undef CSPRNG_CONF_ENABLED
#define CSPRNG_CONF_ENABLED 1

/* configure AKES */
#undef AKES_MAC_CONF_ENABLED
#define AKES_MAC_CONF_ENABLED 1
#undef AKES_MAC_CONF_DECORATED_MAC
#define AKES_MAC_CONF_DECORATED_MAC csma_driver
#undef AKES_MAC_CONF_DECORATED_FRAMER
#define AKES_MAC_CONF_DECORATED_FRAMER framer_802154
#undef AKES_MAC_CONF_STRATEGY
#define AKES_MAC_CONF_STRATEGY csma_strategy
#undef AKES_NBR_CONF_WITH_PAIRWISE_KEYS
#define AKES_NBR_CONF_WITH_PAIRWISE_KEYS 1
#undef AKES_NBR_CONF_WITH_INDICES
#define AKES_NBR_CONF_WITH_INDICES 1

#ifndef AKES_MAC_CONF_UNICAST_SEC_LVL
#define AKES_MAC_CONF_UNICAST_SEC_LVL 6
#endif /* AKES_MAC_CONF_UNICAST_SEC_LVL */

#if ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 1)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 6
#elif ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 2)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 8
#elif ((AKES_MAC_CONF_UNICAST_SEC_LVL & 3) == 3)
#define AKES_MAC_CONF_UNICAST_MIC_LEN 10
#else
#error "unsupported security level"
#endif

#ifndef AKES_MAC_CONF_BROADCAST_SEC_LVL
#define AKES_MAC_CONF_BROADCAST_SEC_LVL 2
#endif /* AKES_MAC_CONF_BROADCAST_SEC_LVL */

#if ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 1)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 6
#elif ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 2)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 8
#elif ((AKES_MAC_CONF_BROADCAST_SEC_LVL & 3) == 3)
#define AKES_MAC_CONF_BROADCAST_MIC_LEN 10
#else
#error "unsupported security level"
#endif

#undef AKES_NBR_CONF_WITH_GROUP_KEYS
#define AKES_NBR_CONF_WITH_GROUP_KEYS (AKES_MAC_CONF_BROADCAST_SEC_LVL & 4)
#undef PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES
#define PACKETBUF_CONF_WITH_UNENCRYPTED_BYTES AKES_NBR_CONF_WITH_GROUP_KEYS
