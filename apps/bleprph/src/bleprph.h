/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef H_BLEPRPH_
#define H_BLEPRPH_

#include "log/log.h"
#include "nimble/ble.h"
#ifdef __cplusplus
extern "C" {
#endif

struct ble_hs_cfg;
struct ble_gatt_register_ctxt;

//verify offset
//if first packet -- chk signature and version of firmware
//also check total legnth of the packet
//calculate total number of packets depending on packet size
//keep track of offset(??)
//compare offset everytime you recieve new packet
//if same packet received .. rewrite
//if packet missed .. discard all packets and send error
//if first packet received in the middle .. discard prev packets and rewrite from start
//whether to use os membuf pool??


typedef struct data_pck {
//  TAILQ_ENTRY(data_pck) q; //next element of the queue of type data_pck
  uint32_t offset;
  uint32_t len;
  uint8_t data_t[20];
 }data_pck_t;

extern struct log bleprph_log;
/* Current transmit power level. This value is broadcast in advertising
 * packets, and corresponds to the return of proxy_conf_tx_pwr_lvl_get. */
//extern int8_t tx_pwr_lvl;
/* bleprph uses the first "peruser" log module. */
#define BLEPRPH_LOG_MODULE  (LOG_MODULE_PERUSER + 0)

/* Convenience macro for logging to the bleprph module. */
#define BLEPRPH_LOG(lvl, ...) \
    LOG_ ## lvl(&bleprph_log, BLEPRPH_LOG_MODULE, __VA_ARGS__)

/** GATT server. */
#define GATT_SVR_SVC_ALERT_UUID               0x1811
#define GATT_SVR_CHR_SUP_NEW_ALERT_CAT_UUID   0x2A47
#define GATT_SVR_CHR_NEW_ALERT                0x2A46
#define GATT_SVR_CHR_SUP_UNR_ALERT_CAT_UUID   0x2A48
#define GATT_SVR_CHR_UNR_ALERT_STAT_UUID      0x2A45
#define GATT_SVR_CHR_ALERT_NOT_CTRL_PT        0x2A44
//#define GATT_TXPWR_SVC_UUID16             0x1804
//#define GATT_TXPWR_CHR_UUID16_TXPWR_LVL   0x2A07

void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg);
int gatt_svr_init(void);

/** Misc. */
void print_bytes(const uint8_t *bytes, int len);
void print_addr(const void *addr);

#ifdef __cplusplus
}
#endif

#endif
