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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "bsp/bsp.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "bleprph.h"

/**
 * The vendor specific security test service consists of two characteristics:
 *     o random-number-generator: generates a random 32-bit number each time
 *       it is read.  This characteristic can only be read over an encrypted
 *       connection.
 *     o static-value: a single-byte characteristic that can always be read,
 *       but can only be written over an encrypted connection.
 */

/* 59462f12-9543-9999-12c8-58b459a2712d */
static const ble_uuid128_t gatt_svr_svc_sec_test_uuid =
    BLE_UUID128_INIT(0x2d, 0x71, 0xa2, 0x59, 0xb4, 0x58, 0xc8, 0x12,
                     0x99, 0x99, 0x43, 0x95, 0x12, 0x2f, 0x46, 0x59);

/* 5c3a659e-897e-45e1-b016-007107c96df6 */
static const ble_uuid128_t gatt_svr_chr_sec_test_rand_uuid =
        BLE_UUID128_INIT(0xf6, 0x6d, 0xc9, 0x07, 0x71, 0x00, 0x16, 0xb0,
                         0xe1, 0x45, 0x7e, 0x89, 0x9e, 0x65, 0x3a, 0x5c);

/* 5c3a659e-897e-45e1-b016-007107c96df7 */
static const ble_uuid128_t gatt_svr_chr_sec_test_static_uuid =
        BLE_UUID128_INIT(0xf7, 0x6d, 0xc9, 0x07, 0x71, 0x00, 0x16, 0xb0,
                         0xe1, 0x45, 0x7e, 0x89, 0x9e, 0x65, 0x3a, 0x5c);
/*00001804-0000-1000-8000-00805f9b34fb*/
static const ble_uuid128_t gatt_svr_svc_tx_uuid =
        BLE_UUID128_INIT(0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
                         0x00, 0x10, 0x00, 0x00, 0x04, 0x18, 0x00, 0x00);	
/*00002A07-0000-1000-8000-00805f9b34fb*/						 
static const ble_uuid128_t gatt_svr_chr_tx_uuid =
        BLE_UUID128_INIT(0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
                         0x00, 0x10, 0x00, 0x00, 0x07, 0x2A, 0x00, 0x00);
/*00001905-0000-2000-9000-0f0e0d0c0b0a*/						 
static const ble_uuid128_t gatt_svr_svc_ota_uuid =
        BLE_UUID128_INIT(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x90,
                         0x00, 0x20, 0x00, 0x00, 0x05, 0x19, 0x00, 0x00);	
/*00000a0a-0000-2000-9000-0f0e0d0c0b0a*/						 
static const ble_uuid128_t gatt_svr_chr_ota_uuid =
        BLE_UUID128_INIT(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x90,
                         0x00, 0x20, 0x00, 0x00, 0x0a, 0x0a, 0x00, 0x00);	
						 
static uint8_t gatt_svr_sec_test_static_val;
static	uint8_t dbuf[20];
static int
gatt_svr_chr_access_sec_test(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg);
							 
data_pck_t* parse_pck(struct os_mbuf *om, uint8_t *err);

static int
gatt_svr_chr_access_txpwr(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt, void *arg);

static int
gatt_svr_chr_access_ota(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt, void *arg);
	
static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    {
        /*** Service: Security test. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &gatt_svr_svc_sec_test_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) { {
            /*** Characteristic: Random number generator. */
            .uuid = &gatt_svr_chr_sec_test_rand_uuid.u,
            .access_cb = gatt_svr_chr_access_sec_test,
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
        }, {
            /*** Characteristic: Static value. */
            .uuid = &gatt_svr_chr_sec_test_static_uuid.u,
            .access_cb = gatt_svr_chr_access_sec_test,
            .flags = BLE_GATT_CHR_F_READ |
                     BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,  //BLE_GATT_CHR_F_RELIABLE_WRITE,BLE_GATT_CHR_F_WRITE_ENC
        }, {
            0, /* No more characteristics in this service. */
        } },
    },
	{
		/*** Service: Tx Power */
		.type = BLE_GATT_SVC_TYPE_PRIMARY,
		.uuid = &gatt_svr_svc_tx_uuid.u,
		.characteristics = (struct ble_gatt_chr_def[]) { {
			/*** Characteristic: Tx Power Level. */
			.uuid = &gatt_svr_chr_tx_uuid.u,
			.access_cb = gatt_svr_chr_access_txpwr,
			.flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
		}, {
			0, /* No more characteristics in this service. */
		} },
	},
	{
		/*** Service: ota */
		.type = BLE_GATT_SVC_TYPE_PRIMARY,
		.uuid = &gatt_svr_svc_ota_uuid.u,
		.characteristics = (struct ble_gatt_chr_def[]) { {
			/*** Characteristic: ota. */
			.uuid = &gatt_svr_chr_ota_uuid.u,
			.access_cb = gatt_svr_chr_access_ota,
			.flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
		}, {
			0, /* No more characteristics in this service. */
		} },
	},
    {
        0, /* No more services. */
    },
};

static int
gatt_svr_chr_write(struct os_mbuf *om, uint16_t min_len, uint16_t max_len,
                   void *dst, uint16_t *len)
{
    uint16_t om_len;
    int rc;

    om_len = OS_MBUF_PKTLEN(om);
    if (om_len < min_len || om_len > max_len) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    rc = ble_hs_mbuf_to_flat(om, dst, max_len, len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static int
gatt_svr_chr_access_sec_test(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg)
{
    const ble_uuid_t *uuid;
    int rand_num;
    int rc;

    uuid = ctxt->chr->uuid;

    /* Determine which characteristic is being accessed by examining its
     * 128-bit UUID.
     */

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_sec_test_rand_uuid.u) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        /* Respond with a 32-bit random number. */
        rand_num = rand();
        rc = os_mbuf_append(ctxt->om, &rand_num, sizeof rand_num);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_sec_test_static_uuid.u) == 0) {
        switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            rc = os_mbuf_append(ctxt->om, &gatt_svr_sec_test_static_val,
                                sizeof gatt_svr_sec_test_static_val);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            rc = gatt_svr_chr_write(ctxt->om,
                                    sizeof gatt_svr_sec_test_static_val,
                                    sizeof gatt_svr_sec_test_static_val,
                                    &gatt_svr_sec_test_static_val, NULL);
            return rc;

        default:
            assert(0);
            return BLE_ATT_ERR_UNLIKELY;
        }
    }

    /* Unknown characteristic; the nimble stack should not have called this
     * function.
     */
    assert(0);
    return BLE_ATT_ERR_UNLIKELY;
}

static int gatt_svr_chr_access_txpwr(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt, void *arg)
{
  int rc;

  //conn_disconnect_after(conn_handle, CONN_TIMEOUT);

  if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
    if (OS_MBUF_PKTLEN(ctxt->om) != 1) {
      return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    rc = gatt_svr_chr_write(ctxt->om,
                                    sizeof gatt_svr_sec_test_static_val,
                                    sizeof gatt_svr_sec_test_static_val,
                                    &gatt_svr_sec_test_static_val, NULL);
    if (rc != 0) {
      return BLE_ATT_ERR_UNLIKELY;
    }
  } else if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
    rc = os_mbuf_append(ctxt->om, &gatt_svr_sec_test_static_val, sizeof(gatt_svr_sec_test_static_val));
    if (rc != 0) {
      return BLE_ATT_ERR_INSUFFICIENT_RES;
    }
  }
  return 0;
}

static int gatt_svr_chr_access_ota(
    uint16_t conn_handle,
    uint16_t attr_handle,
    struct ble_gatt_access_ctxt *ctxt, void *arg)
	{
//		int rc;
		uint8_t err;
		data_pck_t* val_data;
		//conn_disconnect_after(conn_handle, CONN_TIMEOUT);
  if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
/*    if (OS_MBUF_PKTLEN(ctxt->om) != 1) {
      return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }*/
    val_data = parse_pck(ctxt->om,&err);  /*gatt_svr_chr_write(ctxt->om,
                                    sizeof gatt_svr_sec_test_static_val,
                                    sizeof gatt_svr_sec_test_static_val,
                                    &gatt_svr_sec_test_static_val, NULL);*/
	BLEPRPH_LOG(INFO, "val_data; status=%d\n ",
                    val_data);    
	/*if (val_data == NULL) {
      return BLE_ATT_ERR_UNLIKELY;
    }*/
  }
  return 0;  
}

data_pck_t* parse_pck(struct os_mbuf *om, uint8_t *err)
{
	data_pck_t* value;
	int rc;
	uint16_t data_len;
	data_len = OS_MBUF_PKTLEN(om);//OS_MBUF_PKTLEN(om);
    memset(dbuf, 0, sizeof(dbuf));
	rc = ble_hs_mbuf_to_flat(om, dbuf, sizeof(dbuf), &data_len);
	BLEPRPH_LOG(INFO, "data_len; status=%d\n",
                    data_len);
	BLEPRPH_LOG(INFO, "dbuf; status=%s\n",
                    dbuf);
	BLEPRPH_LOG(INFO, "rc; status=%d ",
                    rc);
	if (rc != 0) {
    if (err) {
      *err = 3;
    }
    return NULL;
    }
	value = (data_pck_t*)dbuf;
	value->offset = (uint32_t)((dbuf[3]<<24)|(dbuf[2]<<16)|(dbuf[1]<<8)|dbuf[0]);
	value->len = (uint32_t) ((dbuf[7]<<24)|(dbuf[6]<<16)|(dbuf[5]<<8)|dbuf[4]);
	value->data_t[0] = dbuf[8];//(uint8_t)
	BLEPRPH_LOG(INFO, "offset; status=%d\n ",
                    value->offset);
	BLEPRPH_LOG(INFO, "len; status=%d\n ",
                    value->len);
	BLEPRPH_LOG(INFO, "data; status=%s \n ",
                    value->data_t);
	BLEPRPH_LOG(INFO, "value; status=%d\n ",
                    value);    
	return value;
}

void
gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    char buf[BLE_UUID_STR_LEN];

    switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
        BLEPRPH_LOG(DEBUG, "registered service %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                    ctxt->svc.handle);
        break;

    case BLE_GATT_REGISTER_OP_CHR:
        BLEPRPH_LOG(DEBUG, "registering characteristic %s with "
                           "def_handle=%d val_handle=%d\n",
                    ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                    ctxt->chr.def_handle,
                    ctxt->chr.val_handle);
        break;

    case BLE_GATT_REGISTER_OP_DSC:
        BLEPRPH_LOG(DEBUG, "registering descriptor %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                    ctxt->dsc.handle);
        break;

    default:
        assert(0);
        break;
    }
}

int
gatt_svr_init(void)
{
    int rc;

    rc = ble_gatts_count_cfg(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    return 0;
}
