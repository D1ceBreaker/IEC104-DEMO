/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author IEC104 Parser Implementation
 *
 * App-layer parser for IEC 60870-5-104 protocol
 */

 #include "suricata-common.h"
 #include "util-debug.h"
 #include "util-enum.h"
 
 #include "app-layer-protos.h"
 #include "app-layer-parser.h"
 #include "app-layer-detect-proto.h"
 #include "app-layer-events.h"
 #include "app-layer-iec104.h"
 #include "flow.h"
 #include "decode.h"
 
 /* Stream direction flags */
 #ifndef STREAM_TOSERVER
 #define STREAM_TOSERVER 0x01
 #endif
 #ifndef STREAM_TOCLIENT
 #define STREAM_TOCLIENT 0x02
 #endif
 
 /* Default number of unreplied requests to be considered a flood. */
 #define IEC104_DEFAULT_REQ_FLOOD_COUNT 500
 
 /* IEC104 decoder event map */
 SCEnumCharMap iec104_decoder_event_table[] = {
     {"MALFORMED", IEC104_DECODER_EVENT_MALFORMED},
     {"INVALID_LENGTH", IEC104_DECODER_EVENT_INVALID_LENGTH},
     {"INVALID_TYPE_ID", IEC104_DECODER_EVENT_INVALID_TYPE_ID},
     {"INVALID_COT", IEC104_DECODER_EVENT_INVALID_COT},
     {"INVALID_ASDU_ADDR", IEC104_DECODER_EVENT_INVALID_ASDU_ADDR},
     {"INVALID_IOA", IEC104_DECODER_EVENT_INVALID_IOA},
     {"UNKNOWN_TYPE_ID", IEC104_DECODER_EVENT_UNKNOWN_TYPE_ID},
     {"UNKNOWN_COT", IEC104_DECODER_EVENT_UNKNOWN_COT},
     {"CONTROL_COMMAND", IEC104_DECODER_EVENT_CONTROL_COMMAND},
     {"SETPOINT_COMMAND", IEC104_DECODER_EVENT_SETPOINT_COMMAND},
     {"FLOODED", IEC104_DECODER_EVENT_FLOODED},
     {NULL, -1},
 };
 
 /**
  * \brief Check if Type ID is valid
  */
 static bool IEC104IsValidTypeID(uint8_t type_id)
 {
     /* Check for valid Type ID ranges */
     if (type_id == 0 || type_id > 255)
         return false;
     
     /* Most common Type IDs are in specific ranges */
     if ((type_id >= 1 && type_id <= 21) ||
         (type_id >= 30 && type_id <= 40) ||
         (type_id >= 45 && type_id <= 64) ||
         (type_id == 70) ||
         (type_id >= 100 && type_id <= 107) ||
         (type_id >= 110 && type_id <= 113) ||
         (type_id >= 120 && type_id <= 139))
         return true;
     
     return false;
 }
 
 /**
  * \brief Check if COT is valid
  */
 static bool IEC104IsValidCOT(uint8_t cot)
 {
     if (cot == 0 || cot > 47)
         return false;
     
     /* Valid COT values */
     if ((cot >= 1 && cot <= 16) ||
         (cot == 20) || (cot == 21) ||
         (cot >= 44 && cot <= 47))
         return true;
     
     return false;
 }
 
 /**
  * \brief Check if Type ID is a command
  */
 static bool IEC104IsCommandTypeID(uint8_t type_id)
 {
     return (type_id >= 45 && type_id <= 64) ||  /* Control commands */
            (type_id >= 100 && type_id <= 107) || /* System commands */
            (type_id >= 110 && type_id <= 113);   /* Parameter commands */
 }
 
 /**
  * \brief Check if Type ID is a setpoint command
  */
 static bool IEC104IsSetpointCommand(uint8_t type_id)
 {
     return (type_id >= 48 && type_id <= 50) ||   /* Setpoint commands */
            (type_id >= 61 && type_id <= 63);     /* Setpoint commands with time tag */
 }
 
 /**
  * \brief IEC104 probing parser
  */
 static AppProto IEC104ProbingParser(
         const Flow *f, uint8_t flags, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
 {
     (void)f;  /* unused */
     (void)flags;  /* unused */
     (void)rdir;  /* unused */
 
     /* Check minimum length */
     if (input_len < IEC104_MIN_LEN) {
         return ALPROTO_UNKNOWN;
     }
 
     /* Check start byte */
     if (input[0] != IEC104_START_BYTE) {
         return ALPROTO_FAILED;
     }
 
     /* Check length field */
     uint8_t apdu_len = input[1];
     if (apdu_len < 4 || apdu_len > 253) {
         return ALPROTO_FAILED;
     }
 
     /* Check if we have enough data */
     uint32_t expected_len = 2 + apdu_len; /* Start + Len + APDU */
     if (input_len < expected_len) {
         return ALPROTO_UNKNOWN; /* Need more data */
     }
 
     /* Check control field format */
     uint8_t ctrl_byte1 = input[2];
     uint8_t frame_type = ctrl_byte1 & 0x03;
     
     /* Valid frame types: I-frame (0x00), S-frame (0x01), U-frame (0x03) */
     if (frame_type == 0x02) {
         return ALPROTO_FAILED; /* Invalid frame type */
     }
 
     SCLogDebug("Detected IEC104 protocol.");
     return ALPROTO_IEC104;
 }
 
 /**
  * \brief Allocate IEC104 state
  */
 static void *IEC104StateAlloc(void *orig_state, AppProto proto_orig)
 {
     IEC104State *iec104 = SCCalloc(1, sizeof(IEC104State));
     if (unlikely(iec104 == NULL)) {
         return NULL;
     }
     TAILQ_INIT(&iec104->tx_list);
     return iec104;
 }
 
 /**
  * \brief Free IEC104 state
  */
 static void IEC104StateFree(void *state)
 {
     IEC104State *iec104 = (IEC104State *)state;
     if (iec104 == NULL) {
         return;
     }
 
     IEC104Transaction *tx;
     while ((tx = TAILQ_FIRST(&iec104->tx_list)) != NULL) {
         TAILQ_REMOVE(&iec104->tx_list, tx, next);
         if (tx->data) {
             SCFree(tx->data);
         }
         SCFree(tx);
     }
     SCFree(iec104);
 }
 
 /**
  * \brief Set IEC104 event
  */
 static void IEC104SetEvent(IEC104State *iec104, uint8_t event)
 {
     if (iec104 && iec104->curr) {
         SCAppLayerDecoderEventsSetEventRaw(&iec104->curr->tx_data.events, event);
         iec104->events++;
     }
 }
 
 /**
  * \brief Allocate IEC104 transaction
  */
 static IEC104Transaction *IEC104TxAlloc(IEC104State *iec104, bool request)
 {
     IEC104Transaction *tx = SCCalloc(1, sizeof(IEC104Transaction));
     if (unlikely(tx == NULL)) {
         return NULL;
     }
     iec104->transaction_max++;
     if (request) {
         iec104->unreplied++;
     }
     iec104->curr = tx;
     tx->tx_id = iec104->transaction_max;
     tx->is_request = request;
     if (tx->is_request) {
         tx->tx_data.flags = APP_LAYER_TX_SKIP_INSPECT_TC;
     } else {
         tx->tx_data.flags = APP_LAYER_TX_SKIP_INSPECT_TS;
     }
     TAILQ_INSERT_TAIL(&iec104->tx_list, tx, next);
     return tx;
 }
 
 /**
  * \brief Free IEC104 transaction
  */
 static void IEC104TxFree(void *state, uint64_t tx_id)
 {
     IEC104State *iec104 = (IEC104State *)state;
     if (iec104 == NULL) {
         return;
     }
 
     IEC104Transaction *tx;
     TAILQ_FOREACH(tx, &iec104->tx_list, next) {
         if (tx->tx_id == tx_id) {
             TAILQ_REMOVE(&iec104->tx_list, tx, next);
             if (tx->data) {
                 SCFree(tx->data);
             }
             SCFree(tx);
             break;
         }
     }
 }
 
 /**
  * \brief Get transaction count
  */
 static uint64_t IEC104GetTxCnt(void *state)
 {
     IEC104State *iec104 = (IEC104State *)state;
     if (iec104 == NULL) {
         return 0;
     }
     return iec104->transaction_max;
 }
 
 /**
  * \brief Get transaction by ID
  */
 static void *IEC104GetTx(void *state, uint64_t tx_id)
 {
     IEC104State *iec104 = (IEC104State *)state;
     if (iec104 == NULL) {
         return NULL;
     }
 
     IEC104Transaction *tx;
     TAILQ_FOREACH(tx, &iec104->tx_list, next) {
         if (tx->tx_id == tx_id) {
             return tx;
         }
     }
     return NULL;
 }
 
 /**
  * \brief Get state progress
  */
 static int IEC104GetStateProgress(void *alstate, uint8_t direction)
 {
     IEC104State *iec104 = (IEC104State *)alstate;
     if (iec104 == NULL) {
         return 0;
     }
     
     /* IEC104 is a simple request-response protocol */
     /* Return 1 if we have transactions, 0 otherwise */
     return (iec104->transaction_max > 0) ? 1 : 0;
 }
 
 /**
  * \brief Get transaction data
  */
 static AppLayerTxData *IEC104GetTxData(void *tx)
 {
     IEC104Transaction *iec104_tx = (IEC104Transaction *)tx;
     if (iec104_tx == NULL) {
         return NULL;
     }
     return &iec104_tx->tx_data;
 }
 
 /**
  * \brief Get state data
  */
 static AppLayerStateData *IEC104GetStateData(void *state)
 {
     IEC104State *iec104 = (IEC104State *)state;
     if (iec104 == NULL) {
         return NULL;
     }
     /* IEC104 doesn't have separate state data, return NULL */
     return NULL;
 }
 
 /**
  * \brief Parse IEC104 APDU
  */
 static AppLayerResult IEC104Parse(Flow *f, void *state,
         AppLayerParserState *pstate, StreamSlice stream_slice, void *local_storage)
 {
     IEC104State *iec104 = (IEC104State *)state;
     const uint8_t *data = stream_slice.input;
     uint32_t data_len = stream_slice.input_len;
     const bool toserver = (stream_slice.flags & STREAM_TOSERVER) != 0;
 
     if (data_len < IEC104_MIN_LEN) {
         return APP_LAYER_INCOMPLETE(0, IEC104_MIN_LEN - data_len);
     }
 
     /* Check start byte */
     if (data[0] != IEC104_START_BYTE) {
         return APP_LAYER_ERROR;
     }
 
     /* Get APDU length */
     uint8_t apdu_len = data[1];
     if (apdu_len < 4 || apdu_len > 253) {
         if (iec104 && iec104->curr) {
             IEC104SetEvent(iec104, IEC104_DECODER_EVENT_INVALID_LENGTH);
         }
         return APP_LAYER_ERROR;
     }
 
     /* Calculate total frame length */
     uint32_t frame_len = 2 + apdu_len; /* Start + Len + APDU */
     if (data_len < frame_len) {
         return APP_LAYER_INCOMPLETE(data_len, frame_len - data_len);
     }
 
     /* Check for flood */
     if (iec104 && toserver && iec104->unreplied > IEC104_DEFAULT_REQ_FLOOD_COUNT) {
         IEC104SetEvent(iec104, IEC104_DECODER_EVENT_FLOODED);
     }
 
     /* Parse control field */
     uint8_t ctrl_byte1 = data[2];
     uint8_t frame_type = ctrl_byte1 & 0x03;
 
     /* Handle I-frame (Information frame) */
     if (frame_type == 0x00 && apdu_len >= 6) {
         /* I-frame contains ASDU */
         IEC104Transaction *tx = NULL;
         if (iec104) {
             tx = IEC104TxAlloc(iec104, toserver);
             if (tx == NULL) {
                 return APP_LAYER_ERROR;
             }
         }
 
         /* Parse ASDU */
         uint32_t offset = 6; /* Start(1) + Len(1) + Ctrl(4) */
         if (apdu_len >= 6) {
             uint8_t type_id = data[offset];
             uint8_t vsq = data[offset + 1];
             uint8_t cot = data[offset + 2];
             uint16_t asdu_addr = data[offset + 3] | (data[offset + 4] << 8);
             
             if (tx) {
                 tx->type_id = type_id;
                 tx->vsq = vsq;
                 tx->sq = (vsq >> 7) & 0x01;
                 tx->num_ix = vsq & 0x7F;
                 tx->cot = cot;
                 tx->asdu_addr = asdu_addr;
             }
 
             /* Validate Type ID */
             if (!IEC104IsValidTypeID(type_id)) {
                 if (iec104 && iec104->curr) {
                     IEC104SetEvent(iec104, IEC104_DECODER_EVENT_INVALID_TYPE_ID);
                 }
             } else {
                 /* Check for unknown Type ID in valid range but not standard */
                 if (type_id < 1 || (type_id > 21 && type_id < 30) ||
                     (type_id > 40 && type_id < 45) || (type_id > 64 && type_id < 70) ||
                     (type_id > 70 && type_id < 100) || (type_id > 107 && type_id < 110) ||
                     (type_id > 113 && type_id < 120) || type_id > 139) {
                     if (iec104 && iec104->curr) {
                         IEC104SetEvent(iec104, IEC104_DECODER_EVENT_UNKNOWN_TYPE_ID);
                     }
                 }
             }
 
             /* Validate COT */
             if (!IEC104IsValidCOT(cot)) {
                 if (iec104 && iec104->curr) {
                     IEC104SetEvent(iec104, IEC104_DECODER_EVENT_INVALID_COT);
                 }
             } else if (cot > 21 && cot < 44) {
                 if (iec104 && iec104->curr) {
                     IEC104SetEvent(iec104, IEC104_DECODER_EVENT_UNKNOWN_COT);
                 }
             }
 
             /* Check for commands */
             if (IEC104IsCommandTypeID(type_id)) {
                 if (iec104 && iec104->curr) {
                     IEC104SetEvent(iec104, IEC104_DECODER_EVENT_CONTROL_COMMAND);
                 }
             }
 
             /* Check for setpoint commands */
             if (IEC104IsSetpointCommand(type_id)) {
                 if (iec104 && iec104->curr) {
                     IEC104SetEvent(iec104, IEC104_DECODER_EVENT_SETPOINT_COMMAND);
                 }
             }
 
             /* Parse IOA (Information Object Address) */
             offset += 5; /* Type ID + VSQ + COT + ASDU Addr (2 bytes) */
             if (apdu_len >= 8 && offset + 3 <= apdu_len) {
                 uint32_t ioa = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16);
                 if (tx) {
                     tx->ioa = ioa;
                 }
                 offset += 3;
             }
 
             /* Store data */
             if (tx && offset < apdu_len) {
                 uint32_t data_len = apdu_len - offset;
                 tx->data = SCCalloc(1, data_len);
                 if (tx->data) {
                     memcpy(tx->data, data + offset, data_len);
                     tx->data_len = data_len;
                 }
             }
         } else {
             if (iec104 && iec104->curr) {
                 IEC104SetEvent(iec104, IEC104_DECODER_EVENT_MALFORMED);
             }
         }
     }
     /* Handle S-frame (Supervisory frame) or U-frame (Unnumbered frame) */
     else if (frame_type == 0x01 || frame_type == 0x03) {
         /* S-frame and U-frame don't contain ASDU, just control information */
         if (iec104) {
             IEC104Transaction *tx = IEC104TxAlloc(iec104, toserver);
             if (tx) {
                 tx->type_id = 0; /* No Type ID for S/U frames */
             }
         }
     } else {
         if (iec104 && iec104->curr) {
             IEC104SetEvent(iec104, IEC104_DECODER_EVENT_MALFORMED);
         }
     }
 
     return APP_LAYER_OK;
 }
 
 /**
  * \brief Get event info by name
  */
 static int IEC104GetEventInfo(const char *event_name, uint8_t *event_id, AppLayerEventType *event_type)
 {
     return SCAppLayerGetEventIdByName(event_name, iec104_decoder_event_table, event_id);
 }
 
 /**
  * \brief Get event info by ID
  */
 static int IEC104GetEventInfoById(uint8_t event_id, const char **event_name, AppLayerEventType *event_type)
 {
     if (event_id >= IEC104_DECODER_EVENT_MAX) {
         return -1;
     }
     *event_name = iec104_decoder_event_table[event_id].enum_name;
     *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
     return 0;
 }
 
 /**
  * \brief Register IEC104 parsers
  */
 void RegisterIEC104Parsers(void)
 {
     const char *proto_name = "iec104";
 
     /* Register protocol string - ALPROTO_IEC104 is already defined in app-layer-protos.h */
     /* For protocols defined after ALPROTO_MAX_STATIC, AppProtoRegisterProtoString should handle it */
     /* But we need to ensure the array is large enough first */
     AppProtoRegisterProtoString(ALPROTO_IEC104, proto_name);
 
     /* Register protocol for detection - this may be called before alpd_ctx.alproto_names
      * is initialized, but AppLayerProtoDetectRegisterProtocol handles that case */
     AppLayerProtoDetectRegisterProtocol(ALPROTO_IEC104, proto_name);
 
     /* Register probing parser */
     SCAppLayerProtoDetectPPRegister(IPPROTO_TCP, IEC104_DEFAULT_PORT, ALPROTO_IEC104,
             0, 0, STREAM_TOSERVER, IEC104ProbingParser, IEC104ProbingParser);
 
     /* Register parser */
     AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IEC104, STREAM_TOSERVER, IEC104Parse);
     AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IEC104, STREAM_TOCLIENT, IEC104Parse);
 
     /* Register state functions */
     AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_IEC104, IEC104StateAlloc, IEC104StateFree);
 
     /* Register transaction functions */
     AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_IEC104, IEC104TxFree);
     AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetTxCnt);
     AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetTx);
 
     /* Register event functions */
     AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetEventInfo);
     AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetEventInfoById);
 
     /* Register logger */
     SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC104);
 
     /* Register state progress completion status */
     AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_IEC104, 1, 1);
     
     /* Register state progress function */
     AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetStateProgress);
 
     /* Register transaction and state data functions */
     AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetTxData);
     AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_IEC104, IEC104GetStateData);
 
     SCLogDebug("IEC104 parser registered successfully");
 }
 