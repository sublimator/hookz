// Macros from XRPLF/hook-macros (inlined — hookmacro.h has include resolution issues with wasi-sdk)
#define ENCODE_TT_SIZE 3
#define ENCODE_TT(buf_out, tt) { uint8_t utt = tt; buf_out[0] = 0x12U; buf_out[1] = (utt >> 8) & 0xFFU; buf_out[2] = (utt >> 0) & 0xFFU; buf_out += ENCODE_TT_SIZE; }
#define _01_02_ENCODE_TT(buf_out, tt) ENCODE_TT(buf_out, tt);

#define ENCODE_UINT32_COMMON_SIZE 5U
#define ENCODE_UINT32_COMMON(buf_out, i, field) { uint32_t ui = i; uint8_t uf = field; buf_out[0] = 0x20U + (uf & 0x0FU); buf_out[1] = (ui >> 24) & 0xFFU; buf_out[2] = (ui >> 16) & 0xFFU; buf_out[3] = (ui >> 8) & 0xFFU; buf_out[4] = (ui >> 0) & 0xFFU; buf_out += ENCODE_UINT32_COMMON_SIZE; }
#define ENCODE_UINT32_UNCOMMON_SIZE 6U
#define ENCODE_UINT32_UNCOMMON(buf_out, i, field) { uint32_t ui = i; uint8_t uf = field; buf_out[0] = 0x20U; buf_out[1] = uf; buf_out[2] = (ui >> 24) & 0xFFU; buf_out[3] = (ui >> 16) & 0xFFU; buf_out[4] = (ui >> 8) & 0xFFU; buf_out[5] = (ui >> 0) & 0xFFU; buf_out += ENCODE_UINT32_UNCOMMON_SIZE; }

#define _02_02_ENCODE_FLAGS(buf_out, tag) ENCODE_UINT32_COMMON(buf_out, tag, 0x2U);
#define _02_04_ENCODE_SEQUENCE(buf_out, sequence) ENCODE_UINT32_COMMON(buf_out, sequence, 0x4U);
#define _02_26_ENCODE_FLS(buf_out, fls) ENCODE_UINT32_UNCOMMON(buf_out, fls, 0x1AU);
#define _02_27_ENCODE_LLS(buf_out, lls) ENCODE_UINT32_UNCOMMON(buf_out, lls, 0x1BU);

#define ENCODE_DROPS_SIZE 9
#define ENCODE_DROPS(buf_out, drops, amount_type) { uint8_t uat = amount_type; uint64_t udrops = drops; buf_out[0] = 0x60U + (uat & 0x0FU); buf_out[1] = 0b01000000 + ((udrops >> 56) & 0b00111111); buf_out[2] = (udrops >> 48) & 0xFFU; buf_out[3] = (udrops >> 40) & 0xFFU; buf_out[4] = (udrops >> 32) & 0xFFU; buf_out[5] = (udrops >> 24) & 0xFFU; buf_out[6] = (udrops >> 16) & 0xFFU; buf_out[7] = (udrops >> 8) & 0xFFU; buf_out[8] = (udrops >> 0) & 0xFFU; buf_out += ENCODE_DROPS_SIZE; }
#define _06_08_ENCODE_DROPS_FEE(buf_out, drops) ENCODE_DROPS(buf_out, drops, amFEE);

#define ENCODE_SIGNING_PUBKEY_NULL_SIZE 35
#define ENCODE_SIGNING_PUBKEY_NULL(buf_out) { buf_out[0] = 0x73U; buf_out[1] = 0x21U; *(uint64_t*)(buf_out+2) = 0; *(uint64_t*)(buf_out+10) = 0; *(uint64_t*)(buf_out+18) = 0; *(uint64_t*)(buf_out+25) = 0; buf_out += ENCODE_SIGNING_PUBKEY_NULL_SIZE; }
#define _07_03_ENCODE_SIGNING_PUBKEY_NULL(buf_out) ENCODE_SIGNING_PUBKEY_NULL(buf_out);

#define ENCODE_ACCOUNT_SIZE 22
#define ENCODE_ACCOUNT(buf_out, account_id, account_type) { uint8_t uat = account_type; buf_out[0] = 0x80U + uat; buf_out[1] = 0x14U; *(uint64_t*)(buf_out + 2) = *(uint64_t*)(account_id + 0); *(uint64_t*)(buf_out + 10) = *(uint64_t*)(account_id + 8); *(uint32_t*)(buf_out + 18) = *(uint32_t*)(account_id + 16); buf_out += ENCODE_ACCOUNT_SIZE; }
#define _08_01_ENCODE_ACCOUNT_SRC(buf_out, account_id) ENCODE_ACCOUNT(buf_out, account_id, atACCOUNT);
#define _08_03_ENCODE_ACCOUNT_DST(buf_out, account_id) ENCODE_ACCOUNT(buf_out, account_id, atDESTINATION);

#define _0E_0E_ENCODE_HOOKOBJ(buf_out, hhash) { \
    uint8_t* hook0 = (hhash); \
    *buf_out++ = 0xEEU; \
    if (hook0 == 0) { } \
    else { \
        *buf_out++ = 0x22U; *buf_out++ = 0x00U; *buf_out++ = 0x00U; *buf_out++ = 0x00U; *buf_out++ = 0x01U; \
        if (hook0 == (uint8_t*)0xFFFFFFFFUL) { \
            *buf_out++ = 0x20U; *buf_out++ = 0x60U; *buf_out++ = 0x00U; *buf_out++ = 0x00U; *buf_out++ = 0x00U; *buf_out++ = 0x01U; \
        } else { \
            *buf_out++ = 0x5DU; \
            *(uint64_t*)(buf_out + 0) = *(uint64_t*)(hook0 + 0); \
            *(uint64_t*)(buf_out + 8) = *(uint64_t*)(hook0 + 8); \
            *(uint64_t*)(buf_out + 16) = *(uint64_t*)(hook0 + 16); \
            *(uint64_t*)(buf_out + 24) = *(uint64_t*)(hook0 + 24); \
            buf_out += 32; \
        } \
    } \
    *buf_out++ = 0xE1U; \
}

#define PREPARE_HOOKSET(buf_out_master, maxlen, h, sizeout) { \
    uint8_t* buf_out = (buf_out_master); \
    uint8_t acc[20]; \
    uint32_t cls = (uint32_t)ledger_seq(); \
    hook_account(SBUF(acc)); \
    _01_02_ENCODE_TT(buf_out, ttHOOK_SET); \
    _02_02_ENCODE_FLAGS(buf_out, tfCANONICAL); \
    _02_04_ENCODE_SEQUENCE(buf_out, 0); \
    _02_26_ENCODE_FLS(buf_out, cls + 1); \
    _02_27_ENCODE_LLS(buf_out, cls + 5); \
    uint8_t* fee_ptr_hs = buf_out; \
    _06_08_ENCODE_DROPS_FEE(buf_out, 0); \
    _07_03_ENCODE_SIGNING_PUBKEY_NULL(buf_out); \
    _08_01_ENCODE_ACCOUNT_SRC(buf_out, acc); \
    uint32_t remaining_size = (maxlen) - (buf_out - (buf_out_master)); \
    int64_t edlen = etxn_details((uint32_t)buf_out, remaining_size); \
    buf_out += edlen; \
    *buf_out++ = 0xFBU; \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[0]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[1]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[2]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[3]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[4]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[5]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[6]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[7]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[8]); \
    _0E_0E_ENCODE_HOOKOBJ(buf_out, h[9]); \
    *buf_out++ = 0xF1U; \
    int64_t fee = etxn_fee_base(buf_out_master, buf_out - (buf_out_master)); \
    _06_08_ENCODE_DROPS_FEE(fee_ptr_hs, fee); \
    sizeout = buf_out - (buf_out_master); \
}
#define _06_01_ENCODE_DROPS_AMOUNT(buf_out, drops) ENCODE_DROPS(buf_out, drops, amAMOUNT);

#ifndef FLIP_ENDIAN
#define FLIP_ENDIAN(n) ((uint32_t)(((n & 0xFFU) << 24U) | ((n & 0xFF00U) << 8U) | ((n & 0xFF0000U) >> 8U) | ((n & 0xFF000000U) >> 24U)))
#endif
