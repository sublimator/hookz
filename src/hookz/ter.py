"""Transaction result (TER) codes from xahaud.

Auto-generated from include/xrpl/protocol/TER.h.
Source: xahaud @ bb244ef77
Regenerate: python scripts/gen-constants.py <xahaud-root>

Every constant carries its origin in the repo's citation
convention — `xahaud:<path>:<line>` names the exact line of the
pinned xahaud tree it was read from.
"""

# ---- TELcodes ----
telLOCAL_ERROR = -399  # xahaud:include/xrpl/protocol/TER.h:52
telBAD_DOMAIN = -398  # xahaud:include/xrpl/protocol/TER.h:53
telBAD_PATH_COUNT = -397  # xahaud:include/xrpl/protocol/TER.h:54
telBAD_PUBLIC_KEY = -396  # xahaud:include/xrpl/protocol/TER.h:55
telFAILED_PROCESSING = -395  # xahaud:include/xrpl/protocol/TER.h:56
telINSUF_FEE_P = -394  # xahaud:include/xrpl/protocol/TER.h:57
telNO_DST_PARTIAL = -393  # xahaud:include/xrpl/protocol/TER.h:58
telCAN_NOT_QUEUE = -392  # xahaud:include/xrpl/protocol/TER.h:59
telCAN_NOT_QUEUE_BALANCE = -391  # xahaud:include/xrpl/protocol/TER.h:60
telCAN_NOT_QUEUE_BLOCKS = -390  # xahaud:include/xrpl/protocol/TER.h:61
telCAN_NOT_QUEUE_BLOCKED = -389  # xahaud:include/xrpl/protocol/TER.h:62
telCAN_NOT_QUEUE_FEE = -388  # xahaud:include/xrpl/protocol/TER.h:63
telCAN_NOT_QUEUE_FULL = -387  # xahaud:include/xrpl/protocol/TER.h:64
telWRONG_NETWORK = -386  # xahaud:include/xrpl/protocol/TER.h:65
telREQUIRES_NETWORK_ID = -385  # xahaud:include/xrpl/protocol/TER.h:66
telNETWORK_ID_MAKES_TX_NON_CANONICAL = -384  # xahaud:include/xrpl/protocol/TER.h:67
telNON_LOCAL_EMITTED_TXN = -383  # xahaud:include/xrpl/protocol/TER.h:68
telIMPORT_VL_KEY_NOT_RECOGNISED = -382  # xahaud:include/xrpl/protocol/TER.h:69
telCAN_NOT_QUEUE_IMPORT = -381  # xahaud:include/xrpl/protocol/TER.h:70
telENV_RPC_FAILED = -380  # xahaud:include/xrpl/protocol/TER.h:71

# ---- TEMcodes ----
temMALFORMED = -299  # xahaud:include/xrpl/protocol/TER.h:90
temBAD_AMOUNT = -298  # xahaud:include/xrpl/protocol/TER.h:92
temBAD_CURRENCY = -297  # xahaud:include/xrpl/protocol/TER.h:93
temBAD_EXPIRATION = -296  # xahaud:include/xrpl/protocol/TER.h:94
temBAD_FEE = -295  # xahaud:include/xrpl/protocol/TER.h:95
temBAD_ISSUER = -294  # xahaud:include/xrpl/protocol/TER.h:96
temBAD_LIMIT = -293  # xahaud:include/xrpl/protocol/TER.h:97
temBAD_OFFER = -292  # xahaud:include/xrpl/protocol/TER.h:98
temBAD_PATH = -291  # xahaud:include/xrpl/protocol/TER.h:99
temBAD_PATH_LOOP = -290  # xahaud:include/xrpl/protocol/TER.h:100
temBAD_REGKEY = -289  # xahaud:include/xrpl/protocol/TER.h:101
temBAD_SEND_NATIVE_LIMIT = -288  # xahaud:include/xrpl/protocol/TER.h:102
temBAD_SEND_NATIVE_MAX = -287  # xahaud:include/xrpl/protocol/TER.h:103
temBAD_SEND_NATIVE_NO_DIRECT = -286  # xahaud:include/xrpl/protocol/TER.h:104
temBAD_SEND_NATIVE_PARTIAL = -285  # xahaud:include/xrpl/protocol/TER.h:105
temBAD_SEND_NATIVE_PATHS = -284  # xahaud:include/xrpl/protocol/TER.h:106
temBAD_SEQUENCE = -283  # xahaud:include/xrpl/protocol/TER.h:107
temBAD_SIGNATURE = -282  # xahaud:include/xrpl/protocol/TER.h:108
temBAD_SRC_ACCOUNT = -281  # xahaud:include/xrpl/protocol/TER.h:109
temBAD_TRANSFER_RATE = -280  # xahaud:include/xrpl/protocol/TER.h:110
temDST_IS_SRC = -279  # xahaud:include/xrpl/protocol/TER.h:111
temDST_NEEDED = -278  # xahaud:include/xrpl/protocol/TER.h:112
temINVALID = -277  # xahaud:include/xrpl/protocol/TER.h:113
temINVALID_FLAG = -276  # xahaud:include/xrpl/protocol/TER.h:114
temREDUNDANT = -275  # xahaud:include/xrpl/protocol/TER.h:115
temRIPPLE_EMPTY = -274  # xahaud:include/xrpl/protocol/TER.h:116
temDISABLED = -273  # xahaud:include/xrpl/protocol/TER.h:117
temBAD_SIGNER = -272  # xahaud:include/xrpl/protocol/TER.h:118
temBAD_QUORUM = -271  # xahaud:include/xrpl/protocol/TER.h:119
temBAD_WEIGHT = -270  # xahaud:include/xrpl/protocol/TER.h:120
temBAD_TICK_SIZE = -269  # xahaud:include/xrpl/protocol/TER.h:121
temINVALID_ACCOUNT_ID = -268  # xahaud:include/xrpl/protocol/TER.h:122
temCANNOT_PREAUTH_SELF = -267  # xahaud:include/xrpl/protocol/TER.h:123
temINVALID_COUNT = -266  # xahaud:include/xrpl/protocol/TER.h:124
temUNCERTAIN = -265  # xahaud:include/xrpl/protocol/TER.h:126
temUNKNOWN = -264  # xahaud:include/xrpl/protocol/TER.h:127
temSEQ_AND_TICKET = -263  # xahaud:include/xrpl/protocol/TER.h:129
temBAD_NFTOKEN_TRANSFER_FEE = -262  # xahaud:include/xrpl/protocol/TER.h:130
temBAD_AMM_TOKENS = -261  # xahaud:include/xrpl/protocol/TER.h:132
temXCHAIN_EQUAL_DOOR_ACCOUNTS = -260  # xahaud:include/xrpl/protocol/TER.h:134
temXCHAIN_BAD_PROOF = -259  # xahaud:include/xrpl/protocol/TER.h:135
temXCHAIN_BRIDGE_BAD_ISSUES = -258  # xahaud:include/xrpl/protocol/TER.h:136
temXCHAIN_BRIDGE_NONDOOR_OWNER = -257  # xahaud:include/xrpl/protocol/TER.h:137
temXCHAIN_BRIDGE_BAD_MIN_ACCOUNT_CREATE_AMOUNT = -256  # xahaud:include/xrpl/protocol/TER.h:138
temXCHAIN_BRIDGE_BAD_REWARD_AMOUNT = -255  # xahaud:include/xrpl/protocol/TER.h:139
temXCHAIN_TOO_MANY_ATTESTATIONS = -254  # xahaud:include/xrpl/protocol/TER.h:140
temHOOK_DATA_TOO_LARGE = -253  # xahaud:include/xrpl/protocol/TER.h:142
temEMPTY_DID = -252  # xahaud:include/xrpl/protocol/TER.h:143
temARRAY_EMPTY = -251  # xahaud:include/xrpl/protocol/TER.h:145
temARRAY_TOO_LARGE = -250  # xahaud:include/xrpl/protocol/TER.h:146
temBAD_TRANSFER_FEE = -249  # xahaud:include/xrpl/protocol/TER.h:148

# ---- TEFcodes ----
tefFAILURE = -199  # xahaud:include/xrpl/protocol/TER.h:171
tefALREADY = -198  # xahaud:include/xrpl/protocol/TER.h:172
tefBAD_ADD_AUTH = -197  # xahaud:include/xrpl/protocol/TER.h:173
tefBAD_AUTH = -196  # xahaud:include/xrpl/protocol/TER.h:174
tefBAD_LEDGER = -195  # xahaud:include/xrpl/protocol/TER.h:175
tefCREATED = -194  # xahaud:include/xrpl/protocol/TER.h:176
tefEXCEPTION = -193  # xahaud:include/xrpl/protocol/TER.h:177
tefINTERNAL = -192  # xahaud:include/xrpl/protocol/TER.h:178
tefNO_AUTH_REQUIRED = -191  # xahaud:include/xrpl/protocol/TER.h:179
tefPAST_SEQ = -190  # xahaud:include/xrpl/protocol/TER.h:180
tefWRONG_PRIOR = -189  # xahaud:include/xrpl/protocol/TER.h:181
tefMASTER_DISABLED = -188  # xahaud:include/xrpl/protocol/TER.h:182
tefMAX_LEDGER = -187  # xahaud:include/xrpl/protocol/TER.h:183
tefBAD_SIGNATURE = -186  # xahaud:include/xrpl/protocol/TER.h:184
tefBAD_QUORUM = -185  # xahaud:include/xrpl/protocol/TER.h:185
tefNOT_MULTI_SIGNING = -184  # xahaud:include/xrpl/protocol/TER.h:186
tefBAD_AUTH_MASTER = -183  # xahaud:include/xrpl/protocol/TER.h:187
tefINVARIANT_FAILED = -182  # xahaud:include/xrpl/protocol/TER.h:188
tefTOO_BIG = -181  # xahaud:include/xrpl/protocol/TER.h:189
tefNO_TICKET = -180  # xahaud:include/xrpl/protocol/TER.h:190
tefNFTOKEN_IS_NOT_TRANSFERABLE = -179  # xahaud:include/xrpl/protocol/TER.h:191
tefPAST_IMPORT_SEQ = -178  # xahaud:include/xrpl/protocol/TER.h:192
tefPAST_IMPORT_VL_SEQ = -177  # xahaud:include/xrpl/protocol/TER.h:193
tefNONDIR_EMIT = -176  # xahaud:include/xrpl/protocol/TER.h:194
tefIMPORT_BLACKHOLED = -175  # xahaud:include/xrpl/protocol/TER.h:195
tefINVALID_LEDGER_FIX_TYPE = -174  # xahaud:include/xrpl/protocol/TER.h:196

# ---- TERcodes ----
terRETRY = -99  # xahaud:include/xrpl/protocol/TER.h:223
terFUNDS_SPENT = -98  # xahaud:include/xrpl/protocol/TER.h:224
terINSUF_FEE_B = -97  # xahaud:include/xrpl/protocol/TER.h:225
terNO_ACCOUNT = -96  # xahaud:include/xrpl/protocol/TER.h:226
terNO_AUTH = -95  # xahaud:include/xrpl/protocol/TER.h:227
terNO_LINE = -94  # xahaud:include/xrpl/protocol/TER.h:228
terOWNERS = -93  # xahaud:include/xrpl/protocol/TER.h:229
terPRE_SEQ = -92  # xahaud:include/xrpl/protocol/TER.h:230
terLAST = -91  # xahaud:include/xrpl/protocol/TER.h:232
terNO_RIPPLE = -90  # xahaud:include/xrpl/protocol/TER.h:233
terQUEUED = -89  # xahaud:include/xrpl/protocol/TER.h:234
terPRE_TICKET = -88  # xahaud:include/xrpl/protocol/TER.h:235
terNO_AMM = -87  # xahaud:include/xrpl/protocol/TER.h:236
terNO_HOOK = -86  # xahaud:include/xrpl/protocol/TER.h:237

# ---- TEScodes ----
tesSUCCESS = 0  # xahaud:include/xrpl/protocol/TER.h:253
tesPARTIAL = 1  # xahaud:include/xrpl/protocol/TER.h:254

# ---- TECcodes ----
tecCLAIM = 100  # xahaud:include/xrpl/protocol/TER.h:280
tecPATH_PARTIAL = 101  # xahaud:include/xrpl/protocol/TER.h:281
tecUNFUNDED_ADD = 102  # xahaud:include/xrpl/protocol/TER.h:282
tecUNFUNDED_OFFER = 103  # xahaud:include/xrpl/protocol/TER.h:283
tecUNFUNDED_PAYMENT = 104  # xahaud:include/xrpl/protocol/TER.h:284
tecFAILED_PROCESSING = 105  # xahaud:include/xrpl/protocol/TER.h:285
tecDIR_FULL = 121  # xahaud:include/xrpl/protocol/TER.h:286
tecINSUF_RESERVE_LINE = 122  # xahaud:include/xrpl/protocol/TER.h:287
tecINSUF_RESERVE_OFFER = 123  # xahaud:include/xrpl/protocol/TER.h:288
tecNO_DST = 124  # xahaud:include/xrpl/protocol/TER.h:289
tecNO_DST_INSUF_NATIVE = 125  # xahaud:include/xrpl/protocol/TER.h:290
tecNO_LINE_INSUF_RESERVE = 126  # xahaud:include/xrpl/protocol/TER.h:291
tecNO_LINE_REDUNDANT = 127  # xahaud:include/xrpl/protocol/TER.h:292
tecPATH_DRY = 128  # xahaud:include/xrpl/protocol/TER.h:293
tecUNFUNDED = 129  # xahaud:include/xrpl/protocol/TER.h:294
tecNO_ALTERNATIVE_KEY = 130  # xahaud:include/xrpl/protocol/TER.h:295
tecNO_REGULAR_KEY = 131  # xahaud:include/xrpl/protocol/TER.h:296
tecOWNERS = 132  # xahaud:include/xrpl/protocol/TER.h:297
tecNO_ISSUER = 133  # xahaud:include/xrpl/protocol/TER.h:298
tecNO_AUTH = 134  # xahaud:include/xrpl/protocol/TER.h:299
tecNO_LINE = 135  # xahaud:include/xrpl/protocol/TER.h:300
tecINSUFF_FEE = 136  # xahaud:include/xrpl/protocol/TER.h:301
tecFROZEN = 137  # xahaud:include/xrpl/protocol/TER.h:302
tecNO_TARGET = 138  # xahaud:include/xrpl/protocol/TER.h:303
tecNO_PERMISSION = 139  # xahaud:include/xrpl/protocol/TER.h:304
tecNO_ENTRY = 140  # xahaud:include/xrpl/protocol/TER.h:305
tecINSUFFICIENT_RESERVE = 141  # xahaud:include/xrpl/protocol/TER.h:306
tecNEED_MASTER_KEY = 142  # xahaud:include/xrpl/protocol/TER.h:307
tecDST_TAG_NEEDED = 143  # xahaud:include/xrpl/protocol/TER.h:308
tecINTERNAL = 144  # xahaud:include/xrpl/protocol/TER.h:309
tecOVERSIZE = 145  # xahaud:include/xrpl/protocol/TER.h:310
tecCRYPTOCONDITION_ERROR = 146  # xahaud:include/xrpl/protocol/TER.h:311
tecINVARIANT_FAILED = 147  # xahaud:include/xrpl/protocol/TER.h:312
tecEXPIRED = 148  # xahaud:include/xrpl/protocol/TER.h:313
tecDUPLICATE = 149  # xahaud:include/xrpl/protocol/TER.h:314
tecKILLED = 150  # xahaud:include/xrpl/protocol/TER.h:315
tecHAS_OBLIGATIONS = 151  # xahaud:include/xrpl/protocol/TER.h:316
tecTOO_SOON = 152  # xahaud:include/xrpl/protocol/TER.h:317
tecHOOK_REJECTED = 153  # xahaud:include/xrpl/protocol/TER.h:318
tecMAX_SEQUENCE_REACHED = 154  # xahaud:include/xrpl/protocol/TER.h:319
tecNO_SUITABLE_NFTOKEN_PAGE = 155  # xahaud:include/xrpl/protocol/TER.h:320
tecNFTOKEN_BUY_SELL_MISMATCH = 156  # xahaud:include/xrpl/protocol/TER.h:321
tecNFTOKEN_OFFER_TYPE_MISMATCH = 157  # xahaud:include/xrpl/protocol/TER.h:322
tecCANT_ACCEPT_OWN_NFTOKEN_OFFER = 158  # xahaud:include/xrpl/protocol/TER.h:323
tecINSUFFICIENT_FUNDS = 159  # xahaud:include/xrpl/protocol/TER.h:324
tecOBJECT_NOT_FOUND = 160  # xahaud:include/xrpl/protocol/TER.h:325
tecINSUFFICIENT_PAYMENT = 161  # xahaud:include/xrpl/protocol/TER.h:326
tecUNFUNDED_AMM = 162  # xahaud:include/xrpl/protocol/TER.h:327
tecAMM_BALANCE = 163  # xahaud:include/xrpl/protocol/TER.h:328
tecAMM_FAILED = 164  # xahaud:include/xrpl/protocol/TER.h:329
tecAMM_INVALID_TOKENS = 165  # xahaud:include/xrpl/protocol/TER.h:330
tecAMM_EMPTY = 166  # xahaud:include/xrpl/protocol/TER.h:331
tecAMM_NOT_EMPTY = 167  # xahaud:include/xrpl/protocol/TER.h:332
tecAMM_ACCOUNT = 168  # xahaud:include/xrpl/protocol/TER.h:333
tecREQUIRES_FLAG = 169  # xahaud:include/xrpl/protocol/TER.h:334
tecPRECISION_LOSS = 170  # xahaud:include/xrpl/protocol/TER.h:335
tecXCHAIN_BAD_TRANSFER_ISSUE = 171  # xahaud:include/xrpl/protocol/TER.h:336
tecXCHAIN_NO_CLAIM_ID = 172  # xahaud:include/xrpl/protocol/TER.h:337
tecXCHAIN_BAD_CLAIM_ID = 173  # xahaud:include/xrpl/protocol/TER.h:338
tecXCHAIN_CLAIM_NO_QUORUM = 174  # xahaud:include/xrpl/protocol/TER.h:339
tecXCHAIN_PROOF_UNKNOWN_KEY = 175  # xahaud:include/xrpl/protocol/TER.h:340
tecXCHAIN_CREATE_ACCOUNT_NONXRP_ISSUE = 176  # xahaud:include/xrpl/protocol/TER.h:341
tecXCHAIN_WRONG_CHAIN = 177  # xahaud:include/xrpl/protocol/TER.h:342
tecXCHAIN_REWARD_MISMATCH = 178  # xahaud:include/xrpl/protocol/TER.h:343
tecXCHAIN_NO_SIGNERS_LIST = 179  # xahaud:include/xrpl/protocol/TER.h:344
tecXCHAIN_SENDING_ACCOUNT_MISMATCH = 180  # xahaud:include/xrpl/protocol/TER.h:345
tecXCHAIN_INSUFF_CREATE_AMOUNT = 181  # xahaud:include/xrpl/protocol/TER.h:346
tecXCHAIN_ACCOUNT_CREATE_PAST = 182  # xahaud:include/xrpl/protocol/TER.h:347
tecXCHAIN_ACCOUNT_CREATE_TOO_MANY = 183  # xahaud:include/xrpl/protocol/TER.h:348
tecXCHAIN_PAYMENT_FAILED = 184  # xahaud:include/xrpl/protocol/TER.h:349
tecXCHAIN_SELF_COMMIT = 185  # xahaud:include/xrpl/protocol/TER.h:350
tecXCHAIN_CREATE_ACCOUNT_DISABLED = 186  # xahaud:include/xrpl/protocol/TER.h:351
tecXCHAIN_BAD_PUBLIC_KEY_ACCOUNT_PAIR = 192  # xahaud:include/xrpl/protocol/TER.h:352
tecINSUF_RESERVE_SELLER = 187  # xahaud:include/xrpl/protocol/TER.h:353
tecIMMUTABLE = 188  # xahaud:include/xrpl/protocol/TER.h:354
tecTOO_MANY_REMARKS = 189  # xahaud:include/xrpl/protocol/TER.h:355
tecHAS_HOOK_STATE = 190  # xahaud:include/xrpl/protocol/TER.h:356
tecINCOMPLETE = 191  # xahaud:include/xrpl/protocol/TER.h:357
tecEMPTY_DID = 193  # xahaud:include/xrpl/protocol/TER.h:359
tecINVALID_UPDATE_TIME = 194  # xahaud:include/xrpl/protocol/TER.h:360
tecTOKEN_PAIR_NOT_FOUND = 195  # xahaud:include/xrpl/protocol/TER.h:361
tecARRAY_EMPTY = 196  # xahaud:include/xrpl/protocol/TER.h:362
tecARRAY_TOO_LARGE = 197  # xahaud:include/xrpl/protocol/TER.h:363
tecLOCKED = 198  # xahaud:include/xrpl/protocol/TER.h:364
tecBAD_CREDENTIALS = 199  # xahaud:include/xrpl/protocol/TER.h:365
tecLAST_POSSIBLE_ENTRY = 255  # xahaud:include/xrpl/protocol/TER.h:366

_PREFIXES = ('tel', 'tem', 'tef', 'ter', 'tes', 'tec')

_CODES: dict[str, int] = {
    _n: _v for _n, _v in list(globals().items())
    if _n[:3] in _PREFIXES and isinstance(_v, int)
}

_NAMES: dict[int, str] = {}
for _n, _v in _CODES.items():   # first declaration wins
    _NAMES.setdefault(_v, _n)


def code(name: str) -> int:
    """Numeric TER for a symbolic name, e.g. 'tecDST_TAG_NEEDED' -> 143."""
    return _CODES[name]


def name(code: int) -> str:
    """Symbolic name for a numeric TER, e.g. 143 -> 'tecDST_TAG_NEEDED'."""
    return _NAMES[code]
