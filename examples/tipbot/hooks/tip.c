/**
 * Non-custodial Tip bot Hook
 * Author: Richard Holland
 * Date: 20/2/26
 * Description:
 *  Supports tipping on social media platforms (especially twitter/X, netid=1)
 *  Tip actions are monitored by tipbot oracle nodes
 *  Nodes vote on which tips they saw, the amount, the to and from (oracle game)
 *  Hook actions tip after meeting vote quorum
 *  Tipbot Oracle Nodes (TONs) also participate in a governance game
 *  to maintain who is a valid TON according to the Hook.
 */

#include <stdint.h>
#include "hookapi.h"

#define SVAR(x) &(x), sizeof(x)
#define DONE(x) accept((x), sizeof(x), __LINE__)
#define NOPE(x) rollback((x), sizeof(x), __LINE__)


/* Oracle game:
 * Parameter keys: 0..F
 * Parameter values: (le)
 * bytes : type : desc
 * -------------------
 * 00-00 :  u8  : social network ID (1 = twitter, 0 = no more params, 254 = member voting, 255 = hook voting)
 * 01-08 : u64  : post ID
 * 09-28 : var  : user ID to (if first 12 bytes are 0) else accid to
 * 29-36 : u64  : user ID from
 * 37-56 : cur  : currency code
 * 57-76 : acc  : issuer accid
 * 77-84 : xfl  : amount tipped
 */

// cleanup keys are bounded by the values at these two keys
uint8_t cleanup_key_highwater[32] = {'S', 'H'};
uint8_t cleanup_key_lowwater[32] = {'S', 'L'};

uint8_t members_bitfield_key[32] = {'S', 'M'};

uint8_t cleanup_key_lower[32] = {'C'};
uint8_t cleanup_key_upper[32] = {'C'};

uint64_t* cleanup_lower = cleanup_key_lower + 1;
uint64_t* cleanup_upper = cleanup_key_upper + 1;

uint8_t otxn_acc[21] = { 'M' };

//uint8_t user_info_key[22] = { 'U' };

// state keys:
// 'S' L/H/M/U     - special keys above: low water mark, high water mark (for gc), m for member bit field
// 'M' accid       - accid -> seat id
// 'P' seatid      - seat (pos) id -> accid
// 'C' cleaupid    - cleanupid->cleanup key
// 'O' opinion     - snid.postid->post_info
// 'H' pos         - voting said hook hash can be installed at this position (action by other hook)
// 'B' balhash     - user-currency-issuer balance hashes
// user info below contains a catalogue of which balances are held by a given user.
// 'U' useracc     - snid.11zeros.userid or accid -> 256 bit field containing keys to balances held
// 'U' useracc . c - as above but with a one byte indicator as per bit field -> validly held balance hash
 
/*  Result codes:
        D  = Actioned already (done)
        V  = Voted already
        S  = Submitted vote
        A  = Actioned now
        B  = Can't action because balance of sender is too low
        E  = Internal error
        e  = Internal error 2
        W  = Invalid opinion (amt <= 0)
        C  = Can't slot new currency in destination user (too many currencies > 256)
       ' ' = No opinion in this slot
*/
uint8_t donemsg[] = "Tip: 00 Opinions processed. Results:                 ";
uint8_t* tens = (donemsg + 5U);
uint8_t* ones = (donemsg + 6U);


// populate all initial oracle game members here according to their accid, don't forget to
// include additional INIT_MEM macro calls below if adding more
uint8_t initial_members[] = {
    // 0 - rNS4Kt6MuKs8938s4HZgh21r69c48FjNUC
    'M', 
    0x93U,0x65U,0xD6U,0x06U,0xD7U,0x88U,0x4DU,0xC8U,0x95U,0xD0U,
    0xB1U,0x73U,0x2DU,0x19U,0x2CU,0x99U,0x8EU,0x25U,0xA5U,0xAEU,

    // 1 - rJFhr4tGrgJb78V2CixFGXT9hG3NjTduiB 
    'M',
    0xC3U,0x60U,0x32U,0xBFU,0x5EU,0x1AU,0xDEU,0x77U,0x23U,0x0FU,
    0xB8U,0x1EU,0x3DU,0xBEU,0x69U,0x9CU,0xE0U,0x79U,0x3CU,0x07U,

    // 2 - r44SzumX2WtNSjvwHibB6RGhrD2f8AWFvN
    'M',
    0xEAU,0x69U,0x14U,0x3DU,0xA3U,0xCFU,0x57U,0x66U,0xFFU,0x73U,
    0x63U,0x16U,0x70U,0xFBU,0x27U,0x77U,0x13U,0x4BU,0x56U,0x6FU
};
int64_t hook(uint32_t r)
{
    _g(1,1);

    uint32_t current_ledger = ledger_seq();
    // FIX: when current_ledger < 20, the subtraction wraps to ~4 billion
    // (uint32_t underflow), causing every entry to appear "older than cutoff"
    // and be immediately reaped — including freshly created state.
    uint32_t cutoff_ledger = current_ledger > 20U ? current_ledger - 20U : 0;

    // pickup the gc boundaries, these represent which keys to examine for amortized removal
    state(cleanup_key_upper + 1, 8, SBUF(cleanup_key_highwater));
    state(cleanup_key_lower + 1, 8, SBUF(cleanup_key_lowwater));
    
    // try to clean up 16 entries
    for (int i = 0; GUARD(16), *cleanup_lower < *cleanup_upper && i < 16; ++i, ++*cleanup_lower)
    {
        uint8_t key[256];
        int64_t key_len = state(SBUF(key), SBUF(cleanup_key_lower));

        TRACEVAR(key_len);
        TRACEHEX(key);
        if (key_len < 0)
            break;

        uint8_t val[256];
        int64_t val_len = state(SBUF(val), key, key_len);

        TRACEVAR(val_len);
        TRACEHEX(val);
        /*if (val_len < 4)
        {
            // delete the cleanup entry
            state_set(0, 0, SBUF(cleanup_key_lower));
            continue;
        }*/
        
        uint32_t entry_ledger = *((uint32_t*)val);
        TRACEVAR(entry_ledger);
        TRACEVAR(cutoff_ledger);

        if (entry_ledger > cutoff_ledger)
            break;

        // delete the entry pointed to
        state_set(0, 0, key, key_len);
        // delete the cleanup entry
        state_set(0, 0, SBUF(cleanup_key_lower));
    }
    
    state_set(cleanup_lower, 8,  SBUF(cleanup_key_lowwater));

    // we've done amortized cleanup, so early ending will always be via DONE, so we get the cleanup processing
    // done even if there was an error   

    otxn_field(otxn_acc + 1, 20, sfAccount);

    uint8_t hook_acc[20];
    hook_account(SBUF(hook_acc));

    if (BUFFER_EQUAL_20(hook_acc, (otxn_acc+1)))
        DONE("Tip: Passing outgoing txn.");

    uint8_t tt[2];
    otxn_field(SBUF(tt), sfTransactionType);
    if (tt[0] != 0 || tt[1] != ttINVOKE)
        DONE("Tip: Passing non-invoke.");

    uint8_t members_bitfield[32];
    state(SBUF(members_bitfield), SBUF(members_bitfield_key));

    // the members bit field is a 256 bit field where the left most bit (msb) indicates if the seat for member 255
    // is occupied and the right most bit (lsb) indicates if the seat for member 0 is occupied. we count the set
    // bits using a wasm intrinsic called popcnt, and this gives us the total current membership of the smart contract
    // we count the members by dividing the bit field into 4 lots of u64
    uint16_t member_count =
            __builtin_popcountll(*((uint64_t*)(members_bitfield +  0))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield +  8))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield + 16))) +
            __builtin_popcountll(*((uint64_t*)(members_bitfield + 24)));
    
    if (member_count == 0)
    {
        // do initial member setup

        // backward and forward keys for each initial member:
        uint8_t member_id = 0;
        uint8_t* ptr = initial_members;
        #define INIT_MEM\
        {\
            members_bitfield[0] <<= 1U;\
            members_bitfield[0] |= 1U;\
            state_set(SVAR(member_id), ptr, 21U);\
            uint8_t pos[2] = {'P', member_id++};\
            state_set(ptr + 1, 20U, SBUF(pos));\
            ptr += 21U;\
        }
        INIT_MEM;
        INIT_MEM;
        INIT_MEM; // add a line for each initial member to avoid an explicit loop here
        state_set(SBUF(members_bitfield), SBUF(members_bitfield_key));

        member_count = 3;
    }

    // first check if they are a member of the game
    uint8_t member_id;
    if (state(SVAR(member_id), SBUF(otxn_acc)) != 1)
        DONE("Tip: You're not a member of the tipbot oracle game. Did some cleanup anyway.");

    // execution to here means they're a member
    uint8_t const member_id_byte = member_id >> 3;
    uint8_t const member_id_bit = member_id % 8;

    // threshold for actioning a tip is >50% of the members
    uint8_t threshold = (uint8_t)(member_count >> 1U);

    // logic for threshold follows.
    // maintain a super majority at any cost with as little computation as possible:
    // if we have 1 member  then 1 >> 1U == 0, so increment to 1    (1/1 == 100%)
    // if we have 2 members then 2 >> 1U == 1, so increment to 2    (2/2 == 100%)
    // if we have 3 members then 3 >> 1U == 1, so increment to 2    (2/3 ==  66%)
    // if we have 4 members then 4 >> 1U == 2, so increment to 3    (3/4 ==  75%)
    // if we have 5 members then 5 >> 1U == 2, so increment to 3    (3/5 ==  60%)
    // if we have 6 members then 6 >> 1U == 3, so increment to 4    (4/6 ==  66%)
    // and so on
    threshold++;

    TRACEVAR(member_count);
    TRACEVAR(threshold);

#define SNID   *((uint8_t*)(opinion +  1U))
#define POSTID *((uint64_t*)(opinion +  2U))
#define FROMID *((uint64_t*)(opinion + 30U))
#define FROMID_PTR ((uint64_t*)(opinion + 30U))
// only if tip isn't to an r-addr
#define TOID   *((uint64_t*)(opinion + 22U))
// only if tip is to an r-addr
#define TOACC  (opinion + 10U)
// whether the tip is to an r-addr or not
#define IS_TOACC  (\
        *((uint64_t*)(opinion + 10U)) != 0 ||\
        *((uint32_t*)(opinion + 18U)) != 0)
#define CUR    (opinion + 38U)
#define ISS    (opinion + 58U)
#define AMTXFL *((uint64_t*)(opinion + 78U))

    // process opinions
    int i = 0;
    uint8_t* donemsg_upto = donemsg + 37;
    for (; GUARD(16), i < 16; ++i, ++donemsg_upto)
    {
        uint8_t opinion[86] ;
        opinion[0] = 'O';
        
        // a social network id of 0 is the same as stop processing

        int64_t r = otxn_param(opinion + 1, 85, &i, 1);

        TRACEVAR(r);
        if (r != 85 || !SNID)
            break;
        

        // get some information about the post... the ledger it first appeared in
        // whether any xfer on it has been actioned, and who voted
        uint8_t post_info[37] = {};
        /*
            key: netid-postid (u8.u64)
            value: 37 bytes comprisning--
            byte : type : desc
            0-3  : u32  : ledger seq first appearing in
            4-4  : u8   : 1=actioned, 0=not yet actioned
            5-36 : b256 : bit field of member ids who have voted with msb being member 255
        */

        // we'll set the ledger_seq before calling the state recall api, that way if the state doesn't exist
        // the ledger_seq is pre-loaded into the field, and if it does exist it's overriden by the contents
        // of the state entry. this way only the ledger_seq of the first vote (temporaly) is recorded
    
        *((uint32_t*)post_info) = current_ledger;

        if (state(post_info, 37, opinion, 10 /*    'O' . netid . 8 bytes of post id, 
                                                or 'O' . 254   . 1 byte position . 7 bytes lead bytes accid, 
                                                or 'O' . 255   . 1 byte position . 7 bytes lead bytes hhash */) < 0)
        {   
            // add a cleanup key if the entry doesn't exist 
            state_set(opinion, 10, SBUF(cleanup_key_upper));
            ++*cleanup_upper;
        }

        if (post_info[4])
        {
            // tip already actioned
            *donemsg_upto = 'D';
            continue;
        }
        
        // check if user already voted in on this post        
        if ((post_info[5 + member_id_byte] >> member_id_bit) & 1)
        {
            // already voted
            *donemsg_upto = 'V';
            continue;
        }

        *donemsg_upto = 'S';

        // record vote
        post_info[5 + member_id_byte] |= (1U << member_id_bit);

        // now we've processed the general infomation about the post, process the specific information
        // about this opinion expressed by the oracle game member (who xfer'd what to whom)

        // FIX: votes_raw must be zero-initialized. On the first vote for a
        // given opinion, state() returns DOESNT_EXIST and leaves the buffer
        // untouched. Without = {0}, votes[4] (the counter byte) contains
        // stack garbage, producing incorrect vote counts.
        uint32_t votes_raw[2] = {0};
        uint8_t* votes = votes_raw;
        votes_raw[0] = current_ledger; // all values are prefixed with ledger seq for cleanup
        TRACEVAR(current_ledger);
        TRACEVAR(votes_raw[0]);

uint8_t txn_id[32];
int64_t bytes_written =
    otxn_id(txn_id, 32, 0);
        TRACEHEX(txn_id);
       
        TRACEHEX(opinion); 
        uint8_t opinion_key[32];
        util_sha512h(SBUF(opinion_key), SBUF(opinion));
        opinion_key[0] = 'O';

        TRACEHEX(opinion_key);
        int64_t res = state(votes, 5, SBUF(opinion_key));

        TRACEVAR(res);

        TRACEHEX(votes);

        votes[4]++;
        TRACEVAR(votes[4]);
        
        state_set(votes, 5, SBUF(opinion_key));
        
        // assign a cleanup key if this is a new opinion
        if (votes[4] == 1)
        {
            state_set(SBUF(opinion_key), SBUF(cleanup_key_upper));
            ++*cleanup_upper;
        }

        // check if the threshold is met (>50% of members)
        if (votes[4] >= threshold)
            post_info[4] = 1;

        TRACEVAR(threshold);
        TRACEVAR(post_info[4]);

        // update postinfo
        state_set(post_info, 37, opinion, 10);
        // TODO: BUG — post_info[4]=1 is written to state HERE, but validation
        // (W/B/E/O/C checks below) hasn't run yet. If validation fails, the post
        // is permanently marked as actioned without the balance transfer happening.
        // Future votes return 'D' (already actioned) so the tip can never be retried.
        // FIX: move validation checks BEFORE setting post_info[4]=1, or defer the
        // state_set until after validation passes.

        // only continue past this point if we're actioning the tip
        if (!post_info[4])
            continue;

        *donemsg_upto = 'A';

        // check if the from user has balance to cover
        
        // balances key (sha512h hashed):
        // bytes : type : desc
        // 00-19 : xahau accid or snetid(1 byte)..00..userid(8 bytes)
        // 20-39 : cur  : 20 byte currency code (zeros for xah)
        // 40-59 : acc  : 20 byte issuer accid  (zeros for xah)
      
        /*
        opinion binary layout: 
        S = Social network id (u8)
        P = Post id (u64)                           
        T = Send to (accid or social network userid u64 LE) 
        F = Sent from (social network userid u64 LE)          
        C = Cur code
        I = Issuer Addr
        A = XFLAmt
        
        M = member accid (zero account to remove member)
        D = member slot (position 0 - 255)
        H = Hook Hash
        K = Hook On
        L = Hook position

        O = Literal ascii O used to mark an opinion

        There are three different types of opinion: tip voting, member voting and hook voting.

        0         1         2         3         4         5         6         7         8
        01234567890123456789012345678901234567890123456789012345678901234567890123456789012345
 tip    OSPPPPPPPPTTTTTTTTTTTTTTTTTTTTFFFFFFFFCCCCCCCCCCCCCCCCCCCCIIIIIIIIIIIIIIIIIIIIAAAAAAAA
 mem    OSDMMMMMMMMMMMMMMMMMMMM000000000000000000000000000000000000000000000000000000000000000
 hook   OSLHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK0000000000000000000
        */ 

        if (SNID == 255)
        {
            // action hook change
            // because this requires an emit we don't handle it inside this large loop
            // rather set a state entry that lets another hook do the emit
            uint8_t key[2] = { 'H', opinion[2] };
            state_set(opinion + 3, 64, SBUF(key));
            continue;
        }

        if (SNID == 254)
        {
            // action member voting
            uint8_t memacc[21] = {'M'};
            uint8_t pos[2] = {'P', opinion[2]};
            
            // always delete a member even if its already empty
            members_bitfield[opinion[2] >> 3] &= ~(1U << (opinion[2] % 8));
            state(memacc + 1, 20,  SBUF(pos));
            state_set(0,0, SBUF(memacc));
            state_set(0,0, SBUF(pos));

            if (!((*((uint64_t*)(opinion + 3)) == 0 && 
                *((uint64_t*)(opinion + 11)) == 0 && 
                *((uint32_t*)(opinion + 19)) == 0)))
            {
                // if the specified acc isnt the zero account we'll add a member too
                // copy accid into member key
                *((uint64_t*)(memacc+1)) = *((uint64_t*)(opinion + 3));
                *((uint64_t*)(memacc+9)) = *((uint64_t*)(opinion + 11));
                *((uint32_t*)(memacc+17)) = *((uint32_t*)(opinion + 19));

                // FIX: if the new account already occupies a different seat,
                // the old seat's reverse key ('P' + old_seat) and its bit in
                // the members bitfield must be cleared first. Without this,
                // the same account ends up in two seats — inflating
                // member_count and distorting the voting threshold.
                uint8_t existing_pos;
                if (state(SVAR(existing_pos), SBUF(memacc)) == 1 && existing_pos != opinion[2])
                {
                    uint8_t existing_reverse[2] = {'P', existing_pos};
                    members_bitfield[existing_pos >> 3] &= ~(1U << (existing_pos % 8));
                    state_set(0, 0, SBUF(existing_reverse));
                }

                // add / move member into the requested seat
                members_bitfield[opinion[2] >> 3] |= (1U << (opinion[2] % 8));

                // add member key
                state_set(opinion + 2, 1, SBUF(memacc));

                // add reverse key
                state_set(memacc + 1, 20, SBUF(pos)); 
                
            }
            
            // update bitfield
            state_set(SBUF(members_bitfield), SBUF(members_bitfield_key));
            continue;
        }

        // sanity check amount
        // TODO: BUG — this check runs AFTER post is marked actioned (line 354/360).
        // A zero/negative amount opinion that reaches threshold is permanently stuck.
        if (float_compare(AMTXFL, 0, COMPARE_LESS | COMPARE_EQUAL) == 1)
        {
            *donemsg_upto = 'W';
            continue;
        }

        // to avoid double copying the from and to keys will also be the userinfo keys (prefixed with the 'U')
        // however we won't use the 'U' part until a bit later when we need to update user info
        uint8_t from_key[61] = {'U', SNID};

        *((uint64_t*)(from_key + 13U)) = FROMID;
        *((uint64_t*)(from_key + 21U)) = *((uint64_t*)(opinion + 38U));  // first 8 bytes of currency
        *((uint64_t*)(from_key + 29U)) = *((uint64_t*)(opinion + 46U));  // second 8 bytes of currency
        *((uint64_t*)(from_key + 37U)) = *((uint64_t*)(opinion + 54U));  // last 4 bytes of currency, first 4 of iss
        *((uint64_t*)(from_key + 45U)) = *((uint64_t*)(opinion + 62U));  // middle 8 bytes of issuer
        *((uint64_t*)(from_key + 53U)) = *((uint64_t*)(opinion + 70U));  // last 8 bytes of issuer

        uint8_t to_key[61] = {'U', SNID};
        if (IS_TOACC)
        {
            *((uint64_t*)(to_key + 1U)) = *((uint64_t*)(TOACC + 0U));
            *((uint32_t*)(to_key + 9U)) = *((uint32_t*)(TOACC + 8U));
        } 
        *((uint64_t*)(to_key + 13U)) = TOID;
        
        *((uint64_t*)(to_key + 21U)) = *((uint64_t*)(opinion + 38U));  // first 8 bytes of currency
        *((uint64_t*)(to_key + 29U)) = *((uint64_t*)(opinion + 46U));  // second 8 bytes of currency
        *((uint64_t*)(to_key + 37U)) = *((uint64_t*)(opinion + 54U));  // last 4 bytes of currency, first 4 of iss
        *((uint64_t*)(to_key + 45U)) = *((uint64_t*)(opinion + 62U));  // middle 8 bytes of issuer
        *((uint64_t*)(to_key + 53U)) = *((uint64_t*)(opinion + 70U));  // last 8 bytes of issuer

       
        TRACEHEX(from_key);
 
        uint8_t from_key_hash[32];
        util_sha512h(SBUF(from_key_hash), from_key + 1, 60);
        uint8_t to_key_hash[32];
        util_sha512h(SBUF(to_key_hash), to_key + 1, 60);

        from_key_hash[0] = 'B';
        to_key_hash[0] = 'B';

        // balance buffer is 8 bytes of xfl and 1 byte of "balance idx" in the user info
        // user_info bitfield contains 256 slots which is each occupied by a currency
        // this is purely for explorers to look up which currencies are held by which user
        // otherwise full history would be needed to see which currencies are held by a user
        // since the currency pairs are hashed
        uint8_t from_bal_buf[9] = {};

        // the balances key for the from address is already encoded inside the opinion 
        state(SBUF(from_bal_buf), SBUF(from_key_hash));

        TRACEHEX(from_key_hash);
        TRACEHEX(from_bal_buf);
        
        int64_t from_bal = *((uint64_t*)(from_bal_buf));
        uint8_t from_idx = *((uint8_t*)(from_bal_buf + 8U));


        TRACEVAR(from_bal);
        TRACEXFL(from_bal);
        TRACEVAR(AMTXFL);
        TRACEXFL(AMTXFL);

        // check if the balance can even cover the xfer
        // TODO: BUG — same issue: post already marked actioned, balance check too late.
        if (float_compare(from_bal, AMTXFL, COMPARE_LESS) == 1)
        {
            // cannot action the tip, the from balance is too small
            *donemsg_upto = 'B';
            continue;
        }

        // subtract the from balance
        int64_t final_from_bal = float_sum(from_bal, float_negate(AMTXFL));
        // TODO: BUG — post already marked actioned.
        if (final_from_bal < 0 || float_compare(final_from_bal, from_bal, COMPARE_GREATER | COMPARE_EQUAL) == 1)
        {
            // not a sane result, skip / internal error
            *donemsg_upto = 'E';
            continue;
        }
        
        uint8_t to_bal_buf[9] = {};

        state(SBUF(to_bal_buf), SBUF(to_key_hash));

        int64_t to_bal = *((uint64_t*)(to_bal_buf));
        uint8_t to_idx = *((uint8_t*)(to_bal_buf + 8U)); 


        int64_t final_to_bal = float_sum(to_bal, AMTXFL);

        // TODO: BUG — post already marked actioned.
        if (final_to_bal <= 0 || float_compare(final_to_bal, to_bal, COMPARE_LESS) == 1)
        {
            // internal error / overflow / insane result
            *donemsg_upto = 'O';
            continue;
        }
       
        uint8_t to_user_info[32] = {};
        state(SBUF(to_user_info), to_key, 21);

        uint8_t from_user_info[32] = {};
        state(SBUF(from_user_info), from_key, 21);

        *((uint64_t*)from_bal_buf) = final_from_bal;
        *((uint64_t*)to_bal_buf) = final_to_bal;
        
        if (to_bal == 0)
        {
            // if the to-user didn't have this currency before this xfer we need to "slot-in" a new currency
            // that they are holding according to their userinfo card
            // we do that by finding the lowest available 0 bit in the 256 bit field on the user info key
            uint64_t* w = (uint64_t *)to_user_info;
            uint64_t v;

            if      ((v = ~w[0])) to_idx =       __builtin_ctzll(v);
            else if ((v = ~w[1])) to_idx =  64 + __builtin_ctzll(v);
            else if ((v = ~w[2])) to_idx = 128 + __builtin_ctzll(v);
            else if ((v = ~w[3])) to_idx = 192 + __builtin_ctzll(v);
            else
            {
                // user can't accept new currencies, already maxed out at 256
                // TODO: BUG — post already marked actioned.
                *donemsg_upto = 'C';
                continue;
            }

            to_user_info[to_idx >> 3] |= (uint8_t)(1U << (to_idx % 8U));
            // we'll clober some data in the to_key buffer to construct this user info entry
            // 'U'. snid . 11 zeros . userid . idx, or
            // 'U' . accid . idx
            // 0         1         2
            // 0123456789012345678901
            // UAAAAAAAAAAAAAAAAAAAAI
            // US00000000000UUUUUUUUI
            // maps to currency . issuer (pulled from opinion field)
            to_key[21] = to_idx;
            
            state_set(opinion + 38U, 40, to_key, 22);

            // update the user info to reflect the index
            state_set(SBUF(to_user_info), to_key, 21);

            to_bal_buf[8] = to_idx;
        }

        // update from balance
        if (final_from_bal == 0)
        {
            // if the final balance is completely xfered then remove the currency from the user altogether
            state_set(0,0, SBUF(from_key_hash));

            // also erase the bit from the user's info that represents this currency
            from_user_info[from_idx >> 3U] &= ~((uint8_t)(1U << (from_idx % 8U)));

            state_set(SBUF(from_user_info), from_key, 21);

            // delete the index
            from_key[21] = from_idx;
            state_set(0,0, from_key, 22);
        }
        else
            state_set(SBUF(from_bal_buf), SBUF(from_key_hash));

        
        state_set(SBUF(to_bal_buf), SBUF(to_key_hash));
    }

    // update the cleanup boundaries
    state_set(cleanup_upper, 8,  SBUF(cleanup_key_highwater));

    *tens += i / 10;
    *ones += i % 10;

    DONE(donemsg);
}
