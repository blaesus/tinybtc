#include <stdlib.h>
#include <utils/integers.h>

#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/obj_mac.h"

#include "script.h"
#include "messages/tx.h"
#include "datatypes.h"
#include "parameters.h"
#include "utils/memory.h"
#include "utils/data.h"
#include "utils/bignum.h"

#define UNKNOWN_OPCODE "UNKNOWN_OPCODE"

#define MAX_STACK_FRAME_WIDTH 1024 // TODO: dynamic allocate

#define SECP256K1_TAG_PUBKEY_EVEN 0x02
#define SECP256K1_TAG_PUBKEY_ODD 0x03
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 0x06
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD 0x07

#define MASK_HASHTYPE(ht) (ht & 0x1f)

enum HashType {
    SIGHASH_ALL_ALTERNATIVE = 0,
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

enum FrameType {
    FRAME_TYPE_OP,
    FRAME_TYPE_DATA,
};

struct StackFrame {
    Byte data[MAX_STACK_FRAME_WIDTH];
    uint32_t dataWidth;
    enum FrameType type;

    Byte opHeader[8];
    uint8_t opHeaderWidth;
};

typedef struct StackFrame StackFrame;

struct Stack {
    struct StackFrame *frames[MAX_STACK_HEIGHT];
    uint64_t height;
};

void polish_tx_copy(TxPayload *txCopy, uint32_t hashtype, uint64_t currentInputIndex);

bool is_anonymous_push_data_op(Byte op) {
    return (op > OP_0) && (op < OP_PUSHDATA1);
}

bool is_push_data_op(Byte op) {
    return is_anonymous_push_data_op(op)|| op == OP_PUSHDATA1 || op == OP_PUSHDATA2 || op == OP_PUSHDATA4;
}

void hash_tx_with_hashtype(TxPayload *tx, uint32_t hashType, uint64_t inputIndex, Byte *hash) {
    if (MASK_HASHTYPE(hashType) == SIGHASH_SINGLE
        && tx->txInputCount > tx->txOutputCount
        && inputIndex >= tx->txOutputCount
    ) {
        // Simulate bug, see https://bitcointalk.org/index.php?topic=260595.0
        memset(hash, 0, SHA256_LENGTH);
        hash[0] = 1;
        return;
    }
    polish_tx_copy(tx, hashType, inputIndex);
    Byte *buffer = MALLOC(MESSAGE_BUFFER_LENGTH, "hash_tx_with_hashtype:buffer");
    uint64_t width = serialize_tx_payload(tx, buffer);
    memcpy(buffer + width, &hashType, 4);
    width += 4;
    dsha256(buffer, (uint32_t)width, hash);
    FREE(buffer, "hash_tx_with_hashtype:buffer");
}

typedef struct Stack Stack;

StackFrame get_empty_frame() {
    StackFrame frame;
    memset(&frame, 0, sizeof(frame));
    return frame;
}

StackFrame pop(Stack *stack) {
    if (stack->height == 0) {
        fprintf(stderr, "\nattempting to pop an empty stack; returning empty frame...\n");
        return get_empty_frame();
    }
    StackFrame *ptrTop = stack->frames[stack->height - 1];
    stack->height--;
    StackFrame result = *ptrTop;
    FREE(ptrTop, "push:frame");
    return result;
}

void push(Stack *stack, StackFrame data) {
    stack->frames[stack->height] = CALLOC(1, sizeof(StackFrame), "push:frame");
    memcpy(stack->frames[stack->height], &data, sizeof(StackFrame));
    stack->height++;
}

StackFrame top(Stack *stack) {
    if (stack->height == 0) {
        fprintf(stderr, "\nattempting to top an empty stack; returning empty frame...\n");
        return get_empty_frame();
    }
    return *stack->frames[stack->height - 1];
}

// From Bitcoin 0.0.1

const char *get_op_name(enum OpcodeType opcode) {
    switch (opcode)
    {
        // push value
        case OP_0                      : return "0";
        case OP_PUSHDATA1              : return "OP_PUSHDATA1";
        case OP_PUSHDATA2              : return "OP_PUSHDATA2";
        case OP_PUSHDATA4              : return "OP_PUSHDATA4";
        case OP_1NEGATE                : return "-1";
        case OP_RESERVED               : return "OP_RESERVED";
        case OP_1                      : return "1";
        case OP_2                      : return "2";
        case OP_3                      : return "3";
        case OP_4                      : return "4";
        case OP_5                      : return "5";
        case OP_6                      : return "6";
        case OP_7                      : return "7";
        case OP_8                      : return "8";
        case OP_9                      : return "9";
        case OP_10                     : return "10";
        case OP_11                     : return "11";
        case OP_12                     : return "12";
        case OP_13                     : return "13";
        case OP_14                     : return "14";
        case OP_15                     : return "15";
        case OP_16                     : return "16";

        // control
        case OP_NOP                    : return "OP_NOP";
        case OP_VER                    : return "OP_VER";
        case OP_IF                     : return "OP_IF";
        case OP_NOTIF                  : return "OP_NOTIF";
        case OP_VERIF                  : return "OP_VERIF";
        case OP_VERNOTIF               : return "OP_VERNOTIF";
        case OP_ELSE                   : return "OP_ELSE";
        case OP_ENDIF                  : return "OP_ENDIF";
        case OP_VERIFY                 : return "OP_VERIFY";
        case OP_RETURN                 : return "OP_RETURN";

        // stack ops
        case OP_TOALTSTACK             : return "OP_TOALTSTACK";
        case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
        case OP_2DROP                  : return "OP_2DROP";
        case OP_2DUP                   : return "OP_2DUP";
        case OP_3DUP                   : return "OP_3DUP";
        case OP_2OVER                  : return "OP_2OVER";
        case OP_2ROT                   : return "OP_2ROT";
        case OP_2SWAP                  : return "OP_2SWAP";
        case OP_IFDUP                  : return "OP_IFDUP";
        case OP_DEPTH                  : return "OP_DEPTH";
        case OP_DROP                   : return "OP_DROP";
        case OP_DUP                    : return "OP_DUP";
        case OP_NIP                    : return "OP_NIP";
        case OP_OVER                   : return "OP_OVER";
        case OP_PICK                   : return "OP_PICK";
        case OP_ROLL                   : return "OP_ROLL";
        case OP_ROT                    : return "OP_ROT";
        case OP_SWAP                   : return "OP_SWAP";
        case OP_TUCK                   : return "OP_TUCK";

        // splice ops
        case OP_CAT                    : return "OP_CAT";
        case OP_SUBSTR                 : return "OP_SUBSTR";
        case OP_LEFT                   : return "OP_LEFT";
        case OP_RIGHT                  : return "OP_RIGHT";
        case OP_SIZE                   : return "OP_SIZE";

        // bit logic
        case OP_INVERT                 : return "OP_INVERT";
        case OP_AND                    : return "OP_AND";
        case OP_OR                     : return "OP_OR";
        case OP_XOR                    : return "OP_XOR";
        case OP_EQUAL                  : return "OP_EQUAL";
        case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
        case OP_RESERVED1              : return "OP_RESERVED1";
        case OP_RESERVED2              : return "OP_RESERVED2";

        // numeric
        case OP_1ADD                   : return "OP_1ADD";
        case OP_1SUB                   : return "OP_1SUB";
        case OP_2MUL                   : return "OP_2MUL";
        case OP_2DIV                   : return "OP_2DIV";
        case OP_NEGATE                 : return "OP_NEGATE";
        case OP_ABS                    : return "OP_ABS";
        case OP_NOT                    : return "OP_NOT";
        case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
        case OP_ADD                    : return "OP_ADD";
        case OP_SUB                    : return "OP_SUB";
        case OP_MUL                    : return "OP_MUL";
        case OP_DIV                    : return "OP_DIV";
        case OP_MOD                    : return "OP_MOD";
        case OP_LSHIFT                 : return "OP_LSHIFT";
        case OP_RSHIFT                 : return "OP_RSHIFT";
        case OP_BOOLAND                : return "OP_BOOLAND";
        case OP_BOOLOR                 : return "OP_BOOLOR";
        case OP_NUMEQUAL               : return "OP_NUMEQUAL";
        case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
        case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
        case OP_LESSTHAN               : return "OP_LESSTHAN";
        case OP_GREATERTHAN            : return "OP_GREATERTHAN";
        case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
        case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
        case OP_MIN                    : return "OP_MIN";
        case OP_MAX                    : return "OP_MAX";
        case OP_WITHIN                 : return "OP_WITHIN";

        // crypto
        case OP_RIPEMD160              : return "OP_RIPEMD160";
        case OP_SHA1                   : return "OP_SHA1";
        case OP_SHA256                 : return "OP_SHA256";
        case OP_HASH160                : return "OP_HASH160";
        case OP_HASH256                : return "OP_HASH256";
        case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
        case OP_CHECKSIG               : return "OP_CHECKSIG";
        case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
        case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

        case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

        case OP_NOP1                   : return "OP_NOP1";
        case OP_NOP2                   : return "OP_NOP2/OP_CHECKLOCKTIMEVERIFY";
        default:
            return UNKNOWN_OPCODE;
    }
}

void print_op(Byte op) {
    printf("%s(%#02x)\n", get_op_name(op), op);
}

void print_frame(StackFrame *frame) {
    if (frame->type == FRAME_TYPE_DATA) {
        print_object(frame->data, frame->dataWidth);
    }
    else {
        print_op(frame->data[0]);
    }
}

void print_stack_with_label(struct Stack *stack, char *label) {
    if (!LOG_SCRIPT_STACKS) {
        return;
    }
    if (label) {
        printf("\n=== %s Stack (height=%llu) ===\n", label, stack->height);
    }
    else {
        printf("\n=== Stack (height=%llu) ===\n", stack->height);
    }
    for (uint16_t i = 0; i < stack->height; i++) {
        printf("Frame %02i: ", i);
        print_frame(stack->frames[i]);
    }
    printf("---------------------\n");
}

void load_program(Stack *stack, Byte *program, uint64_t programLength) {
    for (uint64_t i = 0; i < programLength; i++) {
        Byte datum = program[i];
        StackFrame newFrame = get_empty_frame();
        if (is_push_data_op(datum)) {
            newFrame.type = FRAME_TYPE_DATA;
            uint32_t dataWidth = 0;
            uint8_t opHeaderWidth = 0;
            if (is_anonymous_push_data_op(datum)) {
                dataWidth = datum;
                opHeaderWidth = 1;
            }
            else if (datum == OP_PUSHDATA1) {
                dataWidth = program[i+1];
                opHeaderWidth = 2;
            }
            else if (datum == OP_PUSHDATA2) {
                dataWidth = program[i+1] + program[i+2] * 256U;
                opHeaderWidth = 3;
            }
            else {
                fprintf(stderr, "Unimplemented push data op %u\n", datum);
            }
            memcpy(newFrame.opHeader, program + i, opHeaderWidth);
            newFrame.opHeaderWidth = (uint8_t)opHeaderWidth;
            i += opHeaderWidth;

            newFrame.dataWidth = dataWidth;
            memcpy(newFrame.data, program + i, dataWidth);
            i += dataWidth - 1;
        }
        else {
            newFrame.type = FRAME_TYPE_OP;
            newFrame.dataWidth = 1;
            memcpy(newFrame.data, &datum, 1);
            newFrame.opHeaderWidth = 0;
        }
        push(stack, newFrame);
    }
}

uint64_t index_byte_from_end(const Byte *string, uint64_t stringLength, Byte target, bool *found) {
    for (uint64_t i = stringLength; i > 0; i--) {
        if (string[i] == target) {
            if (found) {
                *found = true;
            }
            return i;
        }
    }
    if (found) {
        *found = false;
    }
    return 0;
}

void print_stack(struct Stack *stack) {
    print_stack_with_label(stack, NULL);
}

void print_ops(Byte *array, uint64_t length) {
    for (uint64_t i = 0; i < length; i++) {
        print_op(array[i]);
    }
}

Stack get_empty_stack() {
    Stack stack;
    memset(&stack, 0, sizeof(stack));
    return stack;
}

void free_stack_frames(Stack *stack) {
    for (uint64_t i = 0; i < stack->height; i++) {
        FREE(stack->frames[i]->data, "push:frame");
    }
}

bool are_frames_equal(StackFrame *frameA, StackFrame *frameB) {
    return (frameA->type == frameB->type)
           && (frameA->dataWidth == frameB->dataWidth)
           && (memcmp(frameA->data, frameB->data, frameA->dataWidth) == 0);
}

TxPayload *make_tx_copy(CheckSigMeta meta, Byte *subscript, uint64_t subscriptLength) {
    TxPayload *txCopy = CALLOC(1, sizeof(TxPayload), "make_tx_copy:txCopy");
    clone_tx(meta.currentTx, txCopy);
    for (uint64_t i = 0; i < txCopy->txInputCount; i++) {
        TxIn *txIn = &txCopy->txInputs[i];
        txIn->signature_script_length = 0;
        memset(txIn->signature_script, 0, sizeof(txIn->signature_script));
    }
    memcpy(
        txCopy->txInputs[meta.txInputIndex].signature_script,
        subscript,
        subscriptLength
    );
    txCopy->txInputs[meta.txInputIndex].signature_script_length = subscriptLength;
    return txCopy;
}

#define MAX_SIGNATURE_DATA 128

struct SignatureComponent {
    int8_t type;
    int8_t length;
    Byte data[MAX_SIGNATURE_DATA];
};

typedef struct SignatureComponent SignatureComponent;

struct DerSignature {
    int8_t sequence;
    int8_t length;
    SignatureComponent r;
    SignatureComponent s;
};

typedef struct DerSignature DerSignature;

uint64_t parse_elliptic_point(Byte *ptrBuffer, SignatureComponent *point) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &point->type);
    p += PARSE_INTO(p, &point->length);
    p += PARSE_INTO_OF_LENGTH(p, &point->data, point->length);
    return p - ptrBuffer;
}

uint64_t serialize_elliptic_point(SignatureComponent *point, Byte *ptrBuffer) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(point->type, p);
    p += SERIALIZE_TO(point->length, p);
    p += SERIALIZE_TO_OF_LENGTH(point->data, p, point->length);
    return p - ptrBuffer;
}

uint64_t parse_der(Byte *ptrBuffer, DerSignature *signature) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &signature->sequence);
    p += PARSE_INTO(p, &signature->length);
    p += parse_elliptic_point(p, &signature->r);
    p += parse_elliptic_point(p, &signature->s);
    return p - ptrBuffer;
}

uint64_t serialize_der(DerSignature *signature, Byte *ptrBuffer) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(signature->sequence, p);
    p += SERIALIZE_TO(signature->length, p);
    p += serialize_elliptic_point(&signature->r, p);
    p += serialize_elliptic_point(&signature->s, p);
    return p - ptrBuffer;
}

bool byte_has_initial_zero(Byte n) {
    return (n & 0x80) != 0;
}

int8_t fix_signature_component_preceding_zeros(SignatureComponent *component) {
    int8_t offset = 0;
    // Remove current zeros
    while (component->data[0] == 0 && component->length > 0) {
        memcpy(component->data, component->data+1, component->length-1);
        component->length -= 1;
        offset -= 1;
    }
    // Put in our own
    if (byte_has_initial_zero(component->data[0])) {
        memcpy(component->data+1, component->data, component->length);
        component->data[0] = 0;
        component->length += 1;
        offset += 1;
    }
    return offset;
}

void fix_signature(DerSignature *signature) {
    signature->length += fix_signature_component_preceding_zeros(&signature->r);
    signature->length += fix_signature_component_preceding_zeros(&signature->s);
}

void print_elliptic_point(SignatureComponent *point) {
    printf("point type %i, length %i, data:", point->type, point->length);
    print_object(point->data, (uint64_t)point->length);
}

void print_der(DerSignature *signature) {
    printf("---------- signature ----------\n");
    printf("sequence %#02x, length %i (%#02x)\n", signature->sequence, signature->length, signature->length);
    print_elliptic_point(&signature->r);
    print_elliptic_point(&signature->s);
    printf("-------------------------------\n");
}

void fix_signature_frame(StackFrame *sigFrame) {
    DerSignature *signature = CALLOC(1, sizeof(*signature), "fix_signature_frame:signature");
    parse_der(sigFrame->data, signature);
    #if LOG_SIGNATURE_FIXING
    print_der(signature);
    #endif
    fix_signature(signature);
    #if LOG_SIGNATURE_FIXING
    print_der(signature);
    #endif
    sigFrame->dataWidth = (uint16_t)(serialize_der(signature, sigFrame->data) + 1);
    FREE(signature, "fix_signature_frame:signature");
}


void polish_tx_copy(TxPayload *txCopy, uint32_t hashtype, uint64_t currentInputIndex) {
    if (MASK_HASHTYPE(hashtype) == SIGHASH_NONE) {
        memset(txCopy->txOutputs, 0, sizeof(TxOut) * txCopy->txOutputCount);
        txCopy->txOutputCount = 0;
        for (uint64_t i = 0; i < txCopy->txInputCount; i++) {
            if (i != currentInputIndex) {
                txCopy->txInputs[i].sequence = 0;
            }
        }
    }
    else if (MASK_HASHTYPE(hashtype) == SIGHASH_SINGLE) {
        txCopy->txOutputCount = currentInputIndex + 1;
        txCopy->txOutputs = realloc(txCopy->txOutputs, txCopy->txOutputCount * sizeof(TxOut));
        for (uint64_t i = 0; i < txCopy->txOutputCount; i++) {
            if (i != currentInputIndex) {
                TxOut *out = &txCopy->txOutputs[i];
                out->public_key_script_length = 0;
                out->value = -1;
            }
        }
        for (uint64_t i = 0; i < txCopy->txInputCount; i++) {
            if (i != currentInputIndex) {
                TxIn *input = &txCopy->txInputs[i];
                input->sequence = 0;
            }
        }
    }

    if (hashtype & SIGHASH_ANYONECANPAY) {
        txCopy->txInputs[0] = txCopy->txInputs[currentInputIndex];
        txCopy->txInputCount = 1;
    }
}

bool is_pubkey_prefix_valid(Byte prefix) {
    return prefix == SECP256K1_TAG_PUBKEY_EVEN
           || prefix == SECP256K1_TAG_PUBKEY_ODD
           || prefix == SECP256K1_TAG_PUBKEY_UNCOMPRESSED
           || prefix == SECP256K1_TAG_PUBKEY_HYBRID_EVEN
           || prefix == SECP256K1_TAG_PUBKEY_HYBRID_ODD;
}

bool BN_is_not_zero(BIGNUM *num) {
    return !BN_is_zero(num);
}

typedef void NullaryOperatorFunction(BIGNUM *result);

typedef void BinaryOperatorFunction(BIGNUM *result, BIGNUM *bignum1, BIGNUM *bignum2);

typedef void UnaryOperatorFunction(BIGNUM *result, BIGNUM *bignum);

// Nullary

void negative_one(BIGNUM *result) {
    BN_set_word(result, 1);
    BN_set_negative(result, -1);
}

void perform_nullary_operator(Stack *stack, NullaryOperatorFunction f) {
    BIGNUM *result = BN_new();
    f(result);
    StackFrame resultFrame = {
        .type = FRAME_TYPE_DATA,
    };
    resultFrame.dataWidth = bignum_to_bytes(result, resultFrame.data);
    push(stack, resultFrame);
    BN_free(result);
}

// Unary

void absolute_value(BIGNUM *result, BIGNUM *bignum) {
    BN_copy(result, bignum);
    if (BN_is_negative(result)) {
        BN_set_negative(result, 0);
    }
}

void increment(BIGNUM *result, BIGNUM *bignum) {
    BN_copy(result, bignum);
    BN_add_word(result, 1);
}

void decrement(BIGNUM *result, BIGNUM *bignum) {
    BN_copy(result, bignum);
    BN_sub_word(result, 1);
}

void negate(BIGNUM *result, BIGNUM *bignum) {
    BN_copy(result, bignum);
    if (BN_is_negative(result)) {
        BN_set_negative(result, 0);
    }
    else {
        BN_set_negative(result, -1);
    }
}


void perform_unary_operator(Stack *stack, UnaryOperatorFunction f) {
    StackFrame top = pop(stack);
    BIGNUM *bignum = BN_new();
    bytes_to_bignum(top.data, top.dataWidth, bignum);
    BIGNUM *result = BN_new();
    f(result, bignum);
    StackFrame resultFrame = {
        .type = FRAME_TYPE_DATA,
    };
    resultFrame.dataWidth = bignum_to_bytes(result, resultFrame.data);
    push(stack, resultFrame);
    BN_free(bignum);
    BN_free(result);
}

// Binary

void greater_than(BIGNUM *result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_set_word(result, BN_cmp(bignum2, bignum1) > 0 ? 1 : 0);
}

void less_than(BIGNUM *result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_set_word(result, BN_cmp(bignum2, bignum1) < 0 ? 1 : 0);
}

void equal(BIGNUM* result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_set_word(result, BN_cmp(bignum2, bignum1) == 0 ? 1 : 0);
}

void add(BIGNUM* result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_add(result, bignum2, bignum1);
}

void minus(BIGNUM* result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_sub(result, bignum2, bignum1);
}

void boolean_or(BIGNUM* result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_set_word(result, (Byte)(BN_is_not_zero(bignum1) || BN_is_not_zero(bignum2)));
}

void boolean_and(BIGNUM* result, BIGNUM *bignum1, BIGNUM *bignum2) {
    BN_set_word(result, (Byte)(BN_is_not_zero(bignum1) && BN_is_not_zero(bignum2)));
}

void perform_binary_operator(Stack *stack, BinaryOperatorFunction f) {
    StackFrame frame1 = pop(stack);
    StackFrame frame2 = pop(stack);

    BIGNUM *bignum1 = BN_new();
    bytes_to_bignum(frame1.data, frame1.dataWidth, bignum1);
    BIGNUM *bignum2 = BN_new();
    bytes_to_bignum(frame2.data, frame2.dataWidth, bignum2);
    BIGNUM *result = BN_new();
    f(result, bignum1, bignum2);
    // printf("binary operator: f(%s, %s) = %s\n", BN_bn2dec(bignum1), BN_bn2dec(bignum2), BN_bn2dec(result));

    StackFrame resultFrame = {
        .type = FRAME_TYPE_DATA,
    };
    resultFrame.dataWidth = bignum_to_bytes(result, resultFrame.data);
    push(stack, resultFrame);

    BN_free(bignum1);
    BN_free(bignum2);
    BN_free(result);
}

StackFrame get_numerical_frame(uint32_t value) {
    BIGNUM *result = BN_new();
    BN_set_word(result, value);
    StackFrame resultFrame = {
        .type = FRAME_TYPE_DATA,
    };
    resultFrame.dataWidth = bignum_to_bytes(result, resultFrame.data);
    BN_free(result);
    return resultFrame;
}

StackFrame get_boolean_frame(bool value) {
    return get_numerical_frame((Byte) value);
}


// 1: valid, 0: invalid, <0: error
int8_t check_signature(StackFrame pubkeyFrame, StackFrame sigFrame, CheckSigMeta meta, Byte *subscript, uint64_t subscriptLength) {
    if (!is_pubkey_prefix_valid(pubkeyFrame.data[0])) {
        printf(
            "\nInvalid pubkey prefix %#02x. Possibly arbitrary data. Skipping...\n",
            pubkeyFrame.data[0]
        );
        return -1;
    }
    EC_KEY *ptrPubKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    int32_t status = EC_KEY_oct2key(
        ptrPubKey,
        pubkeyFrame.data,
        pubkeyFrame.dataWidth,
        NULL
    );
    if (status != 1) {
        fprintf(stderr, "Failed to decode elliptic public key\n");
        return -1;
    }

    uint32_t hashtype = sigFrame.data[sigFrame.dataWidth-1];
    fix_signature_frame(&sigFrame);
    SHA256_HASH hashTx = {0};
    TxPayload *txCopy = make_tx_copy(meta, subscript, subscriptLength);
    hash_tx_with_hashtype(txCopy, hashtype, meta.txInputIndex, hashTx);
    release_items_in_tx(txCopy);
    FREE(txCopy, "make_tx_copy:txCopy");

    int32_t verification = ECDSA_verify(
        0,
        hashTx,
        sizeof(hashTx),
        sigFrame.data,
        sigFrame.dataWidth - 1,
        ptrPubKey
    );
    EC_KEY_free(ptrPubKey);

    if (verification == -1) {
        uint64_t error = ERR_get_error();
        fprintf(stderr, "ECDSA_verify error %llu: %s\n", error, ERR_reason_error_string(error));
        return -100;
    }
    else if (verification == 0) {
        fprintf(stderr, "ECDSA_verify: invalid signature\n");
        return 0;
    }
    else {
        #if LOG_VALIDATION_PROCEDURES
        printf("ECDSA_verify: OK\n");
        #endif
        return 1;
    }
}

int64_t find_op_frame(Stack *stack, uint64_t end, Byte op) {
    for (int64_t i = end; i > 0; i--) {
        StackFrame *frame = stack->frames[i];
        if (frame->type == FRAME_TYPE_OP && frame->data[0] == op) {
            return i;
        }
    }
    return -1;
}

uint64_t form_subscript(Stack *inputStack, uint64_t checksigIndex, Byte *subscript, bool useAllScript) {
    int64_t separatorIndex = find_op_frame(inputStack, checksigIndex, OP_CODESEPARATOR);
    if (separatorIndex < 0) {
        return 0;
    }
    uint64_t subscriptLength = 0;
    uint64_t end = useAllScript ? inputStack->height : checksigIndex + 1;
    for (uint64_t i = (uint64_t)separatorIndex+1; i < end && i < inputStack->height; i++) {
        StackFrame *frame = inputStack->frames[i];
        if (frame->type == FRAME_TYPE_OP && frame->data[0] == OP_CODESEPARATOR) {
            continue;
        }
        memcpy(subscript + subscriptLength, frame->opHeader, frame->opHeaderWidth);
        subscriptLength += frame->opHeaderWidth;
        memcpy(subscript + subscriptLength, frame->data, frame->dataWidth);
        subscriptLength += frame->dataWidth;
    }
    return subscriptLength;
}

typedef void HashFunc(void *data, uint32_t length, Byte *result);

StackFrame hash_frame(StackFrame topFrame, HashFunc hashFunc, uint32_t outputWidth) {
    StackFrame newFrame = get_empty_frame();
    hashFunc(topFrame.data, topFrame.dataWidth, newFrame.data);
    newFrame.dataWidth = outputWidth;
    newFrame.type = FRAME_TYPE_DATA;
    return newFrame;
}

void hash_top_frame(Stack *stack, HashFunc hashFunc, uint32_t outputWidth) {
    if (stack->height < 1) {
        fprintf(stderr, "hash_top_frame: insufficient frames\n");
        return;
    }
    StackFrame topFrame = pop(stack);
    StackFrame newFrame = hash_frame(topFrame, hashFunc, outputWidth);
    push(stack, newFrame);
}

bool is_frame_truthy(StackFrame *frame) {
    if (frame->dataWidth == 0) {
        return false;
    }
    for (uint64_t i = 0; i < frame->dataWidth; i++) {
        if (frame->data[i]) {
            return true;
        }
    }
    return false;
}


int64_t next_op(Stack *stack, uint64_t start, Byte op) {
    for (uint64_t i = start+1; i < stack->height; i++) {
        StackFrame *frame = stack->frames[i];
        if (frame->type == FRAME_TYPE_OP && frame->data[0] == op) {
            return i;
        }
    }
    return -1;
}

bool is_branch_op_frame(StackFrame *frame) {
    if (frame->type != FRAME_TYPE_OP) {
        return false;
    }
    Byte op = frame->data[0];
    return op == OP_IF || op == OP_ELSE || op == OP_NOTIF || op == OP_ENDIF;
}

bool execute_verify(Stack *runtimeStack) {
    if (runtimeStack->height == 0) {
        return false;
    }
    StackFrame topFrame = pop(runtimeStack);
    if (!is_frame_truthy(&topFrame)) {
        return false;
    }
    return true;
}

bool execute_checksig(Stack *runtimeStack, Stack *inputStack, uint64_t i, CheckSigMeta meta) {
    if (runtimeStack->height < 2) {
        fprintf(stderr, "OP_CHECKSIG: insufficient frames\n");
        return false;
    }
    StackFrame pubkeyFrame = pop(runtimeStack);
    StackFrame sigFrame = pop(runtimeStack);
    Byte *subscript = CALLOC(1, 100000, "subscript");
    uint64_t subscriptLength = form_subscript(inputStack, i, subscript, true);
    int8_t result = check_signature(pubkeyFrame, sigFrame, meta, subscript, subscriptLength);
    FREE(subscript, "subscript");
    push(runtimeStack, get_boolean_frame(result));
    return true;
}

enum BranchState {
    BRANCH_OUTSIDE,
    BRANCH_EXECUTING,
    BRANCH_NOT_EXECUTING,
};

bool evaluate(Stack *inputStack, CheckSigMeta meta) {
    Stack runtimeStack = get_empty_stack();
    Stack altRuntimeStack = get_empty_stack();

    enum BranchState branchState = BRANCH_OUTSIDE;

    for (uint64_t i = 0; i < inputStack->height; i++) {
        StackFrame *inputFrame = inputStack->frames[i];
        if (branchState == BRANCH_NOT_EXECUTING && !is_branch_op_frame(inputFrame)) {
            #if LOG_SCRIPT_STACKS
            printf("Skipping frame for branching:\n");
            print_frame(inputFrame);
            #endif
            continue;
        }
        if (inputFrame->type == FRAME_TYPE_DATA) {
            #if LOG_SCRIPT_STACKS
            printf("next frame: %u bytes data\n", inputFrame->dataWidth);
            #endif
            push(&runtimeStack, *inputFrame);
        }
        else if (inputFrame->type == FRAME_TYPE_OP) {
            Byte op = inputFrame->data[0];
            #if LOG_SCRIPT_STACKS
            printf("next frame: %s\n", get_op_name(op));
            #endif
            switch (op) {
                case OP_DUP: {
                    if (runtimeStack.height == 0) {
                        fprintf(stderr, "OP_DUP: empty stack\n");
                        goto immediate_fail;
                    }
                    push(&runtimeStack, top(&runtimeStack));
                    break;
                }
                case OP_2DUP: {
                    if (runtimeStack.height < 2) {
                        fprintf(stderr, "OP_2DUP: insufficient frames\n");
                        goto immediate_fail;
                    }
                    StackFrame topFrame = pop(&runtimeStack);
                    StackFrame subtopFrame = pop(&runtimeStack);
                    push(&runtimeStack, subtopFrame);
                    push(&runtimeStack, topFrame);
                    push(&runtimeStack, subtopFrame);
                    push(&runtimeStack, topFrame);
                    break;
                }
                case OP_EQUALVERIFY: {
                    if (runtimeStack.height < 2) {
                        fprintf(stderr, "OP_EQUALVERIFY: insufficient frames\n");
                        goto immediate_fail;
                    }
                    StackFrame topFrame = pop(&runtimeStack);
                    StackFrame subtopFrame = pop(&runtimeStack);
                    if (!are_frames_equal(&topFrame, &subtopFrame)) {
                        fprintf(stderr, "OP_EQUALVERIFY: unequal frames\n");
                        goto immediate_fail;
                    }
                    break;
                }
                case OP_CHECKSIG: {
                    if (!execute_checksig(&runtimeStack, inputStack, i, meta)) {
                        goto immediate_fail;
                    }
                    break;
                }
                case OP_EQUAL: {
                    if (runtimeStack.height < 2) {
                        fprintf(stderr, "OP_EQUAL: insufficient frames\n");
                        goto immediate_fail;
                    }
                    StackFrame frameA = pop(&runtimeStack);
                    StackFrame frameB = pop(&runtimeStack);
                    push(&runtimeStack, get_boolean_frame(are_frames_equal(&frameA, &frameB)));
                    break;
                }
                case OP_NOP: {
                    break;
                }
                case OP_DROP: {
                    pop(&runtimeStack);
                    break;
                }
                case OP_NIP: {
                    StackFrame topFrame = pop(&runtimeStack);
                    pop(&runtimeStack);
                    push(&runtimeStack, topFrame);
                    break;
                }
                case OP_HASH160: {
                    hash_top_frame(&runtimeStack, sharipe, RIPEMD_LENGTH);
                    break;
                }
                case OP_SHA256: {
                    hash_top_frame(&runtimeStack, sha256, SHA256_LENGTH);
                    break;
                }
                case OP_HASH256: {
                    hash_top_frame(&runtimeStack, dsha256, SHA256_LENGTH);
                    break;
                }
                case OP_SHA1: {
                    hash_top_frame(&runtimeStack, sha1, SHA1_LENGTH);
                    break;
                }
                case OP_RIPEMD160: {
                    hash_top_frame(&runtimeStack, ripemd, SHA1_LENGTH);
                    break;
                }
                case OP_CODESEPARATOR: {
                    break;
                }
                case OP_0: {
                    StackFrame newFrame = get_empty_frame();
                    newFrame.dataWidth = 0;
                    push(&runtimeStack, newFrame);
                    break;
                }
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16: {
                    push(&runtimeStack, get_numerical_frame(inputFrame->data[0] - OP_1 + (Byte)1));
                    break;
                }
                case OP_CHECKMULTISIG: {
                    StackFrame publicKeyCountFrame = pop(&runtimeStack);

                    // Load public keys
                    Byte publicKeyCount = publicKeyCountFrame.data[0];
                    StackFrame *publicKeys = CALLOC(
                        (size_t)publicKeyCount, sizeof(StackFrame), "OP_CHECKMULTISIG:publicKeys"
                    );
                    for (int8_t pki = 0; pki < publicKeyCount; pki++) {
                        StackFrame publicKeyFrame = pop(&runtimeStack);
                        memcpy(&publicKeys[pki], &publicKeyFrame, sizeof(publicKeyFrame));
                    }

                    // Load signatures
                    StackFrame signatureCountFrame = pop(&runtimeStack);
                    Byte signatureCount = signatureCountFrame.data[0];
                    StackFrame *signatures = CALLOC(
                        (size_t)signatureCount, sizeof(StackFrame), "OP_CHECKMULTISIG:signatures"
                    );
                    for (int8_t si = 0; si < signatureCount; si++) {
                        StackFrame signatureFrame = pop(&runtimeStack);
                        memcpy(&signatures[si], &signatureFrame, sizeof(signatureFrame));
                    }

                    // Simulate Bitcoin bug
                    pop(&runtimeStack);

                    Byte *subscript = CALLOC(1, 100000, "subscript");
                    uint64_t subscriptLength = form_subscript(inputStack, i, subscript, false);

                    // Check public keys against signatures
                    int8_t pki = 0;
                    int8_t si = 0;
                    bool result = false;
                    while (true) {
                        if (pki >= publicKeyCount || si >= signatureCount) {
                            result = false;
                            break;
                        }
                        bool signatureValid = check_signature(publicKeys[pki], signatures[si], meta, subscript, subscriptLength) == 1;
                        if (signatureValid) {
                            if (si + 1 == signatureCount) {
                                result = true;
                                break;
                            }
                            pki++;
                            si++;
                        }
                        else {
                            pki++;
                        }
                    }
                    FREE(publicKeys, "OP_CHECKMULTISIG:publicKeys");
                    FREE(signatures, "OP_CHECKMULTISIG:signatures");
                    FREE(subscript, "subscript");
                    push(&runtimeStack, get_boolean_frame(result));
                    break;
                }
                case OP_NOP1: {
                    break;
                }
                case OP_NOP2: {
                    // TODO: implement OP_CHECKLOCKTIMEVERIFY
                    break;
                }
                case OP_MIN: {
                    StackFrame frame1 = pop(&runtimeStack);
                    StackFrame frame2 = pop(&runtimeStack);
                    StackFrame *minFrame = &frame1;
                    if (frame1.dataWidth > frame2.dataWidth) {
                        minFrame = &frame2;
                    }
                    else if (frame2.dataWidth > frame1.dataWidth) {
                        minFrame = &frame1;
                    }
                    else {
                        for (int16_t digit = frame1.dataWidth; digit >= 0; digit--) {
                            if (frame1.data[digit] > frame2.data[digit]) {
                                minFrame = &frame2;
                                break;
                            }
                            else if (frame1.data[digit] < frame2.data[digit]) {
                                minFrame = &frame1;
                                break;
                            }
                        }
                    }
                    push(&runtimeStack, *minFrame);
                    break;
                }
                case OP_SIZE: {
                    StackFrame topFrame = top(&runtimeStack);
                    uint32_t width = topFrame.dataWidth;
                    push(&runtimeStack, get_numerical_frame(width));
                    break;
                }
                case OP_IF: {
                    int64_t endifIndex = next_op(inputStack, i, OP_ENDIF);
                    if (endifIndex < 0) {
                        goto immediate_fail;
                    }
                    StackFrame topFrame = pop(&runtimeStack);
                    if (is_frame_truthy(&topFrame)) {
                        branchState = BRANCH_EXECUTING;
                    }
                    else {
                        branchState = BRANCH_NOT_EXECUTING;
                    }
                    break;
                }
                case OP_ELSE: {
                    if (branchState == BRANCH_OUTSIDE) {
                        fprintf(stderr, "Unexpected OP_ELSE\n");
                        goto immediate_fail;
                    }
                    else if (branchState == BRANCH_EXECUTING) {
                        branchState = BRANCH_NOT_EXECUTING;
                    }
                    else {
                        branchState = BRANCH_EXECUTING;
                    }
                    break;
                }
                case OP_ENDIF: {
                    if (branchState == BRANCH_OUTSIDE) {
                        fprintf(stderr, "Unexpected OP_ENDIF\n");
                        goto immediate_fail;
                    }
                    branchState = BRANCH_OUTSIDE;
                    break;
                }
                case OP_RETURN: {
                    fprintf(stderr, "Encountered OP_RETURN\n");
                    goto immediate_fail;
                }
                case OP_ADD: {
                    perform_binary_operator(&runtimeStack, add);
                    break;
                }
                case OP_SUB: {
                    perform_binary_operator(&runtimeStack, minus);
                    break;
                }
                case OP_1SUB: {
                    perform_unary_operator(&runtimeStack, decrement);
                    break;
                }
                case OP_GREATERTHAN: {
                    perform_binary_operator(&runtimeStack, greater_than);
                    break;
                }
                case OP_LESSTHAN: {
                    perform_binary_operator(&runtimeStack, less_than);
                    break;
                }
                case OP_NUMEQUAL: {
                    perform_binary_operator(&runtimeStack, equal);
                    break;
                }
                case OP_VERIFY: {
                    if (!execute_verify(&runtimeStack)) {
                        goto immediate_fail;
                    }
                    break;
                }
                case OP_NEGATE: {
                    perform_unary_operator(&runtimeStack, negate);
                    break;
                }
                case OP_DEPTH: {
                    push(&runtimeStack, get_numerical_frame((Byte)runtimeStack.height));
                    break;
                }
                case OP_SWAP: {
                    StackFrame topFrame = pop(&runtimeStack);
                    StackFrame top2Frame = pop(&runtimeStack);
                    push(&runtimeStack, topFrame);
                    push(&runtimeStack, top2Frame);
                    break;
                }
                case OP_1ADD: {
                    perform_unary_operator(&runtimeStack, increment);
                    break;
                }
                case OP_BOOLOR: {
                    perform_binary_operator(&runtimeStack, boolean_or);
                    break;
                }
                case OP_BOOLAND: {
                    perform_binary_operator(&runtimeStack, boolean_and);
                    break;
                }
                case OP_1NEGATE: {
                    perform_nullary_operator(&runtimeStack, negative_one);
                    break;
                }
                case OP_ABS: {
                    perform_unary_operator(&runtimeStack, absolute_value);
                    break;
                }
                case OP_WITHIN: {
                    StackFrame maxFrame = pop(&runtimeStack);
                    StackFrame minFrame = pop(&runtimeStack);
                    StackFrame targetFrame = pop(&runtimeStack);
                    BIGNUM *max = BN_new();
                    BIGNUM *min = BN_new();
                    BIGNUM *target = BN_new();
                    bytes_to_bignum(maxFrame.data, maxFrame.dataWidth, max);
                    bytes_to_bignum(minFrame.data, minFrame.dataWidth, min);
                    bytes_to_bignum(targetFrame.data, targetFrame.dataWidth, target);
                    bool result = (BN_cmp(min, target) <= 0) && (BN_cmp(target, max) <= 0);
                    push(&runtimeStack, get_boolean_frame(result));
                    BN_free(max);
                    BN_free(min);
                    BN_free(target);
                    break;
                }
                case OP_TOALTSTACK: {
                    StackFrame top = pop(&runtimeStack);
                    push(&altRuntimeStack, top);
                    break;
                }
                case OP_FROMALTSTACK: {
                    StackFrame top = pop(&altRuntimeStack);
                    push(&runtimeStack, top);
                    break;
                }
                case OP_CHECKSIGVERIFY: {
                    if (!execute_checksig(&runtimeStack, inputStack, i, meta)) {
                        goto immediate_fail;
                    }
                    if (!execute_verify(&runtimeStack)) {
                        goto immediate_fail;
                    }
                    break;
                }
                case OP_PICK: {
                    StackFrame topFrame = pop(&runtimeStack);
                    Byte count = topFrame.data[0];
                    int64_t index = runtimeStack.height - 1 - count;
                    if (index < 0) {
                        fprintf(stderr, "OP_PICK: insufficient frames\n");
                        goto immediate_fail;
                    }
                    StackFrame target = *runtimeStack.frames[index];
                    push(&runtimeStack, target);
                    break;
                }
                case OP_ROLL: {
                    StackFrame topFrame = pop(&runtimeStack);
                    Byte count = topFrame.data[0];
                    int64_t index = runtimeStack.height - 1 - count;
                    if (index < 0) {
                        fprintf(stderr, "OP_ROLL: insufficient frames\n");
                        return -1;
                    }
                    StackFrame target = *runtimeStack.frames[index];
                    for (uint64_t x = (uint64_t)index; x < runtimeStack.height - index + 1; x++) {
                        *runtimeStack.frames[x] = *runtimeStack.frames[x+1];
                    }
                    runtimeStack.height--;
                    push(&runtimeStack, target);
                    break;
                }
                case OP_TUCK: {
                    StackFrame topFrame = pop(&runtimeStack);
                    StackFrame top2Frame = pop(&runtimeStack);
                    push(&runtimeStack, topFrame);
                    push(&runtimeStack, top2Frame);
                    push(&runtimeStack, topFrame);
                    break;
                }
                case OP_ROT: {
                    StackFrame frame1 = pop(&runtimeStack);
                    StackFrame frame2 = pop(&runtimeStack);
                    StackFrame frame3 = pop(&runtimeStack);
                    push(&runtimeStack, frame2);
                    push(&runtimeStack, frame1);
                    push(&runtimeStack, frame3);
                    break;
                }
                case OP_NOT: {
                    StackFrame topFrame = top(&runtimeStack);
                    if (topFrame.type == FRAME_TYPE_DATA) {
                        BIGNUM *num = BN_new();
                        bytes_to_bignum(topFrame.data, topFrame.dataWidth, num);
                        bool isZero = BN_get_word(num) == 0;
                        BN_free(num);
                        if (isZero) {
                            push(&runtimeStack, get_boolean_frame(true));
                            break;
                        }
                    }
                    push(&runtimeStack, get_boolean_frame(false));
                    break;
                }
                default: {
                    fprintf(stderr, "\nUnimplemented op %#02x [%s]\n", op, get_op_name(op));
                    goto immediate_fail;
                }
            }
        }
        else {
            fprintf(stderr, "Unknown frame type %u", inputFrame->type);
            goto immediate_fail;
        }
        print_stack_with_label(&runtimeStack, "Runtime");
    }

    // Calculate final output
    bool result;
    if (runtimeStack.height == 0) {
        printf("No frames remain when input are exhausted\n");
        result = false;
    }
    else {
        StackFrame lastFrame = top(&runtimeStack);
        result = !is_byte_array_empty(lastFrame.data, lastFrame.dataWidth);
    }
    free_stack_frames(&runtimeStack);
    return result;

    immediate_fail:
    free_stack_frames(&runtimeStack);
    return false;
}

bool run_program(Byte *program, uint64_t programLength, CheckSigMeta meta) {
    Stack inputStack = get_empty_stack();
    load_program(&inputStack, program, programLength);
    print_stack_with_label(&inputStack, "Input");
    bool result = evaluate(&inputStack, meta);
    free_stack_frames(&inputStack);
    return result;
}
