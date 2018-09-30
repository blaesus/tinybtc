#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include "script.h"
#include "datatypes.h"
#include "parameters.h"
#include "hash.h"
#include "config.h"
#include "utils/memory.h"
#include "utils/data.h"

#define UNKNOWN_OPCODE "UNKNOWN_OPCODE"

#define MAX_STACK_FRAME_WIDTH 256

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
    uint16_t dataWidth;
    enum FrameType type;
};

typedef struct StackFrame StackFrame;

struct Stack {
    struct StackFrame *frames[MAX_STACK_HEIGHT];
    uint64_t height;
};

bool is_anonymous_push_data_op(Byte op) {
    return (op > OP_0) && (op < OP_PUSHDATA1);
}

bool is_push_data_op(Byte op) {
    return is_anonymous_push_data_op(op)|| op == OP_PUSHDATA1 || op == OP_PUSHDATA2 || op == OP_PUSHDATA4;
}

void hash_tx_with_hashtype(TxPayload *tx, int32_t hashType, Byte *hash) {
    Byte *buffer = CALLOC(1, MESSAGE_BUFFER_LENGTH, "hash_tx_with_hashtype:buffer");
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

StackFrame get_boolean_frame(bool value) {
    StackFrame resultFrame = {
        .type = FRAME_TYPE_DATA,
        .dataWidth = 1,
        .data = { (Byte)value }
    };
    return resultFrame;
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
            uint16_t dataWidth = 0;
            uint16_t dataStartOffset = 0;
            if (is_anonymous_push_data_op(datum)) {
                dataWidth = datum;
                dataStartOffset = 1;
            }
            else if (datum == OP_PUSHDATA1) {
                dataWidth = program[i+1];
                dataStartOffset = 2;
            }
            else {
                fprintf(stderr, "Unimplemented push data op %u\n", datum);
            }
            newFrame.dataWidth = dataWidth;
            memcpy(newFrame.data, program + (i+dataStartOffset), dataWidth);
            i += dataWidth + dataStartOffset - 1;
        }
        else {
            newFrame.type = FRAME_TYPE_OP;
            newFrame.dataWidth = 1;
            memcpy(newFrame.data, &datum, 1);
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

TxPayload *make_tx_copy(CheckSigMeta meta) {
    Byte *subscript = CALLOC(1, 100000, "make_tx_copy:subscript");
    Byte subscriptIndex = 0;
    memcpy(
        subscript,
        meta.sourceOutput->public_key_script,
        meta.sourceOutput->public_key_script_length
    );
    subscriptIndex += meta.sourceOutput->public_key_script_length;
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
        subscriptIndex
    );
    txCopy->txInputs[meta.txInputIndex].signature_script_length = subscriptIndex;
    FREE(subscript, "make_tx_copy:subscript");
    return txCopy;
}

#define MAX_SIGNATURE_DATA 128

struct EllipticPoint {
    int8_t pointType;
    int8_t length;
    Byte data[MAX_SIGNATURE_DATA];
};

typedef struct EllipticPoint EllipticPoint;

struct DerSignature {
    int8_t sequence;
    int8_t length;
    EllipticPoint r;
    EllipticPoint s;
};

typedef struct DerSignature DerSignature;

uint64_t parse_elliptic_point(Byte *ptrBuffer, EllipticPoint *point) {
    Byte *p = ptrBuffer;
    p += PARSE_INTO(p, &point->pointType);
    p += PARSE_INTO(p, &point->length);
    p += PARSE_INTO_OF_LENGTH(p, &point->data, point->length);
    return p - ptrBuffer;
}

uint64_t serialize_elliptic_point(EllipticPoint *point, Byte *ptrBuffer) {
    Byte *p = ptrBuffer;
    p += SERIALIZE_TO(point->pointType, p);
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

int8_t fix_point(EllipticPoint *point) {
    // The initial zeros may kill internal OpenSSL checks
    if (point->data[0] == 0 && point->data[1] == 0) {
        memcpy(point->data, point->data+2, point->length-2);
        point->length -= 2;
        return -2;
    }
    // Set correct initial zero
    if (byte_has_initial_zero(point->data[0])) {
        memcpy(point->data+1, point->data, point->length);
        point->data[0] = 0;
        point->length += 1;
        return 1;
    }
    if (point->data[0] == 0 && !byte_has_initial_zero(point->data[1])) {
        memcpy(point->data, point->data+1, point->length-1);
        point->length -= 1;
        return -1;
    }
    return 0;
}

void fix_signature(DerSignature *signature) {
    signature->length += fix_point(&signature->r);
    signature->length += fix_point(&signature->s);
}

void print_elliptic_point(EllipticPoint *point) {
    printf("point type %i, length %i, data:", point->pointType, point->length);
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
    #if LOG_VALIDATION_PROCEDURES
    print_der(signature);
    #endif
    fix_signature(signature);
    #if LOG_VALIDATION_PROCEDURES
    print_der(signature);
    #endif
    sigFrame->dataWidth = (uint16_t)(serialize_der(signature, sigFrame->data) + 1);
    FREE(signature, "fix_signature_frame:signature");
}

int8_t polish_tx_copy(TxPayload *txCopy, uint32_t hashtype) {
    switch (hashtype) {
        case SIGHASH_ALL_ALTERNATIVE:
        case SIGHASH_ALL: {
            return 0;
        }
        default: {
            fprintf(stderr, "Unrecognized hashtype %u\n", hashtype);
            return -1;
        }
    }
}

bool evaluate(Stack *inputStack, CheckSigMeta meta) {
    Stack runtimeStack = get_empty_stack();

    for (uint64_t i = 0; i < inputStack->height; i++) {
        StackFrame *inputFrame = inputStack->frames[i];
        if (inputFrame->type == FRAME_TYPE_DATA) {
            push(&runtimeStack, *inputFrame);
        }
        else if (inputFrame->type == FRAME_TYPE_OP) {
            Byte op = inputFrame->data[0];
            switch (op) {
                case OP_DUP: {
                    if (runtimeStack.height == 0) {
                        fprintf(stderr, "OP_DUP: empty stack\n");
                        goto immediate_fail;
                    }
                    push(&runtimeStack, top(&runtimeStack));
                    break;
                }
                case OP_HASH160: {
                    if (runtimeStack.height == 0) {
                        fprintf(stderr, "OP_HASH160: empty stack\n");
                        goto immediate_fail;
                    }
                    StackFrame currentTop = pop(&runtimeStack);
                    StackFrame newFrame = {
                        .type = FRAME_TYPE_DATA,
                        .dataWidth = RIPEMD_LENGTH,
                        .data = {0}
                    };
                    sharipe(currentTop.data, currentTop.dataWidth, newFrame.data);
                    push(&runtimeStack, newFrame);
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
                    // Deduce public key
                    if (runtimeStack.height < 2) {
                        fprintf(stderr, "OP_CHECKSIG: insufficient frames\n");
                        goto immediate_fail;
                    }
                    StackFrame pubkeyFrame = pop(&runtimeStack);
                    if (pubkeyFrame.dataWidth < 65) {
                        fprintf(stderr, "Unimplemented: compressed public key\n");
                        goto immediate_fail;
                    }
                    EC_KEY *ptrPubKey = EC_KEY_new_by_curve_name(NID_secp256k1);
                    int32_t status = EC_KEY_oct2key(
                        ptrPubKey,
                        pubkeyFrame.data,
                        pubkeyFrame.dataWidth,
                        NULL
                    );
                    if (status != 1) {
                        fprintf(stderr, "Failed to decode elliptic public key");
                        goto immediate_fail;
                    }

                    StackFrame sigFrame = pop(&runtimeStack);
                    uint32_t hashtype = sigFrame.data[sigFrame.dataWidth-1];
                    fix_signature_frame(&sigFrame);
                    SHA256_HASH hashTx = {0};
                    TxPayload *txCopy = make_tx_copy(meta);
                    if (polish_tx_copy(txCopy, hashtype)) {
                        goto immediate_fail;
                    };
                    hash_tx_with_hashtype(txCopy, hashtype, hashTx);
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

                    if (verification == -1) {
                        uint64_t error = ERR_get_error();
                        fprintf(stderr, "ECDSA_verify error %llu: %s\n", error, ERR_reason_error_string(error));
                    }
                    else if (verification == 0) {
                        fprintf(stderr, "ECDSA_verify: invalid signature\n");
                    }
                    else {
                        #if LOG_VALIDATION_PROCEDURES
                        printf("ECDSA_verify: OK\n");
                        #endif
                    }

                    push(&runtimeStack, get_boolean_frame(verification == 1));
                    EC_KEY_free(ptrPubKey);
                    break;
                }
                case OP_0: {
                    StackFrame newFrame = {
                        .type = FRAME_TYPE_DATA,
                        .dataWidth = MAX_STACK_FRAME_WIDTH,
                        .data = {0},
                    };
                    push(&runtimeStack, newFrame);
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
