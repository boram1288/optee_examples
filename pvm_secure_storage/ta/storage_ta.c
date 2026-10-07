// SPDX-License-Identifier: MIT
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <storage_ta.h>
#include <string.h>
#include <stdint.h>

struct entry { uint8_t digest[32]; uint64_t version; uint32_t slot, reserved; };
struct state { uint32_t magic, volume; uint64_t generation; uint8_t key[32]; struct entry blocks[SS_BLOCKS]; };
struct record { uint8_t data[SS_BLOCK_SIZE]; uint32_t magic, volume, block, slot; uint64_t version; uint8_t nonce[12], tag[16]; uint8_t padding[4096-52]; };
_Static_assert(sizeof(struct record) == SS_RECORD_SIZE, "record size");
_Static_assert(sizeof(struct entry) == 48, "entry size");
static struct state current, committed;
static bool initialized, dirty;
static TEE_ObjectHandle key = TEE_HANDLE_NULL;
static const char object_id[] = "pvm-storage-anchor-v1";

static TEE_Result save_state(void)
{
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_Result r;
    /* One atomic replacement of the complete bounded trusted table. */
    r = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_REE, object_id, sizeof(object_id),
        TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE, TEE_HANDLE_NULL,
        &current, sizeof(current), &object);
    if (!r) TEE_CloseObject(object);
    return r;
}
static TEE_Result init(uint32_t create, uint32_t volume)
{
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    size_t count = 0;
    TEE_Result r;
    TEE_Attribute attribute;
    if (initialized || volume != SS_VOLUME_ID || create > 1) return TEE_ERROR_BAD_STATE;
    r = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object_id, sizeof(object_id),
                                TEE_DATA_FLAG_ACCESS_READ, &object);
    if (r == TEE_ERROR_ITEM_NOT_FOUND && create) {
        memset(&current, 0, sizeof(current));
        current.magic = SS_VOLUME_ID; current.volume = volume;
        TEE_GenerateRandom(current.key, sizeof(current.key));
        r = save_state();
    } else if (!r) {
        r = TEE_ReadObjectData(object, &current, sizeof(current), &count);
        TEE_CloseObject(object);
        if (!r && (count != sizeof(current) || current.magic != SS_VOLUME_ID || current.volume != volume))
            r = TEE_ERROR_CORRUPT_OBJECT;
        /* Explicit provisioning never silently replaces an existing anchor. */
        if (!r && create) r = TEE_ERROR_ACCESS_CONFLICT;
    }
    if (r) return r;
    for (unsigned i = 0; i < SS_BLOCKS; i++)
        if (current.blocks[i].slot > 1 || current.blocks[i].reserved) return TEE_ERROR_CORRUPT_OBJECT;
    r = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key);
    if (r) return r;
    TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE, current.key, sizeof(current.key));
    r = TEE_PopulateTransientObject(key, &attribute, 1);
    if (r) return r;
    committed = current; initialized = true; dirty = false;
    return TEE_SUCCESS;
}
static TEE_Result digest(const void *data, size_t size, uint8_t out[32])
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    size_t len = 32;
    TEE_Result r = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (!r) { r = TEE_DigestDoFinal(op, data, size, out, &len); TEE_FreeOperation(op); }
    return r;
}
static TEE_Result crypt(unsigned block, bool encrypt, TEE_Param p[4])
{
    struct record *rec = TEE_Malloc(sizeof(*rec), 0);
    uint8_t *plain = TEE_Malloc(SS_BLOCK_SIZE, 0);
    uint8_t hash[32];
    struct entry *entry = &current.blocks[block];
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    size_t len = SS_BLOCK_SIZE, taglen = 16;
    TEE_Result r = TEE_ERROR_OUT_OF_MEMORY;
    if (!rec || !plain) goto out;
    if (encrypt) {
        if (entry->version == UINT64_MAX) { r = TEE_ERROR_OVERFLOW; goto out; }
        memcpy(plain, p[1].memref.buffer, SS_BLOCK_SIZE);
        memset(rec, 0, sizeof(*rec));
        rec->magic = SS_VOLUME_ID; rec->volume = current.volume; rec->block = block;
        rec->slot = 1 - committed.blocks[block].slot;
        rec->version = entry->version + 1;
        TEE_GenerateRandom(rec->nonce, sizeof(rec->nonce));
    } else {
        memcpy(rec, p[1].memref.buffer, sizeof(*rec));
        r = digest(rec, sizeof(*rec), hash);
        if (r) goto out;
        if (!entry->version || TEE_MemCompare(hash, entry->digest, 32) ||
            rec->magic != SS_VOLUME_ID || rec->volume != current.volume ||
            rec->block != block || rec->version != entry->version || rec->slot != entry->slot) {
            r = TEE_ERROR_SECURITY; goto out;
        }
    }
    r = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, encrypt ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT, 256);
    if (r) goto out;
    r = TEE_SetOperationKey(op, key);
    if (r) goto out;
    r = TEE_AEInit(op, rec->nonce, 12, 128, 24, SS_BLOCK_SIZE);
    if (r) goto out;
    TEE_AEUpdateAAD(op, &rec->magic, 24); /* magic, volume, block, slot, version */
    if (encrypt) {
        r = TEE_AEEncryptFinal(op, plain, SS_BLOCK_SIZE, rec->data, &len, rec->tag, &taglen);
        if (r) goto out;
        r = digest(rec, sizeof(*rec), hash);
        if (r) goto out;
        memcpy(p[2].memref.buffer, rec, sizeof(*rec));
        memcpy(entry->digest, hash, 32); entry->version = rec->version; entry->slot = rec->slot;
        dirty = true;
    } else {
        r = TEE_AEDecryptFinal(op, rec->data, SS_BLOCK_SIZE, plain, &len, rec->tag, 16);
        if (!r) memcpy(p[2].memref.buffer, plain, SS_BLOCK_SIZE);
    }
out:
    if (op) TEE_FreeOperation(op);
    if (plain) { TEE_MemFill(plain, 0, SS_BLOCK_SIZE); TEE_Free(plain); }
    if (rec) { TEE_MemFill(rec, 0, sizeof(*rec)); TEE_Free(rec); }
    return r;
}
TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void)
{
    if (key) TEE_FreeTransientObject(key);
    TEE_MemFill(&current, 0, sizeof(current)); TEE_MemFill(&committed, 0, sizeof(committed));
    initialized = dirty = false; key = TEE_HANDLE_NULL;
}
TEE_Result TA_OpenSessionEntryPoint(uint32_t types, TEE_Param p[4], void **ctx)
{
    TEE_UUID guard = STORAGE_GUARD_UUID;
    TEE_TASessionHandle session = TEE_HANDLE_NULL;
    TEE_Identity client;
    uint32_t origin;
    TEE_Result r;
    (void)p; *ctx = NULL;
    if (types != TEE_PARAM_TYPES(0,0,0,0)) return TEE_ERROR_BAD_PARAMETERS;
    r = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT, "gpd.client.identity", &client);
    if (r || client.login != TEE_LOGIN_REE_KERNEL) return TEE_ERROR_ACCESS_DENIED;
    r = TEE_OpenTASession(&guard, TEE_TIMEOUT_INFINITE, TEE_PARAM_TYPES(0,0,0,0), NULL, &session, &origin);
    if (r) return r;
    r = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE, 0, TEE_PARAM_TYPES(0,0,0,0), NULL, &origin);
    TEE_CloseTASession(session);
    return r;
}
void TA_CloseSessionEntryPoint(void *ctx) { (void)ctx; }
TEE_Result TA_InvokeCommandEntryPoint(void *ctx, uint32_t cmd, uint32_t types, TEE_Param p[4])
{
    unsigned block = p[0].value.a;
    (void)ctx;
    if (cmd == SS_INIT && types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,0,0,0))
        return init(block, p[0].value.b);
    if (!initialized) return TEE_ERROR_BAD_STATE;
    if (cmd == SS_COMMIT && types == TEE_PARAM_TYPES(0,0,0,0)) {
        TEE_Result r;
        if (!dirty) return TEE_SUCCESS;
        if (current.generation == UINT64_MAX) return TEE_ERROR_OVERFLOW;
        current.generation++;
        r = save_state();
        if (!r) { committed = current; dirty = false; }
        return r;
    }
    if (block >= SS_BLOCKS) return TEE_ERROR_BAD_PARAMETERS;
    if (cmd == SS_QUERY && types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,TEE_PARAM_TYPE_VALUE_OUTPUT,0,0)) {
        p[1].value.a = current.blocks[block].version != 0;
        p[1].value.b = current.blocks[block].slot;
        return TEE_SUCCESS;
    }
    if ((cmd == SS_ENCRYPT || cmd == SS_DECRYPT) &&
        types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,TEE_PARAM_TYPE_MEMREF_INPUT,TEE_PARAM_TYPE_MEMREF_OUTPUT,0) &&
        p[1].memref.size == (cmd == SS_ENCRYPT ? SS_BLOCK_SIZE : SS_RECORD_SIZE) &&
        p[2].memref.size == (cmd == SS_ENCRYPT ? SS_RECORD_SIZE : SS_BLOCK_SIZE))
        return crypt(block, cmd == SS_ENCRYPT, p);
    return TEE_ERROR_BAD_PARAMETERS;
}
