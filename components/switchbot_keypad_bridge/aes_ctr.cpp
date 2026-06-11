#include "aes_ctr.h"

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {
const char *const TAG = "switchbot_keypad_bridge.crypto";
}  // namespace

bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length) {
  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  size_t out_len = 0;
  size_t finish_len = 0;

  psa_status_t status = psa_cipher_encrypt_setup(&op, key, PSA_ALG_CTR);
  if (status == PSA_SUCCESS) {
    status = psa_cipher_set_iv(&op, iv, 16);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_update(&op, input, length, output, length, &out_len);
  }
  if (status == PSA_SUCCESS) {
    status = psa_cipher_finish(&op, output + out_len, length - out_len, &finish_len);
  }

  if (status != PSA_SUCCESS) {
    psa_cipher_abort(&op);
    ESP_LOGE(TAG, "AES-CTR operation failed (%d)", static_cast<int>(status));
    return false;
  }
  return true;
}

bool aes_ctr_xcrypt_raw_key(const uint8_t key[16], const uint8_t iv[16],
                            const uint8_t *input, uint8_t *output, size_t length) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attrs, key, 16, &key_id);
  psa_reset_key_attributes(&attrs);
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }

  const bool ok = aes_ctr_xcrypt(key_id, iv, input, output, length);
  psa_destroy_key(key_id);
  return ok;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
