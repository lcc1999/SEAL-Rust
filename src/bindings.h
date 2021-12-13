#include "seal/seal.h"
#include <string>
using namespace seal;

namespace bindings
{
    typedef Serializable<PublicKey> SerializablePublicKey;
    typedef Serializable<RelinKeys> SerializableRelinKeys;
    typedef Serializable<Ciphertext> SerializableCiphertext;
    //setup
    extern "C" EncryptionParameters* new_encryption_parameters(int scheme);
    extern "C" void EncryptionParameters_set_poly_modulus_degree(const EncryptionParameters* ep, size_t degree);
    extern "C" void EncryptionParameters_set_coeff_modulus_Create(const EncryptionParameters* ep, size_t poly_modulus_degree, const std::vector<int> &bit_sizes);
    extern "C" void EncryptionParameters_set_coeff_modulus_BFVDefault(const EncryptionParameters* ep, size_t poly_modulus_degree);
    extern "C" void EncryptionParameters_set_plain_modulus(const EncryptionParameters* ep, size_t plain_modulus);
    extern "C" void EncryptionParameters_set_plain_modulus_Batching(const EncryptionParameters* ep, size_t poly_modulus_degree, int bit_size);
    extern "C" SEALContext* new_SEALContext(const EncryptionParameters* ep);
    
    //keygen
    extern "C" KeyGenerator* new_KeyGenerator(const SEALContext* ctx);
    extern "C" SecretKey* KeyGenerator_secret_key(const KeyGenerator* keygen);
    extern "C" SerializablePublicKey* KeyGenerator_create_public_key(const KeyGenerator* keygen);
    extern "C" SerializableRelinKeys* KeyGenerator_create_relin_keys(const KeyGenerator* keygen);
    extern "C" PublicKey* Serializable_to_PublicKey(const SEALContext* ctx, const SerializablePublicKey* spk);
    extern "C" RelinKeys* Serializable_to_RelinKeys(const SEALContext* ctx, SerializableRelinKeys* srlk);
    
    //encode and decode
    //no simd
    extern "C" std::string data_to_string(uint64_t data);
    extern "C" Plaintext* new_Plaintext(const std::string data);
    extern "C" std::string Plaintext_to_string(const Plaintext* plaintext);
    //use simd
    extern "C" BatchEncoder* new_BatchEncoder(const SEALContext* ctx);
    extern "C" size_t slot_count(const BatchEncoder* be);
    extern "C" Plaintext* encode(const BatchEncoder* be, const std::vector<uint64_t> &vec);
    extern "C" std::vector<uint64_t> decode(const BatchEncoder* be, const Plaintext* plain);
    //ckks
    CKKSEncoder* new_CKKSEncoder(const SEALContext* ctx);
    size_t CKKSEncoder_slot_count(const CKKSEncoder* ce);
    Plaintext* CKKSEncoder_encode_vec(const CKKSEncoder* ce, double scale, const std::vector<double> &vec);
    Plaintext* CKKSEncoder_encode(const CKKSEncoder* ce, double scale, double value);
    std::vector<double> CKKSEncoder_decode(const CKKSEncoder* ce, const Plaintext* plain);
    
    
    //encryptor and decryptor
    extern "C" Decryptor* new_Decryptor(const SEALContext* ctx, const SecretKey* sk);
    extern "C" Ciphertext* Serializable_to_Ciphertext(const SEALContext* ctx, const SerializableCiphertext* cipher);
    extern "C" Plaintext* decrypt(const Decryptor* decryptor, const Ciphertext* ciphertext);
    extern "C" Encryptor* new_Encryptor_pk(const SEALContext* ctx, const PublicKey* pk);
    extern "C" SerializableCiphertext* encrypt(const Encryptor* encryptor, const Plaintext* plaintext);
    extern "C" Encryptor* new_Encryptor_sk(const SEALContext* ctx, const SecretKey* sk);
    extern "C" SerializableCiphertext* encrypt_symmetric(const Encryptor* encryptor, const Plaintext* plaintext);

    //evaluator
    extern "C" Evaluator* new_Evaluator(const SEALContext* ctx);
    extern "C" Ciphertext* negate(const Evaluator* evaluator, const Ciphertext* encrypted);
    extern "C" Ciphertext* add(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" Ciphertext* sub(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" Ciphertext* multiply(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" Ciphertext* square(const Evaluator* evaluator, const Ciphertext* encrypted);
    extern "C" Ciphertext* relinearize(const Evaluator* evaluator, const Ciphertext* encrypted, const RelinKeys* rlk);
    extern "C" Ciphertext* rescale_to_next(const Evaluator* evaluator, const Ciphertext* encrypted);
    extern "C" Ciphertext* exponentiate(const Evaluator* evaluator, const Ciphertext* encrypted, uint64_t exponent, const RelinKeys* rlk);
    extern "C" Ciphertext* add_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain);
    extern "C" Ciphertext* sub_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain);
    extern "C" Ciphertext* multiply_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain);


    extern "C" void negate_inplace(const Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void add_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" void sub_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" void multiply_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2);
    extern "C" void square_inplace(const Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void relinearize_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const RelinKeys* rlk);
    extern "C" void rescale_to_next_inplace(const Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void exponentiate_inplace(const Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, const RelinKeys* rlk);
    extern "C" void add_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain);
    extern "C" void sub_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain);
    extern "C" void multiply_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain);
    
    
    extern "C" void setscale(const Ciphertext* encrypted, double scale);
    extern "C" parms_id_type* parms_id(const Ciphertext* encrypted);
    extern "C" Ciphertext* mod_switch_to(const Evaluator* evaluator, const Ciphertext* encrypted, const parms_id_type* id);
    extern "C" void mod_switch_to_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const parms_id_type* id);
}
