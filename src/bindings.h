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
    extern "C" void EncryptionParameters_set_poly_modulus_degree(EncryptionParameters* ep, size_t degree);
    extern "C" void EncryptionParameters_set_coeff_modulus_Create(EncryptionParameters* ep, size_t poly_modulus_degree, std::vector<int> &bit_sizes);
    extern "C" void EncryptionParameters_set_coeff_modulus_BFVDefault(EncryptionParameters* ep, size_t poly_modulus_degree);
    extern "C" void EncryptionParameters_set_plain_modulus(EncryptionParameters* ep, size_t plain_modulus);
    extern "C" void EncryptionParameters_set_plain_modulus_Batching(EncryptionParameters* ep, size_t poly_modulus_degree, int bit_size);
    extern "C" SEALContext* new_SEALContext(EncryptionParameters* ep);
    
    //keygen
    extern "C" KeyGenerator* new_KeyGenerator(SEALContext* ctx);
    extern "C" SecretKey* KeyGenerator_secret_key(KeyGenerator* keygen);
    extern "C" SerializablePublicKey* KeyGenerator_create_public_key(KeyGenerator* keygen);
    extern "C" SerializableRelinKeys* KeyGenerator_create_relin_keys(KeyGenerator* keygen);
    extern "C" PublicKey* Serializable_to_PublicKey(SEALContext* ctx, SerializablePublicKey* spk);
    extern "C" RelinKeys* Serializable_to_RelinKeys(SEALContext* ctx, SerializableRelinKeys* srlk);
    
    //encode and decode
    //no simd
    extern "C" std::string data_to_string(uint64_t data);
    extern "C" Plaintext* new_Plaintext(std::string data);
    extern "C" std::string Plaintext_to_string(Plaintext* plaintext);
    //use simd
    extern "C" BatchEncoder* new_BatchEncoder(SEALContext* ctx);
    extern "C" size_t slot_count(BatchEncoder* be);
    extern "C" Plaintext* encode(BatchEncoder* be, std::vector<uint64_t> &vec);
    extern "C" std::vector<uint64_t> decode(BatchEncoder* be, Plaintext* plain);
    //ckks
    CKKSEncoder* new_CKKSEncoder(SEALContext* ctx);
    size_t CKKSEncoder_slot_count(CKKSEncoder* ce);
    Plaintext* CKKSEncoder_encode_vec(CKKSEncoder* ce, double scale, std::vector<double> &vec);
    Plaintext* CKKSEncoder_encode(CKKSEncoder* ce, double scale, double value);
    std::vector<double> CKKSEncoder_decode(CKKSEncoder* ce, Plaintext* plain);
    
    
    //encryptor and decryptor
    extern "C" Decryptor* new_Decryptor(SEALContext* ctx, SecretKey* sk);
    extern "C" Ciphertext* Serializable_to_Ciphertext(SEALContext* ctx, SerializableCiphertext* cipher);
    extern "C" Plaintext* decrypt(Decryptor* decryptor, Ciphertext* ciphertext);
    extern "C" Encryptor* new_Encryptor_pk(SEALContext* ctx, PublicKey* pk);
    extern "C" SerializableCiphertext* encrypt(Encryptor* encryptor, Plaintext* plaintext);
    extern "C" Encryptor* new_Encryptor_sk(SEALContext* ctx, SecretKey* sk);
    extern "C" SerializableCiphertext* encrypt_symmetric(Encryptor* encryptor, Plaintext* plaintext);

    //evaluator
    extern "C" Evaluator* new_Evaluator(SEALContext* ctx);
    extern "C" Ciphertext* negate(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" Ciphertext* add(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" Ciphertext* sub(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" Ciphertext* multiply(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" Ciphertext* square(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" Ciphertext* relinearize(Evaluator* evaluator, Ciphertext* encrypted, RelinKeys* rlk);
    extern "C" Ciphertext* rescale_to_next(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" Ciphertext* exponentiate(Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, RelinKeys* rlk);
    extern "C" Ciphertext* add_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);
    extern "C" Ciphertext* sub_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);
    extern "C" Ciphertext* multiply_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);


    extern "C" void negate_inplace(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void add_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" void sub_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" void multiply_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2);
    extern "C" void square_inplace(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void relinearize_inplace(Evaluator* evaluator, Ciphertext* encrypted, RelinKeys* rlk);
    extern "C" void rescale_to_next_inplace(Evaluator* evaluator, Ciphertext* encrypted);
    extern "C" void exponentiate_inplace(Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, RelinKeys* rlk);
    extern "C" void add_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);
    extern "C" void sub_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);
    extern "C" void multiply_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain);
    
    
    extern "C" void setscale(Ciphertext* encrypted, double scale);
    extern "C" parms_id_type* parms_id(Ciphertext* encrypted);
    extern "C" Ciphertext* mod_switch_to(Evaluator* evaluator, Ciphertext* encrypted, parms_id_type* id);
    extern "C" void mod_switch_to_inplace(Evaluator* evaluator, Ciphertext* encrypted, parms_id_type* id);
}
