#include "bindings.h"
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include "seal/seal.h"

using namespace seal;
using namespace seal::util;

namespace bindings
{
    //setup
    EncryptionParameters* new_encryption_parameters(int scheme) {
        return new EncryptionParameters((scheme_type)scheme);
    }
    void EncryptionParameters_set_poly_modulus_degree(EncryptionParameters* ep, int degree) {
        ep->set_poly_modulus_degree(degree);
    }
    void EncryptionParameters_set_plain_modulus(EncryptionParameters* ep, int modulus) {
        ep->set_plain_modulus(modulus);
    }
    void EncryptionParameters_set_coeff_modulus_Create(EncryptionParameters* ep, size_t poly_modulus_degree, std::vector<int> &bit_sizes) {
        std::vector<int> sizes;
          std::copy(bit_sizes.begin(), bit_sizes.end(), std::back_inserter(sizes));
        ep->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,sizes));
    }
    void EncryptionParameters_set_coeff_modulus_BFVDefault(EncryptionParameters* ep, size_t poly_modulus_degree) {
        ep->set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    }
    void EncryptionParameters_set_plain_modulus(EncryptionParameters* ep, size_t plain_modulus) {
        ep->set_plain_modulus(plain_modulus);
    }
    void EncryptionParameters_set_plain_modulus_Batching(EncryptionParameters* ep, size_t poly_modulus_degree, int bit_size) {
        ep->set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, bit_size));
    }    
    SEALContext* new_SEALContext(EncryptionParameters* ep) {
        return new SEALContext(*ep);
    }
    //keygen
    KeyGenerator* new_KeyGenerator(SEALContext* ctx) {
        return new KeyGenerator(*ctx);
    }
    SecretKey* KeyGenerator_secret_key(KeyGenerator* keygen) {
        return new SecretKey(keygen->secret_key());
    }
    SerializablePublicKey* KeyGenerator_create_public_key(KeyGenerator* keygen) {
        return new SerializablePublicKey(keygen->create_public_key());
    }
    SerializableRelinKeys* KeyGenerator_create_relin_keys(KeyGenerator* keygen) {
        return new SerializableRelinKeys(keygen->create_relin_keys());
    }
    PublicKey* Serializable_to_PublicKey(SEALContext* ctx, SerializablePublicKey* spk) {
        std::stringstream data_stream;
        spk->save(data_stream);
        PublicKey* pk = new PublicKey();
        pk->load(*ctx, data_stream);
        return pk;
    }
    RelinKeys* Serializable_to_RelinKeys(SEALContext* ctx, SerializableRelinKeys* srlk) {
        std::stringstream data_stream;
        srlk->save(data_stream);
        RelinKeys* rlk = new RelinKeys();
        rlk->load(*ctx, data_stream);
        return rlk;
    }
    
    
    //encode and decode
    //no simd
    std::string data_to_string(uint64_t data) {
        return std::to_string(data);
    }
    Plaintext* new_Plaintext(std::string data) {
        return new Plaintext(data);
    }
    std::string Plaintext_to_string(Plaintext* plaintext) {
        return plaintext->to_string();
    }
    //use simd
    BatchEncoder* new_BatchEncoder(SEALContext* ctx) {
        return new BatchEncoder(*ctx);
    }
    size_t slot_count(BatchEncoder* be) {
        return be->slot_count();
    }
    Plaintext* encode(BatchEncoder* be, std::vector<uint64_t> &vec) {
        Plaintext* plaintext = new Plaintext();
        be->encode(vec, *plaintext);
        return plaintext;
    }
    std::vector<uint64_t> decode(BatchEncoder* be, Plaintext* plain) {
        std::vector<uint64_t> vec;
        be->decode(*plain, vec);
        return vec;
    }
    //ckks
    CKKSEncoder* new_CKKSEncoder(SEALContext* ctx) {
        return new CKKSEncoder(*ctx);
    }
    size_t CKKSEncoder_slot_count(CKKSEncoder* ce) {
        return ce->slot_count();
    }
    Plaintext* CKKSEncoder_encode_vec(CKKSEncoder* ce, double scale, std::vector<double> &vec) {
        Plaintext* plaintext = new Plaintext();
        ce->encode(vec, scale, *plaintext);
        return plaintext;
    }
    Plaintext* CKKSEncoder_encode(CKKSEncoder* ce, double scale, double value) {
        Plaintext* plaintext = new Plaintext();
        ce->encode(value, scale, *plaintext);
        return plaintext;
    }
    std::vector<double> CKKSEncoder_decode(CKKSEncoder* ce, Plaintext* plain) {
        std::vector<double> vec;
        ce->decode(*plain, vec);
        return vec;
    }
    
    
    //encryptor and decryptor
    Decryptor* new_Decryptor(SEALContext* ctx, SecretKey* sk) {
        return new Decryptor(*ctx,*sk);
    }
    Ciphertext* Serializable_to_Ciphertext(SEALContext* ctx, SerializableCiphertext* cipher) {
        std::stringstream data_stream;
        cipher->save(data_stream);
        Ciphertext* ciphertext = new Ciphertext();
        ciphertext->load(*ctx, data_stream);
        return ciphertext;
    }
    Plaintext* decrypt(Decryptor* decryptor, Ciphertext* ciphertext) {
        Plaintext* plaintext = new Plaintext();
        decryptor->decrypt(*ciphertext, *plaintext);
        return plaintext;
    }
    Encryptor* new_Encryptor_pk(SEALContext* ctx, PublicKey* pk) {
        return new Encryptor(*ctx,*pk);
    }
    SerializableCiphertext* encrypt(Encryptor* encryptor, Plaintext* plaintext) {
        return new SerializableCiphertext(encryptor->encrypt(*plaintext));
    }
    Encryptor* new_Encryptor_sk(SEALContext* ctx, SecretKey* sk) {
        return new Encryptor(*ctx,*sk);
    }
    SerializableCiphertext* encrypt_symmetric(Encryptor* encryptor, Plaintext* plaintext) {
        return new SerializableCiphertext(encryptor->encrypt_symmetric(*plaintext));
    }
    
    //evaluator
    Evaluator* new_Evaluator(SEALContext* ctx) {
        return new Evaluator(*ctx);
    }
    Ciphertext* negate(Evaluator* evaluator, Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->negate(*encrypted,*res);
        return res;
    }
    Ciphertext* add(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->add(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* sub(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->sub(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* multiply(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->multiply(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* square(Evaluator* evaluator, Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->square(*encrypted,*res);
        return res;
    }
    Ciphertext* relinearize(Evaluator* evaluator, Ciphertext* encrypted, RelinKeys* rlk) {
        Ciphertext* res = new Ciphertext();
        evaluator->relinearize(*encrypted, *rlk, *res);
        return res;
    }
    Ciphertext* rescale_to_next(Evaluator* evaluator, Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->rescale_to_next(*encrypted,*res);
        return res;
    }
    Ciphertext* exponentiate(Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, RelinKeys* rlk) {
        Ciphertext* res = new Ciphertext();
        evaluator->exponentiate(*encrypted, exponent, *rlk, *res);
        return res;
    }
    Ciphertext* add_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->add_plain(*encrypted, *plain, *res);
        return res;
    }
    Ciphertext* sub_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->sub_plain(*encrypted, *plain, *res);
        return res;
    }
    Ciphertext* multiply_plain(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->multiply_plain(*encrypted, *plain, *res);
        return res;
    }
    
    
    void negate_inplace(Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->negate_inplace(*encrypted);
    }
    void add_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        evaluator->add_inplace(*encrypted1, *encrypted2);
    }
    void sub_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        evaluator->sub_inplace(*encrypted1, *encrypted2);
    }
    void multiply_inplace(Evaluator* evaluator, Ciphertext* encrypted1, Ciphertext* encrypted2) {
        evaluator->multiply_inplace(*encrypted1, *encrypted2);
    }
    void square_inplace(Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->square_inplace(*encrypted);
    }
    void relinearize_inplace(Evaluator* evaluator, Ciphertext* encrypted, std::unique_ptr<RelinKeys>& rlk) {
        evaluator->relinearize_inplace(*encrypted, *rlk);
    }
    void rescale_to_next_inplace(Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->rescale_to_next_inplace(*encrypted);
    }
    void exponentiate_inplace(Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, std::unique_ptr<RelinKeys>& rlk) {
        evaluator->exponentiate_inplace(*encrypted, exponent, *rlk);
    }
    void add_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        evaluator->add_plain_inplace(*encrypted, *plain);
    }
    void sub_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        evaluator->sub_plain_inplace(*encrypted, *plain);
    }
    void multiply_plain_inplace(Evaluator* evaluator, Ciphertext* encrypted, Plaintext* plain) {
        evaluator->multiply_plain_inplace(*encrypted, *plain);
    }
    
    
    void setscale(Ciphertext* encrypted, double scale) {
        encrypted->scale()=scale;
    }
    parms_id_type* parms_id(Ciphertext* encrypted){
        return new parms_id_type(encrypted->parms_id());
    }
    Ciphertext* mod_switch_to(Evaluator* evaluator, Ciphertext* encrypted, parms_id_type* id){
        Ciphertext* res = new Ciphertext();
        evaluator->mod_switch_to(*encrypted, *id, *res);
        return res;
    }
    void mod_switch_to_inplace(Evaluator* evaluator, Ciphertext* encrypted, parms_id_type* id){
        evaluator->mod_switch_to_inplace(*encrypted, *id);
    }
}
