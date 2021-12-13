#include "bindings.h"
#include <stdexcept>
#include <algorithm>
#include <cmath>
#include "seal/seal.h"

using namespace seal;
using namespace seal::util;

namespace bindings
{
void print_parameters(const SEALContext* ctx)
{
    auto &context_data = ctx->key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}
    //setup
    EncryptionParameters* new_encryption_parameters(int scheme) {
        return new EncryptionParameters((scheme_type)scheme);
    }
    void EncryptionParameters_set_poly_modulus_degree(const EncryptionParameters* ep, int degree) {
        ep->set_poly_modulus_degree(degree);
    }
    void EncryptionParameters_set_plain_modulus(const EncryptionParameters* ep, int modulus) {
        ep->set_plain_modulus(modulus);
    }
    void EncryptionParameters_set_coeff_modulus_Create(const EncryptionParameters* ep, size_t poly_modulus_degree, const std::vector<int> &bit_sizes) {
        std::vector<int> sizes;
          std::copy(bit_sizes.begin(), bit_sizes.end(), std::back_inserter(sizes));
        ep->set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,sizes));
    }
    void EncryptionParameters_set_coeff_modulus_BFVDefault(const EncryptionParameters* ep, size_t poly_modulus_degree) {
        ep->set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    }
    void EncryptionParameters_set_plain_modulus(const EncryptionParameters* ep, size_t plain_modulus) {
        ep->set_plain_modulus(plain_modulus);
    }
    void EncryptionParameters_set_plain_modulus_Batching(const EncryptionParameters* ep, size_t poly_modulus_degree, int bit_size) {
        ep->set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, bit_size));
    }    
    SEALContext* new_SEALContext(const EncryptionParameters* ep) {
        return new SEALContext(*ep);
    }
    //keygen
    KeyGenerator* new_KeyGenerator(const SEALContext* ctx) {
        return new KeyGenerator(*ctx);
    }
    SecretKey* KeyGenerator_secret_key(const KeyGenerator* keygen) {
        return new SecretKey(keygen->secret_key());
    }
    SerializablePublicKey* KeyGenerator_create_public_key(const KeyGenerator* keygen) {
        return new SerializablePublicKey(keygen->create_public_key());
    }
    SerializableRelinKeys* KeyGenerator_create_relin_keys(const KeyGenerator* keygen) {
        return new SerializableRelinKeys(keygen->create_relin_keys());
    }
    PublicKey* Serializable_to_PublicKey(const SEALContext* ctx, const SerializablePublicKey* spk) {
        std::stringstream data_stream;
        spk->save(data_stream);
        PublicKey* pk = new PublicKey();
        pk->load(*ctx, data_stream);
        return pk;
    }
    RelinKeys* Serializable_to_RelinKeys(const SEALContext* ctx, const SerializableRelinKeys* srlk) {
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
    Plaintext* new_Plaintext(const std::string data) {
        return new Plaintext(data);
    }
    std::string Plaintext_to_string(const Plaintext* plaintext) {
        return plaintext->to_string();
    }
    //use simd
    BatchEncoder* new_BatchEncoder(const SEALContext* ctx) {
        return new BatchEncoder(*ctx);
    }
    size_t slot_count(const BatchEncoder* be) {
        return be->slot_count();
    }
    Plaintext* encode(const BatchEncoder* be, const std::vector<uint64_t> &vec) {
        Plaintext* plaintext = new Plaintext();
        be->encode(vec, *plaintext);
        return plaintext;
    }
    std::vector<uint64_t> decode(const BatchEncoder* be, const Plaintext* plain) {
        std::vector<uint64_t> vec;
        be->decode(*plain, vec);
        return vec;
    }
    //ckks
    CKKSEncoder* new_CKKSEncoder(const SEALContext* ctx) {
        return new CKKSEncoder(*ctx);
    }
    size_t CKKSEncoder_slot_count(const CKKSEncoder* ce) {
        return ce->slot_count();
    }
    Plaintext* CKKSEncoder_encode_vec(const CKKSEncoder* ce, double scale, const std::vector<double> &vec) {
        Plaintext* plaintext = new Plaintext();
        ce->encode(vec, scale, *plaintext);
        return plaintext;
    }
    Plaintext* CKKSEncoder_encode(const CKKSEncoder* ce, double scale, double value) {
        Plaintext* plaintext = new Plaintext();
        ce->encode(value, scale, *plaintext);
        return plaintext;
    }
    std::vector<double> CKKSEncoder_decode(const CKKSEncoder* ce, const Plaintext* plain) {
        std::vector<double> vec;
        ce->decode(*plain, vec);
        return vec;
    }
    
    
    //encryptor and decryptor
    Decryptor* new_Decryptor(const SEALContext* ctx, const SecretKey* sk) {
        return new Decryptor(*ctx,*sk);
    }
    Ciphertext* Serializable_to_Ciphertext(const SEALContext* ctx, const SerializableCiphertext* cipher) {
        std::stringstream data_stream;
        cipher->save(data_stream);
        Ciphertext* ciphertext = new Ciphertext();
        ciphertext->load(*ctx, data_stream);
        return ciphertext;
    }
    Plaintext* decrypt(const Decryptor* decryptor, const Ciphertext* ciphertext) {
        Plaintext* plaintext = new Plaintext();
        decryptor->decrypt(*ciphertext, *plaintext);
        return plaintext;
    }
    Encryptor* new_Encryptor_pk(const SEALContext* ctx, const PublicKey* pk) {
        return new Encryptor(*ctx,*pk);
    }
    SerializableCiphertext* encrypt(const Encryptor* encryptor, const Plaintext* plaintext) {
        return new SerializableCiphertext(encryptor->encrypt(*plaintext));
    }
    Encryptor* new_Encryptor_sk(const SEALContext* ctx, const SecretKey* sk) {
        return new Encryptor(*ctx,*sk);
    }
    SerializableCiphertext* encrypt_symmetric(const Encryptor* encryptor, const Plaintext* plaintext) {
        return new SerializableCiphertext(encryptor->encrypt_symmetric(*plaintext));
    }
    
    //evaluator
    Evaluator* new_Evaluator(const SEALContext* ctx) {
        return new Evaluator(*ctx);
    }
    Ciphertext* negate(const Evaluator* evaluator, const Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->negate(*encrypted,*res);
        return res;
    }
    Ciphertext* add(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->add(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* sub(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->sub(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* multiply(const Evaluator* evaluator, const Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        Ciphertext* res = new Ciphertext();
        evaluator->multiply(*encrypted1, *encrypted2, *res);
        return res;
    }
    Ciphertext* square(const Evaluator* evaluator, const Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->square(*encrypted,*res);
        return res;
    }
    Ciphertext* relinearize(const Evaluator* evaluator, const Ciphertext* encrypted, const RelinKeys* rlk) {
        Ciphertext* res = new Ciphertext();
        evaluator->relinearize(*encrypted, *rlk, *res);
        return res;
    }
    Ciphertext* rescale_to_next(const Evaluator* evaluator, const Ciphertext* encrypted) {
        Ciphertext* res = new Ciphertext();
        evaluator->rescale_to_next(*encrypted,*res);
        return res;
    }
    Ciphertext* exponentiate(const Evaluator* evaluator, const Ciphertext* encrypted, uint64_t exponent, const RelinKeys* rlk) {
        Ciphertext* res = new Ciphertext();
        evaluator->exponentiate(*encrypted, exponent, *rlk, *res);
        return res;
    }
    Ciphertext* add_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->add_plain(*encrypted, *plain, *res);
        return res;
    }
    Ciphertext* sub_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->sub_plain(*encrypted, *plain, *res);
        return res;
    }
    Ciphertext* multiply_plain(const Evaluator* evaluator, const Ciphertext* encrypted, const Plaintext* plain) {
        Ciphertext* res = new Ciphertext();
        evaluator->multiply_plain(*encrypted, *plain, *res);
        return res;
    }
    
    
    void negate_inplace(const Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->negate_inplace(*encrypted);
    }
    void add_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        evaluator->add_inplace(*encrypted1, *encrypted2);
    }
    void sub_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        evaluator->sub_inplace(*encrypted1, *encrypted2);
    }
    void multiply_inplace(const Evaluator* evaluator, Ciphertext* encrypted1, const Ciphertext* encrypted2) {
        evaluator->multiply_inplace(*encrypted1, *encrypted2);
    }
    void square_inplace(const Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->square_inplace(*encrypted);
    }
    void relinearize_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const std::unique_ptr<RelinKeys>& rlk) {
        evaluator->relinearize_inplace(*encrypted, *rlk);
    }
    void rescale_to_next_inplace(const Evaluator* evaluator, Ciphertext* encrypted) {
        evaluator->rescale_to_next_inplace(*encrypted);
    }
    void exponentiate_inplace(const Evaluator* evaluator, Ciphertext* encrypted, uint64_t exponent, const std::unique_ptr<RelinKeys>& rlk) {
        evaluator->exponentiate_inplace(*encrypted, exponent, *rlk);
    }
    void add_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain) {
        evaluator->add_plain_inplace(*encrypted, *plain);
    }
    void sub_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain) {
        evaluator->sub_plain_inplace(*encrypted, *plain);
    }
    void multiply_plain_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const Plaintext* plain) {
        evaluator->multiply_plain_inplace(*encrypted, *plain);
    }
    
    
    void setscale(const Ciphertext* encrypted, double scale) {
        encrypted->scale()=scale;
    }
    parms_id_type* parms_id(const Ciphertext* encrypted){
        return new parms_id_type(encrypted->parms_id());
    }
    Ciphertext* mod_switch_to(const Evaluator* evaluator, const Ciphertext* encrypted, const parms_id_type* id){
        Ciphertext* res = new Ciphertext();
        evaluator->mod_switch_to(*encrypted, *id, *res);
        return res;
    }
    void mod_switch_to_inplace(const Evaluator* evaluator, Ciphertext* encrypted, const parms_id_type* id){
        evaluator->mod_switch_to_inplace(*encrypted, *id);
    }
}

