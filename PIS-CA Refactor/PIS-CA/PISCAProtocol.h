#pragma once

#ifndef PISCA_PROTOCOL_H
#define PISCA_PROTOCOL_H

#include <vector>

#include <NTL/ZZ.h>

#include "../CamenischShoup/CamenischShoupEnc.h"
#include "../CamenischShoup/CamenischShoupEncZKP.h"
#include "../Curdleproofs/Curdleproofs.h"
#include "../Curdleproofs/ElGamalCommitment/ElGamalCommitment.h"
#include "../ElGamal/ElGamalEnc.h"
#include "SigmaCiphertextArgument.h"

class PISCAProtocol
{
public:
    struct RoundOneMessage
    {
        CamenischShoupEnc::Ciphertext k_ciphertext;
        std::vector<CamenischShoupEnc::Commitment> k_commitments;
        CamenischShoupEncZKP::ProofMessage k_proof_message;
    };

    struct RoundOneWitness
    {
        NTL::ZZ k;
        NTL::ZZ encryption_randomness;
        std::vector<NTL::ZZ> commitment_randomness;
        CamenischShoupEncZKP::Proof k_proof;
    };

    struct RoundOneState
    {
        RoundOneMessage message;
        RoundOneWitness witness;
    };

    struct RoundTwoMessage
    {
        CamenischShoupEncZKP::BatchBetaProofMessage proof_message;
    };

    struct RoundTwoWitness
    {
        NTL::ZZ k;
        std::vector<NTL::ZZ> input;
        std::vector<NTL::ZZ> a;
        std::vector<NTL::ZZ> alpha;
        std::vector<NTL::ZZ> b;
        std::vector<NTL::ZZ> a_commitment_randomness;
        std::vector<NTL::ZZ> alpha_commitment_randomness;
        std::vector<NTL::ZZ> b_commitment_randomness;
        std::vector<NTL::ZZ> encryption_randomness;
        CamenischShoupEncZKP::BatchBetaProof proof;
    };

    struct RoundTwoState
    {
        RoundTwoMessage message;
        RoundTwoWitness witness;
    };

    struct RoundThreeMessage
    {
        CamenischShoupEncZKP::DecProofMessage proof_message;
        std::vector<ElGamalEnc::Ciphertext> sigma_ciphertexts;
        SigmaCiphertextArgument::ProofMessage sigma_proof_message;
        std::vector<ElGamalEnc::Ciphertext> shuffled_sigma_ciphertexts;
        Curdleproofs::PublicInstance sigma_shuffle_public_instance;
        Curdleproofs::ProofMessage sigma_shuffle_proof_message;
    };

    struct RoundThreeWitness
    {
        CamenischShoupEncZKP::DecProof proof;
        std::vector<NTL::ZZ> gamma;
        std::vector<ElGamalEnc::GroupElement> sigma;
        std::vector<std::shared_ptr<BIGNUM>> sigma_encryption_randomness;
        SigmaCiphertextArgument::Proof sigma_proof;
        std::vector<std::shared_ptr<BIGNUM>> sigma_derandomization_randomness;
        std::vector<std::size_t> sigma_permutation;
        Curdleproofs::Proof sigma_shuffle_proof;
    };

    struct RoundThreeState
    {
        RoundThreeMessage message;
        RoundThreeWitness witness;
    };

    struct PartyState
    {
        std::vector<NTL::ZZ> input;
        std::vector<NTL::ZZ> values;

        CamenischShoupEnc::PublicKey camenisch_shoup_public_key;
        CamenischShoupEnc::SecretKey camenisch_shoup_secret_key;
        CamenischShoupEnc::CommitmentKey camenisch_shoup_commitment_key;

        ElGamalEnc::PublicKey elgamal_public_key;
        ElGamalEnc::SecretKey elgamal_secret_key;
        ElGamalEnc::CommitmentKey elgamal_commitment_key;
        ElGamalCommitment::CommitmentKey sigma_argument_commitment_key;

        NTL::ZZ k;
        RoundOneState round_one;

        std::vector<CamenischShoupEnc::Commitment> input_commitments;
        std::vector<NTL::ZZ> input_commitment_randomness;
        RoundTwoState round_two;
        RoundThreeState round_three;
    };

    struct P1 : PartyState
    {
    };

    struct P2 : PartyState
    {
    };

    PISCAProtocol();

    void Setup(P1& p1, P2& p2) const;
    bool InitializeP1(const std::vector<NTL::ZZ>& x, const std::vector<NTL::ZZ>& v, P1& p1) const;
    bool InitializeP2(const std::vector<NTL::ZZ>& y, P2& p2) const;
    void ExecuteRoundOne(PartyState& round_one_party, const PartyState& verifier_party) const;
    bool VerifyRoundOne(const PartyState& round_one_party, const PartyState& verifier_party) const;
    void ExecuteRoundTwo(PartyState& computation_party, const PartyState& input_party) const;
    bool VerifyRoundTwo(const PartyState& computation_party, const PartyState& input_party) const;
    void ExecuteRoundThree(PartyState& decryption_party, const PartyState& computation_party) const;
    bool VerifyRoundThree(const PartyState& decryption_party, const PartyState& computation_party) const;

    bool CamenischShoupParametersAreIndependent(const P1& p1, const P2& p2) const;
    bool ElGamalBaseParametersAreShared(const P1& p1, const P2& p2) const;
    bool ElGamalNonBaseParametersAreIndependent(const P1& p1, const P2& p2) const;
    bool CommitmentKeysAreIndependent(const P1& p1, const P2& p2) const;

private:
    void GenerateElGamalKeyPairWithSharedBase(
        const ElGamalEnc::PublicKey& shared_public_key,
        ElGamalEnc::PublicKey& public_key,
        ElGamalEnc::SecretKey& secret_key) const;

    void GenerateInputCommitments(
        const CamenischShoupEnc::PublicKey& public_key,
        const CamenischShoupEnc::CommitmentKey& commitment_key,
        const std::vector<NTL::ZZ>& input,
        std::vector<CamenischShoupEnc::Commitment>& commitments,
        std::vector<NTL::ZZ>& commitment_randomness) const;

    void GenerateRoundOneState(
        const CamenischShoupEnc::PublicKey& encryption_public_key,
        const CamenischShoupEnc::CommitmentKey& commitment_key,
        const NTL::ZZ& k,
        RoundOneState& state) const;

    void GenerateRoundTwoState(
        const PartyState& computation_party,
        const PartyState& input_party,
        RoundTwoState& state) const;

    void GenerateRoundThreeState(
        const PartyState& decryption_party,
        const PartyState& computation_party,
        RoundThreeState& state) const;

    CamenischShoupEnc camenisch_shoup_;
    CamenischShoupEncZKP camenisch_shoup_zkp_;
    ElGamalEnc elgamal_;
    ElGamalCommitment sigma_argument_commitment_;
    SigmaCiphertextArgument sigma_ciphertext_argument_;
    Curdleproofs curdleproofs_;
};

#endif // PISCA_PROTOCOL_H
