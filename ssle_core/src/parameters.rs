use primus_barrett_modulus::{
    Barrett, BarrettModulus, integer::multiply_many_values, reduce::Modulus,
};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{CrtGgswParameters, CrtGlevParameters, RingSecretKeyType, RlweParameters};

#[derive(Barrett)]
#[modulus(u32, value = 12289)]
pub struct CommitModulus;

/// Parameters for ssle.
#[derive(Clone)]
pub struct SsleParameters {
    commit_params: RlweParameters<u32, CommitModulus>,
    commit_message_length: usize,
    ring_params: CrtGgswParameters<u64, BarrettModulus<u64>>,
    expand_coeff_params: CrtGlevParameters<u64, BarrettModulus<u64>>,
}

impl SsleParameters {
    pub fn new(party_count: usize) -> Self {
        assert!(party_count.is_power_of_two() && party_count >= 2 && party_count <= 2048);

        let commit_message_length = 60;

        if party_count <= 128 {
            let commit_params = RlweParameters {
                poly_length: 512,
                plain_modulus_value: 2,
                modulus_minus_one: CommitModulus.minus_one(),
                modulus: CommitModulus,
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 3.19,
            };

            let rns_moduli: [u64; 2] = [1125899906826241, 1125899906629633];
            let modulus = multiply_many_values(&rns_moduli);
            let modulus_minus_one = {
                let mut temp = modulus.clone();
                temp[0] -= 1;
                temp
            };
            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 31, Some(2)),
                4 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3)),
                8 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3)),
                16 => BigUintApproxSignedBasis::new(&modulus, 23, Some(3)),
                32 => BigUintApproxSignedBasis::new(&modulus, 20, Some(4)),
                64 => BigUintApproxSignedBasis::new(&modulus, 18, Some(4)),
                128 => BigUintApproxSignedBasis::new(&modulus, 16, Some(5)),
                _ => unreachable!(),
            };

            let ring_params = CrtGgswParameters {
                dimension: 8,
                poly_length: 512,
                modulus_minus_one: modulus_minus_one.clone(),
                modulus: modulus.clone(),
                moduli: moduli.clone(),
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 0.849,
                basis,
            };

            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 34, Some(2)),
                4 => BigUintApproxSignedBasis::new(&modulus, 34, Some(2)),
                8 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3)),
                16 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3)),
                32 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3)),
                64 => BigUintApproxSignedBasis::new(&modulus, 20, Some(4)),
                128 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5)),
                _ => unreachable!(),
            };

            let expand_coeff_params = CrtGlevParameters {
                dimension: 8,
                poly_length: 512,
                modulus_minus_one,
                modulus,
                moduli,
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 0.849,
                basis,
            };

            assert_eq!(ring_params.dimension, expand_coeff_params.dimension);
            assert_eq!(ring_params.modulus, expand_coeff_params.modulus);
            assert_eq!(
                ring_params.secret_key_type,
                expand_coeff_params.secret_key_type
            );

            Self {
                commit_params,
                commit_message_length,
                ring_params,
                expand_coeff_params,
            }
        } else {
            let commit_params = RlweParameters {
                poly_length: 1024,
                plain_modulus_value: 2,
                modulus_minus_one: CommitModulus.minus_one(),
                modulus: CommitModulus,
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 0.849,
            };

            let rns_moduli: [u64; 3] = [137438822401, 68719403009, 68719230977];
            let modulus = multiply_many_values(&rns_moduli);
            let modulus_minus_one = {
                let mut temp = modulus.clone();
                temp[0] -= 1;
                temp
            };
            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5)),
                512 => BigUintApproxSignedBasis::new(&modulus, 16, Some(6)),
                1024 => BigUintApproxSignedBasis::new(&modulus, 14, Some(6)),
                2048 => BigUintApproxSignedBasis::new(&modulus, 11, Some(8)),
                _ => unreachable!(),
            };

            let ring_params = CrtGgswParameters {
                dimension: 4,
                poly_length: 1024,
                modulus_minus_one: modulus_minus_one.clone(),
                modulus: modulus.clone(),
                moduli: moduli.clone(),
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 5.56,
                basis,
            };

            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 19, Some(5)),
                512 => BigUintApproxSignedBasis::new(&modulus, 17, Some(6)),
                1024 => BigUintApproxSignedBasis::new(&modulus, 14, Some(7)),
                2048 => BigUintApproxSignedBasis::new(&modulus, 12, Some(9)),
                _ => unreachable!(),
            };

            let expand_coeff_params = CrtGlevParameters {
                dimension: 4,
                poly_length: 1024,
                modulus_minus_one,
                modulus,
                moduli,
                secret_key_type: RingSecretKeyType::Ternary,
                noise_standard_deviation: 5.56,
                basis,
            };

            assert_eq!(ring_params.dimension, expand_coeff_params.dimension);
            assert_eq!(ring_params.modulus, expand_coeff_params.modulus);
            assert_eq!(
                ring_params.secret_key_type,
                expand_coeff_params.secret_key_type
            );

            Self {
                commit_params,
                commit_message_length,
                ring_params,
                expand_coeff_params,
            }
        }
    }

    pub fn commit_params(&self) -> RlweParameters<u32, CommitModulus> {
        self.commit_params
    }

    pub fn commit_message_length(&self) -> usize {
        self.commit_message_length
    }

    pub fn ring_params(&self) -> &CrtGgswParameters<u64, BarrettModulus<u64>> {
        &self.ring_params
    }

    pub fn expand_coeff_params(&self) -> &CrtGlevParameters<u64, BarrettModulus<u64>> {
        &self.expand_coeff_params
    }
}
