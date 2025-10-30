use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGgswParameters, CrtGlevParameters, CrtGlweParameters, RingSecretKeyType, RlweParameters,
};
use primus_modulus::{Barrett, BarrettModulus, integer::multiply_many_values, reduce::Modulus};
use primus_rns::RNSBase;

#[cfg(feature = "gt128")]
#[derive(Barrett)]
#[modulus(u32, value = 40961)]
pub struct CommitModulus;

#[cfg(not(feature = "gt128"))]
#[derive(Barrett)]
#[modulus(u32, value = 12289)]
pub struct CommitModulus;

pub type CommitValueT = u32;

pub type CommitTable = primus_ntt::Concrete32Table;

pub type CrtValueT = u64;
pub type CrtTable = primus_ntt::CrtConcrete64Table;

/// Parameters for ssle.
#[derive(Clone)]
pub struct SsleParameters {
    commit_params: RlweParameters<u32, CommitModulus>,
    commit_message_length: usize,
    ring_params: CrtGlweParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    ggsw_params: CrtGgswParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    expand_coeff_params: CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
}

const GAMMA: CrtValueT = 140737488273409;

impl SsleParameters {
    pub fn for_test(party_count: usize) -> Self {
        assert!(party_count.is_power_of_two() && party_count >= 2 && party_count <= 2048);

        let commit_message_length = 60;

        let commit_params =
            RlweParameters::new(512, 2, CommitModulus, RingSecretKeyType::Ternary, 3.19);

        let rns_moduli: [CrtValueT; 2] = [1125899906826241, 1125899906629633];

        let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
        let rns_base = RNSBase::new(&moduli).unwrap();
        let modulus = rns_base.moduli_product().to_vec();

        let ring_params = CrtGlweParameters::new(
            8,
            512,
            BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
            BarrettModulus::new(GAMMA),
            &moduli,
            RingSecretKeyType::Ternary,
            0.849,
        );

        let basis = BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base);

        let ggsw_params = CrtGgswParameters::with_glwe_params(&ring_params, basis.clone());

        let expand_coeff_params = CrtGlevParameters::with_glwe_params(&ring_params, basis);

        Self {
            commit_params,
            commit_message_length,
            ring_params,
            ggsw_params,
            expand_coeff_params,
        }
    }

    pub fn new(party_count: usize) -> Self {
        assert!(party_count.is_power_of_two() && party_count >= 2 && party_count <= 2048);

        let commit_message_length = 60;

        if party_count <= 128 {
            let commit_params =
                RlweParameters::new(512, 2, CommitModulus, RingSecretKeyType::Ternary, 3.19);

            let rns_moduli: [CrtValueT; 2] = [1125899906826241, 1125899906629633];

            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let rns_base = RNSBase::new(&moduli).unwrap();
            let modulus = rns_base.moduli_product().to_vec();

            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 31, Some(2), &rns_base),
                4 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                8 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                16 => BigUintApproxSignedBasis::new(&modulus, 23, Some(3), &rns_base),
                32 => BigUintApproxSignedBasis::new(&modulus, 20, Some(4), &rns_base),
                64 => BigUintApproxSignedBasis::new(&modulus, 18, Some(4), &rns_base),
                128 => BigUintApproxSignedBasis::new(&modulus, 16, Some(5), &rns_base),
                _ => unreachable!(),
            };

            let ring_params = CrtGlweParameters::new(
                8,
                512,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                0.849,
            );

            let ggsw_params = CrtGgswParameters::with_glwe_params(&ring_params, basis);

            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 34, Some(2), &rns_base),
                4 => BigUintApproxSignedBasis::new(&modulus, 34, Some(2), &rns_base),
                8 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                16 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                32 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                64 => BigUintApproxSignedBasis::new(&modulus, 20, Some(4), &rns_base),
                128 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5), &rns_base),
                _ => unreachable!(),
            };

            let expand_coeff_params = CrtGlevParameters::with_glwe_params(&ring_params, basis);

            Self {
                commit_params,
                commit_message_length,
                ring_params,
                ggsw_params,
                expand_coeff_params,
            }
        } else {
            let poly_length = match party_count {
                256 | 512 => 512,
                1024 => 1024,
                2048 => 2048,
                _ => unreachable!(),
            };

            let commit_params = RlweParameters::new(
                poly_length,
                2,
                CommitModulus,
                RingSecretKeyType::Ternary,
                0.849,
            );

            let rns_moduli: [CrtValueT; 3] = [137438822401, 68719403009, 68719230977];
            let modulus = multiply_many_values(&rns_moduli);
            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let rns_base = RNSBase::new(&moduli).unwrap();

            let poly_length = match party_count {
                256 | 512 => 512,
                1024 => 1024,
                2048 => 2048,
                _ => unreachable!(),
            };

            let dimmension = 4096 / poly_length;

            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5), &rns_base),
                512 => BigUintApproxSignedBasis::new(&modulus, 16, Some(6), &rns_base),
                1024 => BigUintApproxSignedBasis::new(&modulus, 14, Some(6), &rns_base),
                2048 => BigUintApproxSignedBasis::new(&modulus, 11, Some(8), &rns_base),
                _ => unreachable!(),
            };

            let ring_params = CrtGlweParameters::new(
                dimmension,
                poly_length,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                5.56,
            );

            let ggsw_params = CrtGgswParameters::with_glwe_params(&ring_params, basis);

            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 19, Some(5), &rns_base),
                512 => BigUintApproxSignedBasis::new(&modulus, 17, Some(6), &rns_base),
                1024 => BigUintApproxSignedBasis::new(&modulus, 14, Some(7), &rns_base),
                2048 => BigUintApproxSignedBasis::new(&modulus, 12, Some(9), &rns_base),
                _ => unreachable!(),
            };

            let expand_coeff_params = CrtGlevParameters::with_glwe_params(&ring_params, basis);

            Self {
                commit_params,
                commit_message_length,
                ring_params,
                ggsw_params,
                expand_coeff_params,
            }
        }
    }

    pub fn commit_params(&self) -> &RlweParameters<u32, CommitModulus> {
        &self.commit_params
    }

    pub fn commit_message_length(&self) -> usize {
        self.commit_message_length
    }

    pub fn ring_params(&self) -> &CrtGlweParameters<CrtValueT, BarrettModulus<CrtValueT>> {
        &self.ring_params
    }

    pub fn ggsw_params(&self) -> &CrtGgswParameters<CrtValueT, BarrettModulus<CrtValueT>> {
        &self.ggsw_params
    }

    pub fn expand_coeff_params(&self) -> &CrtGlevParameters<u64, BarrettModulus<u64>> {
        &self.expand_coeff_params
    }
}
