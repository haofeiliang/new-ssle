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

#[cfg(all(not(feature = "gt128"), feature = "gt32"))]
#[derive(Barrett)]
#[modulus(u32, value = 18433)]
pub struct CommitModulus;

#[cfg(all(not(feature = "gt128"), not(feature = "gt32")))]
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
    ring_params: CrtGlweParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    ggsw_params: CrtGgswParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    expand_coeff_params_for_key_gen: CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
    expand_coeff_params: CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>>,
}

const GAMMA: CrtValueT = 2056193;
// const GAMMA: CrtValueT = 2199023190017;

impl SsleParameters {
    pub fn new(party_count: usize) -> Self {
        assert!(party_count.is_power_of_two() && (2..=2048).contains(&party_count));

        let commit_params = if party_count <= 32 {
            RlweParameters::new(512, 2, CommitModulus, RingSecretKeyType::Ternary, 3.19)
        } else {
            RlweParameters::new(1024, 2, CommitModulus, RingSecretKeyType::Ternary, 0.849)
        };

        if party_count <= 128 {
            let rns_moduli: [CrtValueT; 2] = [1125899906826241, 1125899906629633];

            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let rns_base = RNSBase::new(&moduli).unwrap();
            let modulus = rns_base.moduli_product().to_vec();

            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 23, Some(3), &rns_base),
                4 => BigUintApproxSignedBasis::new(&modulus, 23, Some(3), &rns_base),
                8 => BigUintApproxSignedBasis::new(&modulus, 23, Some(3), &rns_base),
                16 => BigUintApproxSignedBasis::new(&modulus, 18, Some(4), &rns_base),
                32 => BigUintApproxSignedBasis::new(&modulus, 18, Some(4), &rns_base),
                64 => BigUintApproxSignedBasis::new(&modulus, 15, Some(5), &rns_base),
                128 => BigUintApproxSignedBasis::new(&modulus, 13, Some(6), &rns_base),
                _ => unreachable!(),
            };

            let ring_params = CrtGlweParameters::new(
                1,
                4096,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                (0.849 * 0.849 * (party_count as f64)).sqrt(),
            );

            let basic_ring_params = CrtGlweParameters::new(
                1,
                4096,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                0.849,
            );

            let ggsw_params = CrtGgswParameters::with_glwe_params(&basic_ring_params, basis);

            let basis = match party_count {
                2 => BigUintApproxSignedBasis::new(&modulus, 33, Some(2), &rns_base),
                4 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                8 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                16 => BigUintApproxSignedBasis::new(&modulus, 25, Some(3), &rns_base),
                32 => BigUintApproxSignedBasis::new(&modulus, 20, Some(4), &rns_base),
                64 => BigUintApproxSignedBasis::new(&modulus, 16, Some(5), &rns_base),
                128 => BigUintApproxSignedBasis::new(&modulus, 16, Some(5), &rns_base),
                _ => unreachable!(),
            };

            let expand_coeff_params_for_key_gen =
                CrtGlevParameters::with_glwe_params(&ring_params, basis.clone());

            let expand_coeff_params =
                CrtGlevParameters::with_glwe_params(&basic_ring_params, basis);

            Self {
                commit_params,
                ring_params,
                ggsw_params,
                expand_coeff_params_for_key_gen,
                expand_coeff_params,
            }
        } else {
            let (rns_moduli, std_dev): ([CrtValueT; 3], f64) = if party_count == 256 {
                ([137438822401, 68719403009, 68719230977], 5.6)
            } else if party_count == 512 || party_count == 1024 {
                ([137438822401, 137438814209, 68719403009], 11.12)
            } else {
                ([137438822401, 137438814209, 137438773249], 22.4)
            };
            let modulus = multiply_many_values(&rns_moduli);
            let moduli = rns_moduli.map(BarrettModulus::new).to_vec();
            let rns_base = RNSBase::new(&moduli).unwrap();

            let poly_length = 4096;
            let dimmension = 1;

            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5), &rns_base),
                512 => BigUintApproxSignedBasis::new(&modulus, 17, Some(5), &rns_base),
                1024 => BigUintApproxSignedBasis::new(&modulus, 14, Some(6), &rns_base),
                2048 => BigUintApproxSignedBasis::new(&modulus, 13, Some(7), &rns_base),
                _ => unreachable!(),
            };

            let ring_params = CrtGlweParameters::new(
                dimmension,
                poly_length,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                (0.849 * 0.849 * (party_count as f64)).sqrt(),
            );

            let basic_ring_params = CrtGlweParameters::new(
                dimmension,
                poly_length,
                BarrettModulus::new(CommitModulus.value_unchecked() as CrtValueT),
                BarrettModulus::new(GAMMA),
                &moduli,
                RingSecretKeyType::Ternary,
                std_dev,
            );

            let ggsw_params = CrtGgswParameters::with_glwe_params(&basic_ring_params, basis);

            let basis = match party_count {
                256 => BigUintApproxSignedBasis::new(&modulus, 21, Some(4), &rns_base),
                512 => BigUintApproxSignedBasis::new(&modulus, 18, Some(5), &rns_base),
                1024 => BigUintApproxSignedBasis::new(&modulus, 15, Some(6), &rns_base),
                2048 => BigUintApproxSignedBasis::new(&modulus, 15, Some(6), &rns_base),
                _ => unreachable!(),
            };

            let expand_coeff_params_for_key_gen =
                CrtGlevParameters::with_glwe_params(&ring_params, basis.clone());

            let expand_coeff_params =
                CrtGlevParameters::with_glwe_params(&basic_ring_params, basis);

            Self {
                commit_params,
                ring_params,
                ggsw_params,
                expand_coeff_params_for_key_gen,
                expand_coeff_params,
            }
        }
    }

    pub fn commit_params(&self) -> &RlweParameters<u32, CommitModulus> {
        &self.commit_params
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

    pub fn expand_coeff_params_for_key_gen(
        &self,
    ) -> &CrtGlevParameters<CrtValueT, BarrettModulus<CrtValueT>> {
        &self.expand_coeff_params_for_key_gen
    }
}
