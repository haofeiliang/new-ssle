use std::sync::Arc;

use indicatif::{ProgressIterator, ProgressStyle};
use primus_fhe_core::DcrtGlweDecryptContext;
use primus_integer::{AsInto, izip};
use primus_lattice::{
    glwe::{CrtGlwe, DcrtGlwe},
    rlwe::NttRlwe,
};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{ArrayBase, CrtPolynomial, DcrtPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::Modulus;
use primus_reduce::ops::*;
use rand::Rng;
use ssle_core::{CommitModulus, CommitTable, CommitValueT, CrtValueT, KeyGen, SsleParameters};

#[test]
fn test_rotate_commit() {
    let rng = &mut rand::rng();

    let party_count = 4;

    let ssle_params = Arc::new(SsleParameters::new(party_count));

    let (msk, mpk, _eck) = KeyGen::generate_keys(&ssle_params, rng);

    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();

    let commit_poly_length = commit_params.poly_length();

    let ring_poly_length = ring_params.poly_length();
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let table = mpk.table();

    let (commit_sk, _commit_pk) = mpk.generate_commit_key_pair(&commit_ntt_table, rng);
    let (commit_sk_2, _) = mpk.generate_commit_key_pair(&commit_ntt_table, rng);

    let commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    // Check commit
    let decrypt_commit = commit_sk.decrypt(&commit, &commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let commit = commit.into_coeff_form(&commit_ntt_table);

    let style = ProgressStyle::with_template(
        "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})",
    )
    .unwrap()
    .progress_chars("##-");

    for r in (0..8192).step_by(4).progress_with_style(style) {
        let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(rns_glwe_len);

        let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
        b.chunks_exact_mut(ring_poly_length)
            .zip(ring_params.delta_mod_q())
            .for_each(|(poly, &one)| {
                poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
            });

        // let r = rng.random_range(0..ring_poly_length * 2);
        // let r = r - (r % party_count);
        // println!("r: {r}");
        // let r = 8192 - 512 + 4;

        CrtPolynomial(b).mul_monomial_assign(r, ring_poly_length, ring_params.cipher_moduli());

        let selector = acc.into_ntt_form(table);

        let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
        let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);
        let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];

        encode_commits
            .chunks_exact_mut(rns_glwe_len)
            .zip(commit.iter_poly(commit_poly_length))
            .for_each(|(encode_commit, poly)| {
                temp.fill(0);
                temp.iter_mut()
                    .zip(poly.iter())
                    .for_each(|(x, &y)| *x = y as CrtValueT);
                ring_params
                    .base_q()
                    .wrapping_decompose_small_values_inplace(
                        &temp,
                        msg.as_mut(),
                        ring_poly_length,
                        CommitModulus.value_unchecked().as_into(),
                    );
                table.transform_slice(msg.as_mut());
                DcrtGlwe(encode_commit).add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &selector,
                    &msg,
                    ring_poly_length,
                    ring_params.cipher_moduli(),
                );
            });

        let mut temp_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];
        let mut temp_crt: Vec<CrtValueT> = vec![0; ring_poly_length * 2];
        let mut decrypt_context =
            DcrtGlweDecryptContext::new(ring_params.cipher_moduli_count(), ring_poly_length);

        let inv_two = CommitModulus.reduce_inv(2);

        let mut temp: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

        let mut div_v = |poly: &mut [CommitValueT]| {
            temp.copy_from(poly.as_ref());
            temp.mul_monomial_assign(party_count, CommitModulus);

            let mut p = Polynomial(poly);

            p.sub_assign(&temp, CommitModulus);
            p.mul_scalar_assign(inv_two, CommitModulus);
        };

        izip!(
            encode_commits.chunks_exact_mut(rns_glwe_len),
            temp_crt.chunks_exact_mut(ring_poly_length),
            temp_commit.chunks_exact_mut(ring_poly_length),
        )
        .for_each(|(ec, cpoly, commit_poly)| {
            msk.decrypt_inplace(
                &DcrtGlwe::new(ec),
                &mut Polynomial(&mut *cpoly),
                ring_params,
                table,
                &mut decrypt_context,
            );
            commit_poly
                .iter_mut()
                .zip(cpoly.iter())
                .for_each(|(x, &y)| {
                    *x = y.try_into().unwrap();
                });
            div_v(commit_poly);
        });

        let mut final_alpha_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];
        let mut final_beta_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];
        izip!(
            temp_commit.chunks_exact(ring_poly_length),
            final_alpha_commit.chunks_exact_mut(commit_poly_length),
            final_beta_commit.chunks_exact_mut(commit_poly_length),
        )
        .for_each(|(s, alpha, beta)| {
            let mut alpha_arr = ArrayBase(alpha);
            let mut beta_arr = ArrayBase(beta);
            for (i, chunk) in s.chunks_exact(commit_poly_length).enumerate() {
                if i == 0 {
                    alpha_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                    beta_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                } else if i % 2 == 0 {
                    alpha_arr.sub_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                    beta_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                } else {
                    alpha_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                    beta_arr.sub_element_wise_assign(&ArrayBase(chunk), CommitModulus);
                }
            }
        });

        final_alpha_commit
            .chunks_exact_mut(commit_poly_length)
            .for_each(|poly| {
                commit_ntt_table.transform_slice(poly);
            });
        final_beta_commit
            .chunks_exact_mut(commit_poly_length)
            .for_each(|poly| {
                commit_ntt_table.transform_slice(poly);
            });

        let alpha_msgs = commit_sk.decrypt(
            &NttRlwe::new(final_alpha_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );
        let beta_msgs = commit_sk.decrypt(
            &NttRlwe::new(final_beta_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );

        assert!(alpha_msgs.is_zero() || beta_msgs.is_zero(), "r: {r}");

        let alpha_msgs = commit_sk_2.decrypt(
            &NttRlwe::new(final_alpha_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );
        let beta_msgs = commit_sk_2.decrypt(
            &NttRlwe::new(final_beta_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );
        assert!(!alpha_msgs.is_zero() && !beta_msgs.is_zero(), "r: {r}");
    }
}

#[test]
fn test_rotate_commit2() {
    let rng = &mut rand::rng();

    let party_count = 4;

    let ssle_params = Arc::new(SsleParameters::new(party_count));

    let (msk, mpk, _eck) = KeyGen::generate_keys(&ssle_params, rng);

    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();

    let commit_poly_length = commit_params.poly_length();

    let ring_poly_length = ring_params.poly_length();
    let rns_poly_len = ring_params.rns_poly_len();
    let rns_glwe_len = ring_params.rns_glwe_len();

    let commit_ntt_table =
        CommitTable::new(commit_poly_length.trailing_zeros(), CommitModulus).unwrap();

    let table = mpk.table();

    let (commit_sk, _commit_pk) = mpk.generate_commit_key_pair(&commit_ntt_table, rng);
    let (commit_sk_2, _) = mpk.generate_commit_key_pair(&commit_ntt_table, rng);

    let commit = commit_sk.encrypt_zeros(commit_params, &commit_ntt_table, rng);

    // Check commit
    let decrypt_commit = commit_sk.decrypt(&commit, &commit_params, &commit_ntt_table);
    assert!(decrypt_commit.iter().copied().all(|v| v == 0));

    let commit = commit.into_coeff_form(&commit_ntt_table);

    let style = ProgressStyle::with_template(
        "[{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})",
    )
    .unwrap()
    .progress_chars("##-");

    for r in (0..8192).step_by(4).progress_with_style(style) {
        let mut acc: CrtGlwe<Vec<CrtValueT>> = CrtGlwe::zero(rns_glwe_len);

        let (_, b) = acc.a_b_mut_slices(ring_params.rns_glwe_mid());
        b.chunks_exact_mut(ring_poly_length)
            .zip(ring_params.delta_mod_q())
            .for_each(|(poly, &one)| {
                poly.iter_mut().step_by(party_count).for_each(|v| *v = one);
            });

        // let r = rng.random_range(0..ring_poly_length * 2);
        // let r = r - (r % party_count);
        // println!("r: {r}");
        // let r = 8192 - 512 + 4;

        CrtPolynomial(b).mul_monomial_assign(r, ring_poly_length, ring_params.cipher_moduli());

        let selector = acc.into_ntt_form(table);

        let mut temp: Vec<CrtValueT> = vec![0; ring_poly_length];
        let mut msg: DcrtPolynomial<Vec<CrtValueT>> = DcrtPolynomial::zero(rns_poly_len);
        let mut encode_commits: Vec<CrtValueT> = vec![0; rns_glwe_len * 2];

        encode_commits
            .chunks_exact_mut(rns_glwe_len)
            .zip(commit.iter_poly(commit_poly_length))
            .for_each(|(encode_commit, poly)| {
                temp.fill(0);
                temp.iter_mut()
                    .zip(poly.iter())
                    .for_each(|(x, &y)| *x = y as CrtValueT);
                ring_params
                    .base_q()
                    .wrapping_decompose_small_values_inplace(
                        &temp,
                        msg.as_mut(),
                        ring_poly_length,
                        CommitModulus.value_unchecked().as_into(),
                    );
                table.transform_slice(msg.as_mut());
                DcrtGlwe(encode_commit).add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &selector,
                    &msg,
                    ring_poly_length,
                    ring_params.cipher_moduli(),
                );
            });

        let mut temp_commit: Vec<CommitValueT> = vec![0; ring_poly_length * 2];
        let mut temp_crt: Vec<CrtValueT> = vec![0; ring_poly_length * 2];
        let mut decrypt_context =
            DcrtGlweDecryptContext::new(ring_params.cipher_moduli_count(), ring_poly_length);

        let inv_two = CommitModulus.reduce_inv(2);

        let mut temp: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

        let mut div_v = |poly: &mut [CommitValueT]| {
            temp.copy_from(poly.as_ref());
            temp.mul_monomial_assign(party_count, CommitModulus);

            let mut p = Polynomial(poly);

            p.sub_assign(&temp, CommitModulus);
            p.mul_scalar_assign(inv_two, CommitModulus);
        };

        izip!(
            encode_commits.chunks_exact_mut(rns_glwe_len),
            temp_crt.chunks_exact_mut(ring_poly_length),
            temp_commit.chunks_exact_mut(ring_poly_length),
        )
        .for_each(|(ec, cpoly, commit_poly)| {
            msk.decrypt_inplace(
                &DcrtGlwe(ec),
                &mut Polynomial(&mut *cpoly),
                ring_params,
                table,
                &mut decrypt_context,
            );
            commit_poly
                .iter_mut()
                .zip(cpoly.iter())
                .for_each(|(x, &y)| {
                    *x = y.try_into().unwrap();
                });
            div_v(commit_poly);
        });

        let mut final_commit: Vec<CommitValueT> = vec![0; commit_poly_length * 2];

        {
            let (a_in, b_in) = temp_commit.split_at_mut(ring_poly_length);
            let (a_out, b_out) = final_commit.split_at_mut(commit_poly_length);

            let mut a_arr = ArrayBase(a_out);
            let mut b_arr = ArrayBase(b_out);

            let mut last = None;
            'o: for (i, (a_chunk, b_chunk)) in a_in
                .chunks_exact(commit_poly_length)
                .zip(b_in.chunks_exact(commit_poly_length))
                .enumerate()
            {
                if !ArrayBase(a_chunk).is_zero() || !ArrayBase(b_chunk).is_zero() {
                    if let Some(last) = last {
                        if last + 1 != i {
                            a_arr.add_element_wise_assign(&ArrayBase(a_chunk), CommitModulus);
                            b_arr.add_element_wise_assign(&ArrayBase(b_chunk), CommitModulus);
                        } else {
                            a_arr.sub_element_wise_assign(&ArrayBase(a_chunk), CommitModulus);
                            b_arr.sub_element_wise_assign(&ArrayBase(b_chunk), CommitModulus);
                        }
                        break 'o;
                    } else {
                        a_arr.copy_from_slice(a_chunk);
                        b_arr.copy_from_slice(b_chunk);
                        last = Some(i);
                    }
                }
            }
        }

        // izip!(
        //     temp_commit.chunks_exact(ring_poly_length),
        //     final_commit.chunks_exact_mut(commit_poly_length),
        // )
        // .for_each(|(s, alpha)| {
        //     let mut alpha_arr = ArrayBase(alpha);

        //     let mut last = None;
        //     'o: for (i, chunk) in s.chunks_exact(commit_poly_length).enumerate() {
        //         if !ArrayBase(chunk).is_zero() {
        //             if let Some(last) = last {
        //                 if last + 1 != i {
        //                     alpha_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus);
        //                 } else {
        //                     alpha_arr.sub_element_wise_assign(&ArrayBase(chunk), CommitModulus);
        //                 }
        //                 break 'o;
        //             } else {
        //                 alpha_arr.copy_from_slice(chunk);
        //                 last = Some(i);
        //             }
        //         }
        //     }
        // });

        final_commit
            .chunks_exact_mut(commit_poly_length)
            .for_each(|poly| {
                commit_ntt_table.transform_slice(poly);
            });

        let msgs = commit_sk.decrypt(
            &NttRlwe::new(final_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );

        assert!(msgs.is_zero(), "r: {r}");

        let msgs = commit_sk_2.decrypt(
            &NttRlwe::new(final_commit.as_ref()),
            commit_params,
            &commit_ntt_table,
        );

        assert!(!msgs.is_zero(), "r: {r}");
    }
}

#[test]
fn inv_v() {
    let rng = &mut rand::rng();

    let party_count = 4;

    let ssle_params = SsleParameters::new(party_count);

    let commit_params = ssle_params.commit_params();
    let ring_params = ssle_params.ring_params();

    let commit_poly_length = commit_params.poly_length();

    let ring_poly_length = ring_params.poly_length();

    let a: PolynomialOwned<CommitValueT> =
        Polynomial::random(commit_poly_length, CommitModulus, rng);

    let mut v: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);
    v.iter_mut().step_by(party_count).for_each(|v| *v = 1);

    let mut msg: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);
    msg.iter_mut().zip(a.iter()).for_each(|(x, &y)| *x = y);

    let mut result: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);

    Polynomial(msg.as_mut_slice()).naive_mul_inplace(
        &Polynomial(v.as_ref()),
        &mut result,
        CommitModulus,
    );

    let inv_two = CommitModulus.reduce_inv(2);

    let div_v = |poly: &mut [CommitValueT]| {
        let mut temp: PolynomialOwned<CommitValueT> = Polynomial::zero(ring_poly_length);
        temp.copy_from(poly.as_ref());
        temp.mul_monomial_assign(party_count, CommitModulus);

        let mut p = Polynomial(poly);

        p.sub_assign(&temp, CommitModulus);
        p.mul_scalar_assign(inv_two, CommitModulus);
    };

    div_v(result.as_mut_slice());

    let (x, y) = result.as_mut_slice().split_at_mut(commit_poly_length);

    let mut x_arr = ArrayBase(x);

    for (i, chunk) in y.chunks_exact(commit_poly_length).enumerate() {
        if i % 2 == 0 {
            x_arr.sub_element_wise_assign(&ArrayBase(chunk), CommitModulus)
        } else {
            x_arr.add_element_wise_assign(&ArrayBase(chunk), CommitModulus)
        }
    }

    assert_eq!(x_arr.as_ref(), a.as_slice());
}

#[test]
fn poly_mul_monomial() {
    let rng = &mut rand::rng();

    let party_count = 4;

    let ssle_params = SsleParameters::new(party_count);

    let commit_params = ssle_params.commit_params();

    let poly_length = commit_params.poly_length();

    let commit_ntt_table = CommitTable::new(poly_length.trailing_zeros(), CommitModulus).unwrap();

    let mut a: PolynomialOwned<CommitValueT> = Polynomial::random(poly_length, CommitModulus, rng);
    let mut v: PolynomialOwned<CommitValueT> = Polynomial::zero(poly_length);
    let mut msg: PolynomialOwned<CommitValueT> = Polynomial::zero(poly_length);

    let mut degree = rng.random_range(0..poly_length);
    if rng.random() {
        v[degree] = 1;
    } else {
        v[degree] = CommitModulus.minus_one();
        degree += poly_length;
    }

    a.naive_mul_inplace(&v, &mut msg, CommitModulus);

    let mut a_c = commit_ntt_table.transform_inplace(a.clone());
    let v = commit_ntt_table.transform_inplace(v);

    a_c.mul_assign(&v, CommitModulus);

    let a_c = commit_ntt_table.inverse_transform_inplace(a_c);

    assert_eq!(a_c, msg);

    a.mul_monomial_assign(degree, CommitModulus);

    assert_eq!(a, msg);
}
