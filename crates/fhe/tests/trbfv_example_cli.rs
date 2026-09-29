//! Validate the shared threshold-example CLI once, rather than recompiling
//! the same tests into every integration-test and library target that imports
//! the example support module.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../support/examples/trbfv.rs"]
mod trbfv;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn addition_mode_parses_valid_arguments_and_rejects_zero_counts() {
    let cli = trbfv::parse_cli(
        &args(&[
            "--num_summed=10",
            "--num_parties=5",
            "--threshold=2",
            "--lambda=40",
        ]),
        20,
        9,
        31,
        Some(50),
    )
    .expect("valid addition arguments must parse");
    assert_eq!(
        (cli.num_summed, cli.num_parties, cli.threshold, cli.lambda),
        (Some(10), 5, 2, 40)
    );

    for flag in ["--num_summed=0", "--lambda=0"] {
        let error = trbfv::parse_cli(&args(&[flag]), 20, 9, 31, Some(50)).unwrap_err();
        assert!(error.contains("nonzero"), "{flag}: {error}");
    }
}

#[test]
fn multiplication_mode_parses_valid_arguments_and_rejects_addition_flag() {
    let cli = trbfv::parse_cli(
        &args(&["--num_parties=3", "--threshold=1", "--lambda=31"]),
        3,
        1,
        31,
        None,
    )
    .expect("valid multiplication arguments must parse");
    assert_eq!(
        (cli.num_summed, cli.num_parties, cli.threshold, cli.lambda),
        (None, 3, 1, 31)
    );
    let defaults = trbfv::parse_cli(&args(&[]), 20, 9, 31, None).unwrap();
    assert_eq!(
        (
            defaults.num_summed,
            defaults.num_parties,
            defaults.threshold
        ),
        (None, 20, 9)
    );

    let error = trbfv::parse_cli(&args(&["--num_summed=4"]), 3, 1, 31, None).unwrap_err();
    assert!(
        error.contains("--num_summed") && error.contains("--help"),
        "{error}"
    );
}

#[test]
fn both_modes_reject_thresholds_the_share_manager_cannot_use() {
    for default_num_summed in [None, Some(50)] {
        // Old parser accepted 1 or 2 parties and a threshold lower than
        // (n-1)/2, but ShareManager rejected them after example setup.
        for n in [1_usize, 2] {
            let error =
                trbfv::parse_cli(&args(&[]), n, (n - 1) / 2, 31, default_num_summed).unwrap_err();
            assert!(error.contains("at least 3"), "{error}");
        }
        let error = trbfv::parse_cli(
            &args(&["--num_parties=5", "--threshold=1"]),
            5,
            2,
            31,
            default_num_summed,
        )
        .unwrap_err();
        assert!(
            error.contains("exactly (num_parties - 1) / 2 = 2"),
            "{error}"
        );

        let valid = trbfv::parse_cli(
            &args(&["--num_parties=5", "--threshold=2"]),
            5,
            2,
            31,
            default_num_summed,
        )
        .unwrap();
        assert_eq!((valid.num_parties, valid.threshold), (5, 2));
    }
}

#[test]
fn parser_rejects_mismatched_thresholds_and_malformed_flags() {
    for (parties, threshold) in [(7_usize, 2_usize), (10, 3), (20, 10)] {
        let error = trbfv::parse_cli(
            &args(&[
                &format!("--num_parties={parties}"),
                &format!("--threshold={threshold}"),
            ]),
            parties,
            (parties - 1) / 2,
            31,
            Some(50),
        )
        .unwrap_err();
        assert!(error.contains(&((parties - 1) / 2).to_string()), "{error}");
    }

    for (flag, expected) in [
        ("--parties=5", "Unrecognized argument"),
        ("--num_parties", "Invalid argument"),
        ("--num_parties=abc", "Invalid `--num_parties` argument"),
    ] {
        let error = trbfv::parse_cli(&args(&[flag]), 5, 2, 31, Some(50)).unwrap_err();
        assert!(error.contains(expected), "{flag}: {error}");
    }
}

#[test]
fn help_text_matches_both_modes_and_manager_constraints() {
    let addition = trbfv::usage_line(true);
    let multiplication = trbfv::usage_line(false);
    assert!(addition.starts_with("[-h|--help]"));
    assert!(addition.contains("[--num_summed=N]"));
    assert!(!multiplication.contains("--num_summed"));
    for usage in [&addition, &multiplication] {
        for flag in ["[--num_parties=N]", "[--threshold=T]", "[--lambda=L]"] {
            assert!(usage.contains(flag));
        }
    }
    for constraint in ["N >= 3", "T = (N-1)/2", "L >= 1"] {
        assert!(trbfv::CONSTRAINTS_LINE.contains(constraint));
    }
}
