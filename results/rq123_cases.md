# RQ1–RQ3 synthetic authority slice

**Status:** 25 reviewed labels; 0 proposed. RQ1 manual vetting and asset namespace are assumptions.
Asset hashes bind a declared snapshot; no live asset-control proof or tool effect.

| ID | Mutation | Expected | Actual | Match |
| --- | --- | --- | --- | --- |
| AA01 | senior_1_asset_a | Accept | Accept | true |
| AA02 | senior_2_asset_b_same_junior | Accept | Accept | true |
| AA03 | cto_registers_asset_a | Accept | Accept | true |
| AA04 | unrecognized_root_signs_first_edge | Reject / RootNotPinned | Reject / RootNotPinned | true |
| AA05 | request_signed_by_wrong_key | Reject / InvalidSignature | Reject / InvalidSignature | true |
| AA06 | junior_edge_parent_points_to_other_senior | Reject / PathMismatch | Reject / PathMismatch | true |
| AA07 | junior_scope_expands_beyond_senior | Reject / DelegationAmplifies | Reject / DelegationAmplifies | true |
| AA08 | asset_b_requested_under_asset_a_path | Reject / AssetOutsideScope | Reject / AssetOutsideScope | true |
| AA09 | record_issuer_lacks_registration_right | Reject / RecordIssuerUnauthorized | Reject / RecordIssuerUnauthorized | true |
| AA10 | record_digest_not_manifest_digest | Reject / SnapshotDigestMismatch | Reject / SnapshotDigestMismatch | true |
| AA11 | manifest_changed_after_record_signing | Reject / SnapshotDigestMismatch | Reject / SnapshotDigestMismatch | true |
| AA12 | senior_edge_expired | Reject / Expired | Reject / Expired | true |
| AA13 | senior_edge_revoked | Reject / Revoked | Reject / Revoked | true |
| AA14 | asset_record_status_missing | Indeterminate / StatusUnknown | Indeterminate / StatusUnknown | true |
| AA15 | request_targets_wrong_provider | Reject / WrongAudience | Reject / WrongAudience | true |
| AA16 | request_claims_different_user_id | Reject / UserMismatch | Reject / UserMismatch | true |
| AA17 | request_uses_record_from_other_path | Reject / PathMismatch | Reject / PathMismatch | true |
| AA18 | unrelated_senior_revoked_other_path_still_valid | Accept | Accept | true |
| AA19 | junior_class_expands_beyond_senior | Reject / DelegationAmplifies | Reject / DelegationAmplifies | true |
| AA20 | record_asset_outside_registrar_scope | Reject / AssetOutsideScope | Reject / AssetOutsideScope | true |
| AA21 | clock_uncertainty_overlaps_record_expiry | Indeterminate / ClockUncertainty | Indeterminate / ClockUncertainty | true |
| AA22 | status_source_unavailable | Indeterminate / StatusUnavailable | Indeterminate / StatusUnavailable | true |
| AA23 | modified_request_payload_keeps_original_signature | Reject / InvalidSignature | Reject / InvalidSignature | true |
| AA24 | malformed_noncanonical_manifest | Reject / MalformedInput | Reject / MalformedInput | true |
| AA25 | foreign_signed_record_and_request_on_other_path | Reject / PathMismatch | Reject / PathMismatch | true |
