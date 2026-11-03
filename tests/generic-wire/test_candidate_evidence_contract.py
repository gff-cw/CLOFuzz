#!/usr/bin/env python3
"""File-only regression source for the real controller's evidence filtering.

Synthetic metadata is used solely as test input, never as acceptance evidence.
No compiler, target, fuzzer, subprocess or socket is invoked by this module.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('candidate_evidence_controller',
                                             Path(__file__).with_name('run_live.py'))
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)
EXAMPLE = bytes.fromhex('a700050100015566')


class CandidateEvidenceContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def capture(self, stem='sample', packets=None, **overrides):
        packets = packets or [EXAMPLE]
        sidecar = dict(format_version=3, run_id='test-only', segment_id=0,
                       candidate_id=1, exec_id=7, purpose='coverage', structured=True,
                       planned_messages=len(packets), attempted_messages=len(packets),
                       sent_messages=len(packets), submitted_records=len(packets),
                       total_bytes_sent=sum(map(len, packets)), partial_bytes_tail=0,
                       is_transmission_complete=True, is_response_complete=True,
                       response_budget_exceeded=False, parent_seed_id=0,
                       target_state=0, layer='HEAD', forkserver='coverage')
        sidecar.update(overrides)
        (self.directory / f'{stem}.json').write_text(json.dumps(sidecar))
        (self.directory / f'{stem}.replay').write_bytes(
            b''.join(len(packet).to_bytes(4, 'little') + packet for packet in packets))
        return sidecar

    def feedback(self, **overrides):
        item = dict(event='layer_feedback', run_id='test-only', segment_id=0,
                    candidate_id=1, exec_id=7, layer_id=1, memory_state_id=0,
                    discoveries=16, new_tuples=1, new_buckets=0)
        item.update(overrides)
        return item

    def evidence(self, feedback=None):
        return CONTROLLER.candidate_evidence(self.directory, EXAMPLE, feedback or [])

    def test_layer_label_without_wire_edit_is_not_edit_evidence(self):
        self.capture()
        evidence = self.evidence([self.feedback()])
        self.assertFalse(evidence['errors'])
        self.assertEqual(evidence['matched_feedback_count'], 1)
        self.assertFalse(any(evidence['edit_samples'].values()))

    def test_actual_head_content_and_sequence_edits_require_their_own_layer(self):
        head = EXAMPLE[:4] + b'\x00\x02' + EXAMPLE[6:]
        content = EXAMPLE[:6] + b'\x99\x66'
        self.capture('head', [head])
        self.capture('content', [content], candidate_id=2, exec_id=8, layer='CONTENT')
        self.capture('sequence', [EXAMPLE, EXAMPLE], candidate_id=3, exec_id=9, layer='SEQUENCE')
        evidence = self.evidence([self.feedback(),
                                  self.feedback(candidate_id=2, exec_id=8, layer_id=2),
                                  self.feedback(candidate_id=3, exec_id=9, layer_id=4)])
        self.assertFalse(evidence['errors'])
        self.assertTrue(all(evidence['edit_samples'].values()))

    def test_missing_purpose_and_legacy_schema_cannot_default_to_coverage(self):
        self.capture('missing', purpose=None)
        self.capture('legacy', format_version=2, candidate_id=2, exec_id=8)
        evidence = self.evidence([self.feedback()])
        self.assertEqual(len(evidence['errors']), 2)
        self.assertFalse(evidence['candidates'])

    def test_partial_diagnostic_is_excluded_before_valid_wire_parsing(self):
        self.capture(is_transmission_complete=False, partial_bytes_tail=2,
                     sent_messages=0, packets=[b'xx'])
        evidence = self.evidence([self.feedback()])
        self.assertFalse(evidence['errors'])
        self.assertFalse(evidence['candidates'])
        self.assertEqual(evidence['excluded_captures'][0]['reason'], 'incomplete execution')

    def test_complete_flag_cannot_hide_missing_planned_records(self):
        self.capture(planned_messages=2)
        evidence = self.evidence([self.feedback()])
        self.assertTrue(evidence['errors'])
        self.assertFalse(evidence['candidates'])

    def test_replay_bytes_must_match_submitted_counts(self):
        self.capture(total_bytes_sent=99)
        self.assertTrue(self.evidence([self.feedback()])['errors'])

    def test_confirmation_and_changed_exec_id_do_not_join_original_feedback(self):
        self.capture('replay', purpose='confirmation')
        self.capture('original', exec_id=8)
        evidence = self.evidence([self.feedback()])
        self.assertEqual(evidence['matched_feedback_count'], 0)
        self.assertFalse(evidence['coverage_discovery_samples'])
        self.assertEqual(evidence['samples_without_matching_feedback'], ['original'])

    def test_duplicate_capture_or_feedback_identity_is_rejected(self):
        self.capture('one')
        self.capture('duplicate')
        evidence = self.evidence([self.feedback()])
        self.assertTrue(evidence['errors'])
        self.assertFalse(evidence['candidates'])
        (self.directory / 'duplicate.json').unlink()
        evidence = self.evidence([self.feedback(), self.feedback()])
        self.assertTrue(evidence['errors'])
        self.assertEqual(evidence['matched_feedback_count'], 0)

    def test_nonzero_entry_requires_matching_layer_and_state_feedback(self):
        self.capture(target_state=42, parent_seed_id=3)
        evidence = self.evidence([self.feedback(memory_state_id=42)])
        self.assertEqual(evidence['nonzero_target_samples'], ['sample'])
        self.assertFalse(any(evidence['edit_samples'].values()))
        evidence = self.evidence([self.feedback(memory_state_id=0)])
        self.assertTrue(evidence['errors'])
        self.assertFalse(evidence['nonzero_target_samples'])

    def test_unexecuted_candidate_must_have_zero_credit(self):
        self.assertTrue(self.evidence([self.feedback(exec_id=0)])['errors'])
        evidence = self.evidence([self.feedback(exec_id=0, discoveries=0, new_tuples=0)])
        self.assertFalse(evidence['errors'])
        self.assertEqual(evidence['unjoined_feedback_count'], 1)


if __name__ == '__main__':
    unittest.main()
