#!/usr/bin/env python3
"""File-only provenance regressions; never invoke the acceptance controller."""
import hashlib
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name('run_live.py')
SPEC = importlib.util.spec_from_file_location('generic_wire_evidence_controller', MODULE_PATH)
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def snapshot(sha256='a', present=True, stable=True, resolved_path='/local/input'):
    result = {'present': present}
    if present:
        result.update(sha256=sha256, resolved_path=resolved_path, stable_during_read=stable)
    return result


def stat_result(mtime_ns=1):
    return SimpleNamespace(st_dev=1, st_ino=2, st_size=4,
                           st_mtime_ns=mtime_ns, st_ctime_ns=mtime_ns)


class EvidenceProvenanceTests(unittest.TestCase):
    def test_stable_file_records_content_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'example')
            result = CONTROLLER.file_snapshot(path)
        self.assertTrue(result['present'])
        self.assertTrue(result['stable_during_read'])
        self.assertEqual(result['size'], 7)
        self.assertEqual(result['sha256'], hashlib.sha256(b'example').hexdigest())

    def test_missing_file_is_unverified_without_claiming_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            result = CONTROLLER.file_snapshot(Path(directory) / 'missing')
        self.assertFalse(result['present'])
        self.assertNotIn('sha256', result)
        self.assertEqual(CONTROLLER.unverified_files({'missing': result}), ['missing'])
        self.assertEqual(CONTROLLER.changed_files({'missing': result}, {'missing': result}), [])

    def test_unreadable_file_keeps_error_and_no_digest(self):
        path = mock.Mock(spec=Path)
        path.is_file.return_value = True
        path.stat.return_value = stat_result()
        path.open.side_effect = PermissionError('read denied')
        result = CONTROLLER.file_snapshot(path)
        self.assertTrue(result['present'])
        self.assertIn('read denied', result['read_error'])
        self.assertNotIn('sha256', result)
        self.assertEqual(CONTROLLER.unverified_files({'input': result}), ['input'])

    def test_unreadable_metadata_is_reported(self):
        path = mock.Mock(spec=Path)
        path.is_file.side_effect = PermissionError('stat denied')
        result = CONTROLLER.file_snapshot(path)
        self.assertFalse(result['present'])
        self.assertIn('stat denied', result['read_error'])
        self.assertEqual(CONTROLLER.unverified_files({'input': result}), ['input'])

    def test_change_during_hash_read_remains_unverified(self):
        path = mock.Mock(spec=Path)
        path.is_file.return_value = True
        path.stat.side_effect = [stat_result(1), stat_result(2)]
        path.open.return_value = io.BytesIO(b'data')
        result = CONTROLLER.file_snapshot(path)
        self.assertEqual(result['sha256'], hashlib.sha256(b'data').hexdigest())
        self.assertFalse(result['stable_during_read'])
        self.assertEqual(CONTROLLER.unverified_files({'input': result}), ['input'])
        self.assertEqual(CONTROLLER.changed_files({'input': result}, {'input': result}), ['input'])

    def test_before_after_content_changes_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'before')
            before = {'input': CONTROLLER.file_snapshot(path)}
            path.write_bytes(b'after')
            after = {'input': CONTROLLER.file_snapshot(path)}
        self.assertEqual(CONTROLLER.changed_files(before, after), ['input'])

    def test_additions_removals_and_resolved_target_changes_are_detected(self):
        before = {'removed': snapshot(), 'moved': snapshot(), 'unchanged': snapshot()}
        after = {'added': snapshot(), 'moved': snapshot(resolved_path='/other/input'),
                 'unchanged': snapshot()}
        self.assertEqual(CONTROLLER.changed_files(before, after), ['added', 'moved', 'removed'])

    def test_unchanged_verified_content_is_not_a_change(self):
        before = {'input': snapshot()}
        self.assertEqual(CONTROLLER.changed_files(before, {'input': snapshot()}), [])
        self.assertEqual(CONTROLLER.unverified_files(before), [])

    def test_missing_artifacts_are_not_reported_as_saved_or_created(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            artifacts = CONTROLLER.artifact_inventory(work, ['candidate'])
            self.assertFalse(any(item['present'] for item in artifacts.values()))
            self.assertFalse(any(item['present_beside_report'] for item in artifacts.values()))
            self.assertEqual(list(work.iterdir()), [])
        self.assertIn('out/protocol-candidates/candidate.json', artifacts)
        self.assertIn('out/protocol-candidates/candidate.replay', artifacts)

    def test_candidate_metadata_does_not_imply_saved_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            metadata = work / 'out/protocol-candidates/candidate.json'
            metadata.parent.mkdir(parents=True)
            metadata.write_text('{}\n', encoding='utf-8')
            artifacts = CONTROLLER.artifact_inventory(work, ['candidate'])
        saved = artifacts['out/protocol-candidates/candidate.json']
        missing = artifacts['out/protocol-candidates/candidate.replay']
        self.assertTrue(saved['present_beside_report'])
        self.assertIn('sha256', saved)
        self.assertFalse(missing['present_beside_report'])
        self.assertNotIn('sha256', missing)
        self.assertEqual(saved['path'], 'out/protocol-candidates/candidate.json')

    def test_external_symlink_is_not_a_preserved_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / 'report-directory'
            work.mkdir()
            external = root / 'external.log'
            external.write_text('external\n', encoding='utf-8')
            (work / 'build.log').symlink_to(external)
            artifact = CONTROLLER.artifact_inventory(work, [])['build.log']
        self.assertTrue(artifact['present'])
        self.assertIn('sha256', artifact)
        self.assertFalse(artifact['present_beside_report'])


if __name__ == '__main__':
    unittest.main()
