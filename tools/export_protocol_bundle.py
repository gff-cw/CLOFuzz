#!/usr/bin/env python3
"""Validate and export the six scoped description packages and shared templates."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tempfile
import zipfile
from init_protocol_spec import PROFILES
from proto_spec_compiler import compile_spec, load, SpecError

ROOT=Path(__file__).resolve().parents[1]


def build_bundle(destination):
    destination=Path(destination)
    packages=[]
    files={}
    for name in PROFILES:
        directory=ROOT/'protocols'/name
        protocol=load(directory/'protocol_spec.yaml')
        state=load(directory/'state_transition.yaml')
        with tempfile.TemporaryDirectory(prefix='protocol-export-check-') as temporary:
            result=compile_spec(protocol,state,temporary)
            for filename in ('protocol_ir.json','state_ir.json','validation.json'):
                if (Path(temporary)/filename).read_bytes()!=(directory/filename).read_bytes():
                    raise SpecError(f'{name}: stale {filename}; regenerate before export')
        packages.append(dict(protocol_id=protocol['protocol_id'],name=protocol['name'],
            scope=protocol['scope'],runtime=result['runtime'],messages=result['messages'],
            fields=result['fields'],semantic_states=result['semantic_states'],
            all_fixtures_complete=all(m.get('fixture_status')=='complete' for m in protocol['messages'])))
        for path in sorted(directory.rglob('*')):
            if path.is_file():files[str(path.relative_to(ROOT))]=path.read_bytes()
    for directory in (ROOT/'protocols/schema',ROOT/'protocols/templates'):
        for path in sorted(directory.rglob('*')):
            if path.is_file():files[str(path.relative_to(ROOT))]=path.read_bytes()
    for name in ('README.md','protocols/README.md','docs/protocol-model-audit.md','docs/template-audit.md',
                 'docs/protocol-description-language.md','docs/architecture.md','docs/references.md',
                 'docs/bacnet-controlled-results.md','docs/controlled-experiment-design.md',
                 'tools/generate_protocol_models.py','tools/protocol_model_details.py',
                 'tools/native_protocol_codecs.py','protocol_codecs.h',
                 'protocol_codec_modbus.c','protocol_codec_iec104.c','protocol_codec_mms.c',
                 'protocol_codec_enip.c','protocol_codec_opcua.c',
                 'tests/protocol/test_model_completeness.py','tools/proto_spec_compiler.py',
                 'tools/init_protocol_spec.py','tools/run_protocol_campaign.py','tools/requirements-protocol.txt'):
        files[name]=(ROOT/name).read_bytes()
    files['BUNDLE-README.md']=('''# Industrial protocol description bundle

Six scoped ICP-IR v1 packages, editable templates, schemas, deterministic generators and offline validators.
Complete fixture means complete wire message inside the declared profile, not all services of each standard.
See protocols/README.md for the twelve YAML entry files and actual runtime support.

From the extracted directory: install tools/requirements-protocol.txt, then run
`python3 tests/protocol/test_model_completeness.py` for independent deep structure checks.
The StateAFL source/build and BACnet server are not bundled; use the project workspace for live mutation.
All six declared profiles have scoped C codecs. Non-BACnet compilation checks
build the bundled codecs with a C11 compiler (CC or cc) in a private temporary
directory. This does not run Python inside StateAFL's mutation loop.
MANIFEST.json contains SHA-256 of every bundled content file.
''').encode()
    manifest=dict(bundle_version=1,format='ICP-IR v1',profiles=packages,
        completeness='Complete messages within each explicitly declared profile; not whole-standard coverage.',
        runtime_scope='Six bounded C codecs; see each profile for supported services and external prerequisites.',
        files={name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())})
    files['MANIFEST.json']=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(files.items()):
            entry=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED;entry.external_attr=0o100644<<16
            archive.writestr(entry,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(output.getvalue())
    return dict(path=str(destination),sha256=hashlib.sha256(output.getvalue()).hexdigest(),
                files=len(files),profiles=packages)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:print(json.dumps(build_bundle(args.output),ensure_ascii=False,indent=2))
    except (OSError,SpecError) as error:parser.exit(1,f'protocol export error: {error}\n')
