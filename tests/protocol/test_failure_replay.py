#!/usr/bin/env python3
"""Local intentional-failure fixture: verify saved LE32 input replays SIGABRT."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from validate_bacnet import replay_records
ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'tests/protocol/evidence/failure-replay'

def port():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    WORK.mkdir(parents=True,exist_ok=False)
    server=WORK/'failure_server'
    env=dict(os.environ,AFL_PATH=str(ROOT),AFL_NO_UI='1',AFL_NO_AFFINITY='1',AFL_SKIP_CPUFREQ='1',AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1')
    build=[str(ROOT/'afl-clang-fast'),'-O1','-g',str(ROOT/'tests/protocol/fixtures/failure_server.c'),'-o',str(server)]
    with (WORK/'build.log').open('w') as log:subprocess.run(build,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    corpus=WORK/'in';corpus.mkdir()
    (corpus/'whois').write_bytes((ROOT/'protocols/bacnet_ip/seeds/who_is.replay').read_bytes())
    command=['setarch',os.uname().machine,'-R',str(ROOT/'afl-fuzz'),'-d','-i',str(corpus),'-o',str(WORK/'out'),'-N',f'udp://127.0.0.1/{port()}','-D','20000','-W','5','-r','5','-w','1000','-K','-m','none','-t','1000','--protocol-spec',str(ROOT/'protocols/bacnet_ip/protocol_ir.json'),'--state-spec',str(ROOT/'protocols/bacnet_ip/state_ir.json'),'--mutation-mode','near_valid','--mutation-layers','head','--',str(server)]
    command.append(command[command.index('-N')+1].rsplit('/',1)[1])
    (WORK/'command.json').write_text(json.dumps(command,indent=2)+'\n')
    logpath=WORK/'fuzz.log';started=time.monotonic()
    with logpath.open('w') as log:
        child=subprocess.Popen(command,cwd=WORK,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            while child.poll() is None and time.monotonic()-started<90:
                if list((WORK/'out/replayable-crashes').glob('id*')):break
                time.sleep(.1)
            if child.poll() is None:child.send_signal(signal.SIGINT)
            status=child.wait(timeout=15)
        finally:
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()
    saved=sorted((WORK/'out/replayable-crashes').glob('id*'))
    assert status==0 and saved,(status,logpath.read_text(errors='replace'))
    records,framing=replay_records(saved[0].read_bytes())
    assert framing=='LE32-length-prefixed' and all(int.from_bytes(b[2:4],'big')==len(b)+1 for b in records)
    replay_port=port()
    with (WORK/'replay-server.log').open('w') as log:
        receiver=subprocess.Popen([str(server),str(replay_port)],cwd=WORK,env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            time.sleep(.15)
            replay_command=[str(ROOT/'aflnet-replay'),str(saved[0]),'BACNET',str(replay_port),'20','1000']
            response=subprocess.run(replay_command,cwd=WORK,env=env,capture_output=True,timeout=10)
            (WORK/'replay-client.log').write_bytes(response.stdout+response.stderr)
            replay_status=receiver.wait(timeout=5)
        finally:
            if receiver.poll() is None:receiver.terminate();receiver.wait(timeout=5)
    assert replay_status==-signal.SIGABRT,replay_status
    result={'passed':True,'fixture':'intentional local assertion; not a BACnet Stack failure','fuzzer_exit':status,'saved_crashes':len(saved),'replayed_file':saved[0].name,'replay_command':replay_command,'replay_client_exit':response.returncode,'replay_server_signal':-replay_status,'messages':len(records),'framing':framing,'intentional_constraint':'BVLC declared length is actual length plus one'}
    (WORK/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
