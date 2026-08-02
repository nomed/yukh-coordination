#!/usr/bin/env python3
"""Generate common replay transcripts consumed by both runtime adapters."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]
sys.dont_write_bytecode=True; sys.path.insert(0,str(ROOT/"conformance"))
from validate import jcs  # noqa: E402

CHANNEL="https://coord.example/channels/cross-runtime"; WORK="https://example.test/issues/42"; TS="2026-08-02T16:00:00.000Z"
IDS={name:f"01989f0e-56b7-7001-815e-a7748f7f{value:04x}" for value,name in enumerate(["claim_a","claim_b","event_a","event_b","release_b","offer","handoff","accept","instance_a","instance_b","receipt"],1)}

def write(path,value): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
def event(name,typ,data,participant="session:a",cause=None,corr=None):
 return {"specversion":"0.1","id":IDS[name],"type":typ,"channel":CHANNEL,"source":"urn:yukh:cross-runtime","participant":{"id":participant,"kind":"session"},"work":{"uri":WORK},"time":TS,"correlation_id":corr or IDS[name],**({"causation_id":cause} if cause else {}),"data":data,"evidence":[],"extensions":{}}
def receipt(ev,sequence,instance=IDS["instance_a"]):
 digest="sha-256:"+hashlib.sha256(jcs(ev)).hexdigest()
 return {"specversion":"0.1","receipt_version":"0.1","receipt_id":f"01989f0e-56b7-7001-915e-a7748f7f{0x100+sequence:04x}","event_id":ev["id"],"tenant_id":"tenant:example","channel_id":"channel:cross-runtime","channel_uri":CHANNEL,"principal_id":"principal:fixture","participant_id":ev["participant"]["id"],"participant_instance_id":instance,"session_epoch":1,"cursor":f"cursor-{sequence}","transcript_epoch":0,"sequence":sequence,"accepted_at":TS,"event_digest":digest,"channel_metadata_digest":"sha-256:"+"1"*64,"acl_policy_version":"acl-v1","acl_policy_digest":"sha-256:"+"2"*64,"acl_decision_receipt_id":f"decision-{sequence}","append_outcome":"appended","key_id":"key-1","signature_algorithm":"ed25519","signature":"A"*86}
def record(ev,sequence,instance=IDS["instance_a"]): return {"event":ev,"receipt":receipt(ev,sequence,instance),"receipt_verified":True}
def transcript(records,*,completeness="complete",lifecycle="active"):
 return {"specversion":"0.1","metadata":{"tenant_id":"tenant:example","channel_id":"channel:cross-runtime","channel_uri":CHANNEL},"transcript_epoch":0,"declared_completeness":completeness,"lifecycle":lifecycle,"origin_sequence":1,"high_water_sequence":len(records),"high_water_receipt_verified":True,"records":records}

def main():
 a=event("event_a","claim",{"claim_id":IDS["claim_a"],"generation":"0","scope":"implementation","boundary":"A","expected_active_claims":[]})
 b=event("event_b","claim",{"claim_id":IDS["claim_b"],"generation":"0","scope":"review","boundary":"B","expected_active_claims":[]},"session:b")
 release=event("release_b","release",{"claim_id":IDS["claim_b"],"generation":"0","parent_claim_event_id":b["id"],"outcome":"withdrawn"},"session:b",b["id"],b["id"])
 offer=event("offer","handoff_offer",{"handoff_id":IDS["handoff"],"claim_id":IDS["claim_a"],"generation":"0","parent_claim_event_id":a["id"],"to_participant_instance_id":IDS["instance_b"],"boundary":"A","boundary_digest":"sha-256:"+"3"*64,"evidence_set_digest":"sha-256:"+"4"*64,"next_action":"continue","unresolved_risks":[]},cause=a["id"],corr=a["id"])
 accept=event("accept","handoff_accept",{"handoff_id":IDS["handoff"],"offer_event_id":offer["id"],"source_claim_event_id":a["id"],"claim_id":IDS["claim_a"],"generation":"0","boundary_digest":"sha-256:"+"3"*64,"evidence_set_digest":"sha-256:"+"4"*64},"session:b",offer["id"],a["id"])
 cases={
  "claim":transcript([record(a,1)]),
  "conflict-release":transcript([record(a,1),record(b,2,IDS["instance_b"]),record(release,3,IDS["instance_b"])]),
  "handoff-incomplete-lifecycle":transcript([record(a,1),record(offer,2),record(accept,3,IDS["instance_b"])],completeness="incomplete",lifecycle="redacted")}
 index=[]
 for name,value in cases.items():
  path=HERE/"cases"/f"{name}.json"; write(path,value); index.append({"name":name,"path":str(path.relative_to(ROOT)),"work_uri":WORK})
 write(HERE/"cases/index.json",index)

if __name__=="__main__": main()
