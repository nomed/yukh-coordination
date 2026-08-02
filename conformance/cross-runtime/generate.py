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
IDS={name:f"01989f0e-56b7-7001-815e-a7748f7f{value:04x}" for value,name in enumerate(["claim_a","claim_b","event_a","event_b","release_b","offer","handoff","accept","instance_a","instance_b","receipt","offer2","handoff2","accept2","review","verify"],1)}

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
 offer2=event("offer2","handoff_offer",{**offer["data"],"handoff_id":IDS["handoff2"]},cause=a["id"],corr=a["id"])
 cases["multi-offer"]=transcript([record(a,1),record(offer,2),record(offer2,3)])
 descriptor={"uri":"https://example.test/evidence/1","media_type":"application/json","digest":{"algorithm":"sha-256","value":"2"*64},"declared_size":"128"}
 descriptor_digest="sha-256:"+hashlib.sha256(b"yukh.evidence-descriptor.v0.1\0"+jcs(descriptor)).hexdigest()
 review=event("review","review_request",{"subject":"Evidence","criteria":["digest"],"evidence_set_digest":"sha-256:"+"4"*64,"independence_required":True}); review["evidence"]=[descriptor]
 for outcome in ["verified","mismatch","unavailable","unauthorized","inconclusive"]:
  verify=event("verify","evidence_verification",{"referenced_event_id":review["id"],"descriptor_digest":descriptor_digest,"uri":descriptor["uri"],"algorithm":"sha-256","expected_digest":"sha-256:"+descriptor["digest"]["value"],"outcome":outcome,"method":"GET","verified_at":TS,"verifier_policy_version":"v1"},cause=review["id"],corr=review["id"])
  if outcome in {"verified","mismatch"}: verify["data"]["observed_digest"]="sha-256:"+("2" if outcome=="verified" else "3")*64
  else: verify["data"]["reason"]=outcome
  cases[f"evidence-{outcome}"]=transcript([record(review,1),record(verify,2)])
  if outcome=="verified": verified_event=json.loads(json.dumps(verify))
 for field,value in [("descriptor_digest","sha-256:"+"9"*64),("uri","https://example.test/wrong"),("algorithm","sha-512"),("expected_digest","sha-256:"+"9"*64)]:
  invalid=json.loads(json.dumps(verified_event)); invalid["data"][field]=value; invalid_record=record(invalid,2)
  cases[f"evidence-invalid-{field.replace('_','-')}"]=transcript([record(review,1),invalid_record])
 duplicate=record(a,1); cases["exact-duplicate"]={**transcript([duplicate,duplicate]),"high_water_sequence":1}
 changed=json.loads(json.dumps(a)); changed["data"]["boundary"]="changed"; cases["event-id-collision"]={**transcript([record(a,1),record(changed,1)]),"high_water_sequence":1}
 changed_receipt=json.loads(json.dumps(record(a,1))); changed_receipt["receipt"]["cursor"]="changed"; cases["changed-duplicate-receipt"]={**transcript([record(a,1),changed_receipt]),"high_water_sequence":1}
 cases["sequence-collision"]={**transcript([record(a,1),record(b,1,IDS["instance_b"])]),"high_water_sequence":1}
 wrong_recipient=json.loads(json.dumps(accept)); cases["cas-wrong-recipient"]=transcript([record(a,1),record(offer,2),record(wrong_recipient,3,IDS["instance_a"])])
 changed_boundary=json.loads(json.dumps(accept)); changed_boundary["data"]["boundary_digest"]="sha-256:"+"9"*64; cases["cas-changed-boundary"]=transcript([record(a,1),record(offer,2),record(changed_boundary,3,IDS["instance_b"])])
 accept2=event("accept2","handoff_accept",accept["data"],"session:b",offer["id"],a["id"]); cases["cas-second-acceptance"]=transcript([record(a,1),record(offer,2),record(accept,3,IDS["instance_b"]),record(accept2,4,IDS["instance_b"])])
 unverified=json.loads(json.dumps(record(a,1))); unverified["receipt_verified"]=False; cases["unverified-receipt"]=transcript([unverified])
 cases["sequence-gap"]={**transcript([record(a,1),record(offer,3)]),"high_water_sequence":3,"declared_completeness":"incomplete"}
 cases["unverified-high-water"]={**transcript([record(a,1)]),"high_water_receipt_verified":False}
 outcomes={
  "multi-offer":{"python":{"kind":"error","code":"INVALID_REFERENCE"},"javascript":{"kind":"projection","final":True,"reasons":[]}},
  "evidence-invalid-descriptor-digest":{"python":{"kind":"error","code":"INVALID_REFERENCE"},"javascript":{"kind":"projection","final":True,"reasons":[]}},
  "evidence-invalid-uri":{"python":{"kind":"error","code":"INVALID_PAYLOAD"},"javascript":{"kind":"projection","final":True,"reasons":[]}},
  "evidence-invalid-algorithm":{"python":{"kind":"error","code":"INVALID_PAYLOAD"},"javascript":{"kind":"projection","final":True,"reasons":[]}},
  "evidence-invalid-expected-digest":{"python":{"kind":"error","code":"INVALID_PAYLOAD"},"javascript":{"kind":"projection","final":True,"reasons":[]}},
  "event-id-collision":{"python":{"kind":"error","code":"ID_COLLISION"},"javascript":{"kind":"projection","final":False,"reasons":["event-id-collision","sequence-collision"]}},
  "changed-duplicate-receipt":{"python":{"kind":"error","code":"INVALID_RECEIPT"},"javascript":{"kind":"projection","final":False,"reasons":["sequence-collision"]}},
  "sequence-collision":{"python":{"kind":"error","code":"INVALID_RECEIPT"},"javascript":{"kind":"projection","final":False,"reasons":["sequence-collision"]}},
  "cas-wrong-recipient":{"python":{"kind":"error","code":"INVALID_HANDOFF_PARTICIPANT"},"javascript":{"kind":"projection","final":False,"reasons":["handoff-precondition-failed"]}},
  "cas-changed-boundary":{"python":{"kind":"error","code":"HANDOFF_PRECONDITION_FAILED"},"javascript":{"kind":"projection","final":False,"reasons":["handoff-precondition-failed"]}},
  "cas-second-acceptance":{"python":{"kind":"error","code":"HANDOFF_PRECONDITION_FAILED"},"javascript":{"kind":"projection","final":False,"reasons":["handoff-precondition-failed"]}},
  "unverified-receipt":{"python":{"kind":"projection","final":True,"reasons":[]},"javascript":{"kind":"projection","final":False,"reasons":["unverified-receipt"]}},
  "unverified-high-water":{"python":{"kind":"projection","final":True,"reasons":[]},"javascript":{"kind":"projection","final":False,"reasons":["unverified-high-water"]}}
 }
 index=[]
 for name,value in cases.items():
  path=HERE/"cases"/f"{name}.json"; write(path,value); row={"name":name,"path":str(path.relative_to(ROOT)),"work_uri":WORK,"mode":"runtime-outcomes" if name in outcomes else "projection-equal"}
  if name in outcomes: row["expected"]=outcomes[name]
  index.append(row)
 write(HERE/"cases/index.json",index)

if __name__=="__main__": main()
