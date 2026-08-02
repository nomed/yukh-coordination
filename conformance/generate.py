#!/usr/bin/env python3
"""Generate the frozen v0.1 core corpus deterministically."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from validate import jcs

ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/"conformance"; FIX=OUT/"fixtures"; CAN=OUT/"canonical"
U=[f"01989f0e-56b7-7e01-915e-a7748f7f62{i:02x}" for i in range(1,40)]
TS="2026-08-02T16:00:00.000Z"; LATER="2026-08-02T16:05:00.000Z"; CH="https://coord.example/channels/project-release"; WORK="https://github.com/nomed/yukh-coordination/issues/4"
DIG="sha-256:"+"1"*64

def write(path,value): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
def evidence(): return {"uri":"https://example.test/evidence/1","media_type":"application/json","digest":{"algorithm":"sha-256","value":"2"*64},"declared_size":"128","revision":"rev-1"}
def event(i,typ,data,*,work=True,corr=None,cause=None,ev=None):
 d={"specversion":"0.1","id":U[i],"type":typ,"channel":CH,"source":"urn:yukh:source:fixture","participant":{"id":"session:fixture","kind":"session","display":"fixture"},"time":TS,"data":data,"evidence":ev or [],"extensions":{}}
 if work:d["work"]={"uri":WORK}
 if corr:d["correlation_id"]=corr
 if cause:d["causation_id"]=cause
 return d

def build_events():
 claim=event(3,"claim",{"claim_id":U[20],"generation":"1","scope":"implementation","boundary":"Café, e\u0301, 😀 — core fixture corpus","expected_active_claims":[]},corr=U[3])
 question=event(5,"question",{"body":"Are canonical bytes stable?","requested_from":[],"response_required":True},corr=U[5])
 review=event(7,"review_request",{"subject":"Core corpus","criteria":["All fixtures classify"],"evidence_set_digest":DIG,"independence_required":True},corr=U[7],ev=[evidence()])
 offer=event(9,"handoff_offer",{"handoff_id":U[21],"claim_id":U[20],"generation":"1","parent_claim_event_id":U[3],"to_participant_instance_id":U[22],"boundary":"Continue corpus","boundary_digest":DIG,"evidence_set_digest":DIG,"next_action":"Run validator","unresolved_risks":[]},corr=U[3],cause=U[3])
 return {
 "join":event(0,"join",{"protocol_versions":["0.1"],"capabilities":["publish","replay"],"status":"available"},work=False),
 "presence":event(1,"presence",{"status":"available","observed_at":TS,"valid_until":LATER},work=False),
 "leave":event(2,"leave",{"reason":"complete"},work=False),
 "claim":claim,
 "progress":event(4,"progress",{"claim_id":U[20],"generation":"1","parent_claim_event_id":U[3],"status":"in_progress","summary":"Generating fixtures","completed":[],"remaining":["manifest"],"blocked_by":[]},corr=U[3],cause=U[3]),
 "question":question,
 "answer":event(6,"answer",{"question_event_id":U[5],"body":"Yes.","disposition":"answered"},corr=U[5],cause=U[5]),
 "review_request":review,
 "verdict":event(8,"verdict",{"review_event_id":U[7],"evidence_set_digest":DIG,"outcome":"pass","summary":"Conforms","findings":[],"reviewer_independent":True},corr=U[7],cause=U[7],ev=[evidence()]),
 "handoff_offer":offer,
 "handoff_accept":event(10,"handoff_accept",{"handoff_id":U[21],"offer_event_id":U[9],"source_claim_event_id":U[3],"claim_id":U[20],"generation":"1","boundary_digest":DIG,"evidence_set_digest":DIG},corr=U[3],cause=U[9]),
 "release":event(11,"release",{"claim_id":U[20],"generation":"1","parent_claim_event_id":U[3],"outcome":"completed","reason":"done"},corr=U[3],cause=U[3]),
 "evidence_verification":event(12,"evidence_verification",{"referenced_event_id":U[7],"descriptor_digest":DIG,"uri":"https://example.test/evidence/1","algorithm":"sha-256","expected_digest":"sha-256:"+"2"*64,"observed_digest":"sha-256:"+"2"*64,"outcome":"verified","method":"HTTP GET","verified_at":TS,"verifier_policy_version":"v1"},corr=U[7],cause=U[7])}

def receipt(event_id): return {"specversion":"0.1","receipt_version":"0.1","receipt_id":U[30],"event_id":event_id,"tenant_id":"tenant:example","channel_id":"channel:release","channel_uri":CH,"principal_id":"principal:fixture","participant_id":"session:fixture","participant_instance_id":U[31],"session_epoch":1,"cursor":"cursor-1","transcript_epoch":0,"sequence":1,"accepted_at":TS,"event_digest":DIG,"channel_metadata_digest":DIG,"acl_policy_version":"acl-v1","acl_policy_digest":DIG,"acl_decision_receipt_id":"decision-1","append_outcome":"appended","key_id":"key-1","signature_algorithm":"ed25519","signature":"A"*86}

def main():
 for p in (FIX,CAN):
  if p.exists(): shutil.rmtree(p)
 events=build_events(); index=[]
 for name,obj in events.items():
  rel=f"conformance/fixtures/positive/event-{name}.json"; write(ROOT/rel,obj); index.append({"path":rel,"schema":"schema/envelope-0.1.schema.json","valid":True})
 # One closed-schema missing-required negative for every signal payload.
 for name,obj in events.items():
  bad=json.loads(json.dumps(obj)); payload_schema=json.loads((ROOT/f"schema/payloads/{name}-0.1.schema.json").read_text()); field=payload_schema.get("required",[])[0] if payload_schema.get("required") else "unexpected"
  if field=="unexpected": bad["data"][field]=True
  else: bad["data"].pop(field,None)
  rel=f"conformance/fixtures/negative/event-{name}-payload.json"; write(ROOT/rel,bad); index.append({"path":rel,"schema":"schema/envelope-0.1.schema.json","valid":False,"reason":"INVALID_PAYLOAD"})
 extras={
  "root-correlation":lambda x:x.update(correlation_id=U[19]),
  "child-causation":lambda x:x.update(causation_id=U[19]),
  "presence-expiry":lambda x:x["data"].update(valid_until=TS),
  "number-extension":lambda x:x["extensions"].update({"example.test":1}),
  "work-on-join":lambda x:x.update(work={"uri":WORK}),
  "missing-work":lambda x:x.pop("work"),
  "bad-time":lambda x:x.update(time="2026-08-02T16:00:00Z"),
  "bad-id":lambda x:x.update(id="not-a-uuid"),
  "verification-reason":lambda x:x["data"].update(reason="forbidden")}
 bases={"root-correlation":"claim","child-causation":"answer","presence-expiry":"presence","number-extension":"claim","work-on-join":"join","missing-work":"claim","bad-time":"claim","bad-id":"claim","verification-reason":"evidence_verification"}
 for name,mutate in extras.items():
  bad=json.loads(json.dumps(events[bases[name]])); mutate(bad); rel=f"conformance/fixtures/negative/{name}.json"; write(ROOT/rel,bad); index.append({"path":rel,"schema":"schema/envelope-0.1.schema.json","valid":False,"reason":"SEMANTIC_OR_SCHEMA"})
 full=json.loads(json.dumps(events["answer"])); full["unexpected_14th_property"]="rejected"; rel="conformance/fixtures/negative/event-14-properties.json"; write(ROOT/rel,full); index.append({"path":rel,"schema":"schema/envelope-0.1.schema.json","valid":False,"reason":"INVALID_ENVELOPE"})
 meta={
  "channel":({"specversion":"0.1","tenant_id":"tenant:example","channel_uri":CH,"channel_id":"channel:release","acl_policy_version":"acl-v1","acl_policy_digest":DIG,"retention_policy_digest":DIG,"retention_epoch":0,"created_at":TS},"schema/channel-metadata-0.1.schema.json"),
  "receipt":(receipt(events["claim"]["id"]),"schema/receipt-0.1.schema.json"),
  "evidence":(evidence(),"schema/evidence-0.1.schema.json"),
  "projection":({"specversion":"0.1","channel_id":"channel:release","work_uri":WORK,"state":"claimed","contenders":[U[20]],"handoff_offer_ids":[],"diagnostics":[],"diagnostics_high_water_sequence":1,"as_of_sequence":1,"completeness":"complete","lifecycle":"active","final":True},"schema/projection-0.1.schema.json")}
 for name,(obj,schema) in meta.items():
  rel=f"conformance/fixtures/positive/{name}.json"; write(ROOT/rel,obj); index.append({"path":rel,"schema":schema,"valid":True})
 # Conditional branches beyond the one-per-signal baseline.
 def add(name,obj,schema,valid,reason=None):
  rel=f"conformance/fixtures/{'positive' if valid else 'negative'}/{name}.json"; write(ROOT/rel,obj); row={"path":rel,"schema":schema,"valid":valid}
  if reason: row["reason"]=reason
  index.append(row)
 successor=json.loads(json.dumps(events["claim"])); successor["id"]=U[13]; successor["correlation_id"]=U[13]; successor["causation_id"]=U[9]; successor["data"]["claim_id"]=U[23]; successor["data"]["predecessor_handoff_event"]=U[9]
 add("event-claim-successor",successor,"schema/envelope-0.1.schema.json",True)
 bad=json.loads(json.dumps(successor)); bad.pop("causation_id"); add("event-claim-successor-missing-causation",bad,"schema/envelope-0.1.schema.json",False,"INVALID_ENVELOPE")
 bad=json.loads(json.dumps(events["claim"])); bad["causation_id"]=U[9]; add("event-claim-root-with-causation",bad,"schema/envelope-0.1.schema.json",False,"INVALID_ENVELOPE")
 for offset,outcome in enumerate(["mismatch","unavailable","unauthorized","inconclusive"],14):
  obj=json.loads(json.dumps(events["evidence_verification"])); obj["id"]=U[offset]; obj["data"]["outcome"]=outcome
  if outcome=="mismatch": obj["data"]["observed_digest"]="sha-256:"+"3"*64
  else: obj["data"].pop("observed_digest"); obj["data"]["reason"]=outcome
  add(f"event-evidence-verification-{outcome}",obj,"schema/envelope-0.1.schema.json",True)
 bad=json.loads(json.dumps(events["evidence_verification"])); bad["data"].pop("observed_digest"); add("verification-verified-without-observed",bad,"schema/envelope-0.1.schema.json",False,"INVALID_PAYLOAD")
 bad=json.loads(json.dumps(events["evidence_verification"])); bad["data"]["outcome"]="unavailable"; bad["data"].pop("observed_digest"); add("verification-unavailable-without-reason",bad,"schema/envelope-0.1.schema.json",False,"INVALID_PAYLOAD")
 access={"type":"https://yukh.dev/problems/access-denied","title":"Access denied","status":403,"code":"ACCESS_DENIED","trace_id":"trace","retryable":False}
 resource={"type":"https://yukh.dev/problems/resource-limit","title":"Resource limit reached","status":429,"code":"RESOURCE_LIMIT","trace_id":"trace","retryable":False}
 add("problem-access-denied",access,"schema/problem-0.1.schema.json",True); add("problem-resource-limit",resource,"schema/problem-0.1.schema.json",True)
 bad={**access,"detail":"existence leak"}; add("problem-access-denied-detail",bad,"schema/problem-0.1.schema.json",False,"ACCESS_DENIED_SHAPE")
 bad={**resource,"status":409}; add("problem-resource-wrong-status",bad,"schema/problem-0.1.schema.json",False,"RESOURCE_LIMIT_SHAPE")
 basep=meta["projection"][0]
 for state,claims,offers in [("unclaimed",[],[]),("released",[],[]),("handoff_offered",[U[20]],[U[21]]),("conflicting",[U[20],U[21]],[])]:
  obj=json.loads(json.dumps(basep)); obj.update(state=state,contenders=claims,handoff_offer_ids=offers); add(f"projection-{state}",obj,"schema/projection-0.1.schema.json",True)
 bad=json.loads(json.dumps(basep)); bad["diagnostics_high_water_sequence"]=2; add("projection-high-water-mismatch",bad,"schema/projection-0.1.schema.json",False,"SEMANTIC")
 bad=json.loads(json.dumps(basep)); bad.update(state="handoff_offered",handoff_offer_ids=[]); add("projection-handoff-without-offer",bad,"schema/projection-0.1.schema.json",False,"INVALID_PROJECTION")
 bad=json.loads(json.dumps(meta["receipt"][0])); bad["append_outcome"]="duplicate"; add("receipt-duplicate-outcome",bad,"schema/receipt-0.1.schema.json",False,"INVALID_RECEIPT")
 bad=json.loads(json.dumps(meta["evidence"][0])); bad.pop("declared_size"); add("evidence-missing-size",bad,"schema/evidence-0.1.schema.json",False,"INVALID_EVIDENCE")
 bad=json.loads(json.dumps(meta["channel"][0])); bad["unexpected"]="x"; add("channel-extra-property",bad,"schema/channel-metadata-0.1.schema.json",False,"INVALID_CHANNEL")
 write(FIX/"index.json",index)
 receipt_preimage=json.loads(json.dumps(meta["receipt"][0])); receipt_preimage.pop("signature")
 vector_values={"event":events["claim"],"channel":meta["channel"][0],"evidence-descriptor":evidence(),"evidence-set":[evidence()],"receipt":meta["receipt"][0],"receipt-signature-preimage":receipt_preimage,"diagnostics":[{"sequence":2,"code":"CLAIM_CONFLICT","severity":"warning","primary_id":U[3],"contender_ids":[U[20],U[21]],"contender_event_ids":[U[3],U[4]]}]}
 domains={"channel":"yukh.channel-metadata.v0.1\u0000","evidence-descriptor":"yukh.evidence-descriptor.v0.1\u0000","evidence-set":"yukh.evidence-set.v0.1\u0000","receipt-signature-preimage":"yukh-coordination-receipt-v0.1\u0000"}
 vectors=[]
 for name,obj in vector_values.items():
  inp=f"conformance/canonical/{name}.input.json"; out=f"conformance/canonical/{name}.canonical.json"; write(ROOT/inp,obj); canonical=jcs(obj); (ROOT/out).write_bytes(canonical)
  row={"name":name,"input":inp,"canonical":out,"digest":"sha-256:"+hashlib.sha256(canonical).hexdigest()}
  if name in domains:
   row["domain_prefix"]=domains[name]; row["domain_digest"]="sha-256:"+hashlib.sha256(domains[name].encode()+canonical).hexdigest()
  vectors.append(row)
 write(CAN/"index.json",vectors)
 allowlist=OUT/"manifest-inputs.txt"
 names=[line for line in allowlist.read_text().splitlines() if line and not line.startswith("#")]
 if names != sorted(set(names)): raise SystemExit("manifest allow-list must be unique and sorted")
 files=[ROOT/name for name in names]
 missing=[str(path.relative_to(ROOT)) for path in files if not path.is_file()]
 candidates={*(p for p in OUT.rglob("*") if p.is_file() and p.name!="SHA256SUMS"), *ROOT.joinpath("schema").rglob("*.json"), *ROOT.joinpath("js").rglob("*.mjs"), *ROOT.joinpath("test").rglob("*.mjs"), ROOT/"package.json", ROOT/".gitignore", ROOT/"docs/rfc/0001-protocol-v0.1.md", ROOT/"docs/rfc/0002-mvp-security-boundary.md"}
 unlisted=sorted(str(path.relative_to(ROOT)) for path in candidates-set(files))
 if missing or unlisted: raise SystemExit(f"manifest allow-list mismatch missing={missing} unlisted={unlisted}")
 (OUT/"SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n" for p in files))

if __name__=="__main__": main()
