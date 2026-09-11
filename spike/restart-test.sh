#!/usr/bin/env bash
# Does `await ctx.requestApproval()` actually survive an agent restart?
# The SDK comment claims it does "by construction". This checks.
set -u
cd "$(dirname "$0")"

jqnode() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);$1})"; }

node server.ts > /tmp/spike-server.log 2>&1 &
SERVER=$!
sleep 1
node agent.ts > /tmp/spike-agent1.log 2>&1 &
AGENT=$!
sleep 1

TH=$(curl -s localhost:4000/snapshot | jqnode 'console.log(j.threads[0].id)')

curl -s -X POST localhost:4000/events -H 'content-type: application/json' -d "{
  \"thread_id\":\"$TH\",
  \"actor\":{\"id\":\"usr_ada\",\"kind\":\"human\",\"display_name\":\"Ada\"},
  \"type\":\"message\",\"body\":{\"text\":\"ship it\"},\"fallback_text\":\"ship it\",
  \"to\":[\"agt_deploy\"]}" > /dev/null
sleep 1

echo "--- killing agent while it awaits approval, then restarting it ---"
kill $AGENT 2>/dev/null; wait $AGENT 2>/dev/null
node agent.ts > /tmp/spike-agent2.log 2>&1 &
AGENT2=$!
sleep 2

read -r APR EVT <<< "$(curl -s localhost:4000/snapshot | jqnode 'const e=j.events.find(x=>x.type==="approval_request");console.log(e.body.approval_id+" "+e.id)')"

curl -s -X POST localhost:4000/events -H 'content-type: application/json' -d "{
  \"thread_id\":\"$TH\",
  \"actor\":{\"id\":\"usr_ada\",\"kind\":\"human\",\"display_name\":\"Ada\"},
  \"type\":\"approval_response\",
  \"body\":{\"approval_id\":\"$APR\",\"decision\":\"approved\",\"decided_by\":{\"id\":\"usr_ada\",\"kind\":\"human\",\"display_name\":\"Ada\"}},
  \"fallback_text\":\"approved\",\"causation_id\":\"$EVT\"}" > /dev/null
sleep 3

echo "--- final event log ---"
curl -s localhost:4000/snapshot | jqnode '
  j.events.forEach(e=>console.log("  "+e.seq+". "+e.type+(e.body.status?"/"+e.body.status:"")+" — "+e.fallback_text.slice(0,58)));
  const done=j.events.some(e=>e.type==="action"&&["succeeded","failed","denied"].includes(e.body.status));
  console.log("\nthread status: "+j.threads[0].status);
  console.log(done ? "RESULT: action completed after restart" : "RESULT: action never completed — the await was lost with the process");
'

kill $AGENT2 $SERVER 2>/dev/null
