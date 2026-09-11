#!/usr/bin/env bash
# Runs every M0 scenario from a clean server each time.
set -u
cd "$(dirname "$0")"

run() {
  node server.ts > /tmp/spike-server.log 2>&1 &
  local SERVER=$!
  sleep 1
  node agent.ts > /tmp/spike-agent.log 2>&1 &
  local AGENT=$!
  sleep 1
  node drive.ts "$1"
  local RC=$?
  kill $AGENT $SERVER 2>/dev/null
  wait $AGENT $SERVER 2>/dev/null
  return $RC
}

run approve || exit 1
run deny || exit 1

echo
echo "=== context budget under pressure (30 tokens) ==="
node server.ts > /tmp/spike-server.log 2>&1 &
SERVER=$!
sleep 1
node agent.ts > /tmp/spike-agent.log 2>&1 &
AGENT=$!
sleep 1
node drive.ts approve > /dev/null 2>&1
TH=$(curl -s localhost:4000/snapshot | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).threads[0].id))")
curl -s "localhost:4000/context?thread_id=$TH&budget_tokens=30" | node -e "
let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
  const c=JSON.parse(s);
  console.log('kept '+c.segments.length+', dropped '+c.dropped_events+', '+c.used_tokens+'/'+c.budget_tokens+' tokens');
  console.log('kept types: '+c.segments.map(x=>x.type).join(', '));
  const gotApproval=c.segments.some(x=>x.type==='approval_request')&&c.segments.some(x=>x.type==='approval_response');
  console.log(gotApproval ? 'PASS: approvals survived the squeeze' : 'FAIL: approvals were dropped');
})"
kill $AGENT $SERVER 2>/dev/null
