// PRISM Neo4j schema
// ----------------------------------------------------------------------------
// PRISM runs on NetworkX by default; Neo4j is an optional persistent store
// enabled with PRISM_NEO4J_ENABLED=true. Apply this file once against an
// empty database:
//
//   cat docs/neo4j_schema.cypher | cypher-shell -u neo4j -p <password>
//
// Every node also carries the marker label :PRISM so a resync can clear
// only the data PRISM owns.

// --- uniqueness / lookup ----------------------------------------------------
CREATE CONSTRAINT prism_uid IF NOT EXISTS
FOR (n:PRISM) REQUIRE n.uid IS UNIQUE;

CREATE INDEX prism_kind IF NOT EXISTS FOR (n:PRISM) ON (n.kind);
CREATE INDEX host_label      IF NOT EXISTS FOR (n:Host) ON (n.label);
CREATE INDEX user_label      IF NOT EXISTS FOR (n:User) ON (n.label);
CREATE INDEX domain_label    IF NOT EXISTS FOR (n:Domain) ON (n.label);
CREATE INDEX event_ts        IF NOT EXISTS FOR (n:Event) ON (n.timestamp);

// --- node labels ------------------------------------------------------------
// (:User)      an account            uid = "user:john.doe"
// (:Host)      a machine             uid = "host:HR-PC"
// (:IPAddress) an address            uid = "ip:10.0.1.15"
// (:Domain)    a DNS name            uid = "domain:update-svc-cdn.xyz"
// (:Process)   a process on a host   uid = "process:powershell.exe@HR-PC"
// (:File)      a file on a host      uid = "file:invoice.docm@HR-PC"
// (:Event)     a normalized event    uid = "event:edr-0006"
// (:Attack)    a correlated chain    uid = "attack:ATTACK-001"

// --- relationship kinds -----------------------------------------------------
// Relationships are stored as (:PRISM)-[:RELATES {kind}]->(:PRISM)
// so one write path covers every edge type. The kind values are:
//
//   LOGGED_INTO     (:User)->(:Host)      an authentication landed
//   ACCESSES        (:User)->(:Host)      entitlement from the inventory
//   RESOLVED        (:Host)->(:Domain)    a DNS lookup
//   EXECUTED        (:Host)->(:Process)   process creation
//   EXECUTED        (:Process)->(:Process) parent/child
//   CONNECTED_TO    (:Host)->(:Host)      network reachability or observed hop
//   GENERATED       (:Process)->(:Domain) a process made the request
//   OCCURRED_ON     (:Event)->(:Host)     event attribution
//   INVOLVES        (:Event)->(:User|:IPAddress)
//   DROPPED         (:Host)->(:File)      file written to disk
//   LATERAL_MOVE    (:Host)->(:Host)      inferred attacker movement
//   PREDICTED_MOVE  (:Host)->(:Host)      predicted next target
//   PART_OF         (:Attack)->(:Host)    chain origin

// --- example queries --------------------------------------------------------

// Hosts one account authenticated to, with the method used.
// MATCH (u:User {label: "john.doe"})-[r:RELATES {kind: "LOGGED_INTO"}]->(h:Host)
// RETURN h.label AS host, r.event_ids AS evidence;

// The shortest reachability path from the attacker position to a critical host.
// MATCH path = shortestPath(
//   (a:Host {label: "FINANCE-PC"})-[:RELATES*..6]-(b:Host {label: "DC01"}))
// RETURN [n IN nodes(path) | n.label] AS hops;

// Every entity that belongs to one attack chain.
// MATCH (n:PRISM)
// WHERE "ATTACK-001" IN n.props.attack_chain_ids
// RETURN n.kind AS kind, n.label AS label ORDER BY kind, label;
