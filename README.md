# pgsql metrics

This is a running repository for tools that extract resource and performance
metrics from PCAP traces of PostgreSQL traffic (v3 wire protocol).  It
currently relies on modified version of scapy which can be downloaded and
installed in the current Python environment using `./setup.sh`.

## metrics.py

This script will run throught the traces and calculate metrics per "group"
(RPC roundtrip) and transaction (client sending `Parse(BEGIN)` to server
sending `CommandComplete(COMMIT)`) labeled by the 4-tuple for the connection.
The metrics currently collected are:

- Bytes sent by client
- Bytes sent by server (transaction metrics do not include the final "ReadyForQuery")
- Time spent waiting on client (always 0 for group metrics)
- Time spent waiting on server

Network delay is not accounted for in this estimation so physical location of
the process making the packet capture will affect the "time spent" metrics.

**NOTE:** This assumes that the client has not optimized their interaction and
  does an explicit `Parse(BEGIN)` at the start of every transaction.
  Additionally, this does not currently handle nested transactions.