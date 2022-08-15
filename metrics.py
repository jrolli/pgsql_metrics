#!/usr/bin/env python3

import argparse
import copy
import csv
import scapy.contrib.postgres

from scapy.all import sniff
from scapy.sessions import TCPSession


def _csv_for_metrics(filepath, collected_metrics):
    if len(collected_metrics) == 0:
        print("No metrics collected!")
        return

    metrics = list(collected_metrics[0].keys())
    with open(filepath, "w") as f:
        csv_writer = csv.DictWriter(f, fieldnames=metrics, delimiter=",", quotechar='"')
        csv_writer.writeheader()
        for row in collected_metrics:
            csv_writer.writerow(row)


class Connection:
    def __init__(self):
        self.to_parse = []
        self.to_bind = []
        self.to_describe = []
        self.to_execute = []
        self.statements = {}
        self.portals = {}
        self.last_client_ts = 0
        self.last_server_ts = 0
        self.with_client = True
        self.group_metrics = []
        self.current_group_metrics = {}
        self.txn_metrics = []
        self.current_txn_metrics = None

    def _get_metrics(self, metrics, label=None):
        output = copy.deepcopy(metrics)
        for row in output:
            row["label"] = label
        return output

    def get_group_metrics(self, label=None):
        return self._get_metrics(self.group_metrics, label)

    def get_txn_metrics(self, label=None):
        return self._get_metrics(self.txn_metrics, label)

    def process_client_messages(self, packet):
        ts = packet.time
        for msg in packet["PostgresFrontend"].contents:
            assert self.with_client
            if self.current_group_metrics:
                self.current_group_metrics["client_bytes"] += len(msg)
            elif not self.current_group_metrics:
                self.current_group_metrics = {
                    "statements": [],
                    "client_bytes": len(msg),
                    "server_bytes": 0,
                    "client_wait": 0,
                    "server_wait": 0,
                }

            if self.current_txn_metrics:
                self.current_txn_metrics["client_bytes"] += len(msg)

            if "Parse" in msg:
                p = msg["Parse"]
                self.to_parse.append((ts, p.destination, p.query))

                if p.query.upper() == b"BEGIN":
                    self.current_txn_metrics = {
                        "statements": [],
                        "client_bytes": len(msg),
                        "server_bytes": 0,
                        "client_wait": 0,
                        "server_wait": 0,
                    }
            elif "Bind" in msg:
                p = msg["Bind"]
                self.to_bind.append((ts, p.destination, p.statement))
            elif "Describe" in msg:
                p = msg["Describe"]
                self.to_describe.append((ts, p.close_type, p.statement))
            elif "Execute" in msg:
                p = msg["Execute"]
                self.to_execute.append((ts, p.portal))
            elif "Sync" in msg:
                assert self.with_client
                if self.last_server_ts != 0 and self.current_txn_metrics:
                    self.current_txn_metrics["client_wait"] += (
                        packet.time - self.last_server_ts
                    )
                self.last_client_ts = packet.time
                self.with_client = False

    def process_server_messages(self, packet):
        ts = packet.time
        for msg in packet["PostgresBackend"].contents:
            assert not self.with_client
            self.current_group_metrics["server_bytes"] += len(msg)
            if self.current_txn_metrics:
                self.current_txn_metrics["server_bytes"] += len(msg)
            if "ParseComplete" in msg:
                query, self.to_parse = self.to_parse[0], self.to_parse[1:]
                self.statements[query[1]] = query[2]
            elif "BindComplete" in msg:
                statement, self.to_bind = self.to_bind[0], self.to_bind[1:]
                self.portals[statement[1]] = self.statements[statement[2]]
            elif "RowDescription" in msg:
                describe, self.to_describe = self.to_describe[0], self.to_describe[1:]
            elif "DataRow" in msg:
                # Returned data
                pass
            elif "CommandComplete" in msg:
                portal, self.to_execute = self.to_execute[0], self.to_execute[1:]
                query = self.portals[portal[1]]
                self.current_group_metrics["statements"].append(query)
                if self.current_txn_metrics:
                    self.current_txn_metrics["statements"].append(query)
                    if query.upper() == b"COMMIT":
                        self.current_txn_metrics["server_wait"] += (
                            packet.time - self.last_client_ts
                        )
                        self.current_txn_metrics["statements"] = b";".join(
                            self.current_txn_metrics["statements"]
                        ).decode()
                        self.txn_metrics.append(self.current_txn_metrics)
                        self.current_txn_metrics = None

            elif "ReadyForQuery" in msg:
                assert not self.with_client
                self.current_group_metrics["server_wait"] += (
                    packet.time - self.last_client_ts
                )
                if self.current_txn_metrics:
                    self.last_server_ts = packet.time
                else:
                    self.last_server_ts = 0
                self.with_client = True
                self.current_group_metrics["statements"] = b";".join(
                    self.current_group_metrics["statements"]
                ).decode()
                self.group_metrics.append(self.current_group_metrics)
                self.current_group_metrics = None


def analyze(traces, txn_metrics_file, group_metrics_file):
    group_metrics = []
    txn_metrics = []

    for tracefile in traces:
        print(f"Processing '{tracefile}'...")
        trace = sniff(offline=tracefile, session=TCPSession)
        connections = {}
        for packet in trace:
            if "PostgresFrontend" in packet:
                # Client to server packet
                conntag = f"{packet['IP'].src}:{packet['TCP'].sport}-{packet['IP'].dst}:{packet['TCP'].dport}"
                if conntag not in connections.keys():
                    connections[conntag] = Connection()
                connections[conntag].process_client_messages(packet)
            elif "PostgresBackend" in packet:
                # Server to client packet
                conntag = f"{packet['IP'].dst}:{packet['TCP'].dport}-{packet['IP'].src}:{packet['TCP'].sport}"
                if conntag in connections.keys():
                    connections[conntag].process_server_messages(packet)
        for conntuple, conn in connections.items():
            group_metrics += conn.get_group_metrics(label=conntuple)
            txn_metrics += conn.get_txn_metrics(label=conntuple)

    _csv_for_metrics(group_metrics_file, group_metrics)
    _csv_for_metrics(txn_metrics_file, txn_metrics)


def main():
    parser = argparse.ArgumentParser(description="connection & server metric tool")
    parser.add_argument("traces", nargs="+", help="PCAP files with session traces")
    parser.add_argument(
        "--txn_metrics", default="txns.csv", help="where to save transaction metrics"
    )
    parser.add_argument(
        "--group_metrics", default="groups.csv", help="where to save group metrics"
    )
    args = parser.parse_args()

    analyze(args.traces, args.txn_metrics, args.group_metrics)


if __name__ == "__main__":
    main()
