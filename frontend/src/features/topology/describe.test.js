import { describe, expect, it } from "vitest";

import { describeNaclRule, describeSgRule, detailRows, portText } from "./describe.js";
import { TOPOLOGY } from "../../test/topologyFixture.js";

describe("describe helpers", () => {
  it("formats ports", () => {
    expect(portText({ protocol: "tcp", from_port: 443, to_port: 443 })).toBe("tcp/443");
    expect(portText({ protocol: "tcp", from_port: 8000, to_port: 8100 })).toBe("tcp/8000-8100");
    expect(portText({ protocol: "-1", from_port: null, to_port: null })).toBe("all traffic");
    expect(portText({ protocol: "icmp", from_port: null, to_port: null })).toBe("icmp");
  });

  it("describes security group rules by direction", () => {
    expect(describeSgRule({ protocol: "tcp", from_port: 22, to_port: 22, cidr: "0.0.0.0/0" }, "ingress")).toBe(
      "tcp/22 from 0.0.0.0/0",
    );
    expect(
      describeSgRule({ protocol: "tcp", from_port: 5432, to_port: 5432, destination_security_group_id: "sg-db" }, "egress"),
    ).toBe("tcp/5432 to sg-db");
  });

  it("describes NACL rules", () => {
    expect(describeNaclRule({ rule_number: 100, action: "deny", protocol: "-1", cidr: "10.0.0.0/8" })).toBe(
      "#100 deny all traffic 10.0.0.0/8",
    );
  });
});

describe("detailRows", () => {
  const find = (id) => TOPOLOGY.nodes.find((n) => n.id === id);
  const row = (rows, label) => rows.find((r) => r.label === label);

  it("shows readable facts for an instance, hiding empty values", () => {
    const rows = detailRows(find("i-web-1"));
    expect(row(rows, "Private IP").values).toEqual(["10.0.1.10"]);
    expect(row(rows, "Public IP").values).toEqual(["203.0.113.10"]);
    expect(row(rows, "Has public IP").values).toEqual(["yes"]);
    expect(row(rows, "Tags").values).toEqual(["tier: web"]);
    expect(rows.every((r) => r.values.length > 0)).toBe(true);
  });

  it("renders security group rules as sentences", () => {
    const rows = detailRows(find("sg-web"));
    expect(row(rows, "Ingress rules").values).toEqual(["tcp/443 from 0.0.0.0/0"]);
    expect(row(rows, "Egress rules").values).toEqual(["tcp/5432 to sg-db"]);
  });

  it("omits empty rule lists and null fields", () => {
    const rows = detailRows(find("sg-app"));
    expect(row(rows, "Ingress rules")).toBeUndefined();
    const subnet = detailRows(find("subnet-private"));
    expect(row(subnet, "Internet gateway")).toBeUndefined();
    expect(row(subnet, "Subnet kind").values).toEqual(["private"]);
  });
});