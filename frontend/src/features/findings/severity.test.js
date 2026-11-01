import { describe, expect, it } from "vitest";

import { describeChange, describeRuleEntry, portText } from "./severity.js";

describe("severity helpers", () => {
  it("formats ports", () => {
    expect(portText({ protocol: "tcp", from_port: 22, to_port: 22 })).toBe(
      "tcp/22",
    );
    expect(portText({ protocol: "tcp", from_port: 20, to_port: 30 })).toBe(
      "tcp/20-30",
    );
    expect(portText({ protocol: "-1", from_port: null, to_port: null })).toBe(
      "all traffic",
    );
  });

  it("describes matching rule entries with direction and 1-based number", () => {
    expect(
      describeRuleEntry({
        direction: "ingress",
        index: 1,
        protocol: "tcp",
        from_port: 22,
        to_port: 22,
        cidr: "0.0.0.0/0",
      }),
    ).toBe("ingress rule #2: tcp/22 from 0.0.0.0/0");
    expect(
      describeRuleEntry({
        direction: "egress",
        index: 0,
        protocol: "-1",
        from_port: null,
        to_port: null,
        cidr: "0.0.0.0/0",
      }),
    ).toBe("egress rule #1: all traffic to 0.0.0.0/0");
  });

  it("describes each proposed action", () => {
    const base = {
      security_group_id: "sg-db",
      protocol: "tcp",
      from_port: 5432,
      to_port: 5432,
    };
    expect(
      describeChange({
        ...base,
        action: "replace_ingress_source",
        new_source_security_group_id: "sg-app",
      }),
    ).toBe("sg-db · tcp/5432: allow only sg-app");
    expect(
      describeChange({
        ...base,
        action: "restrict_ingress_cidr",
        new_cidr: "10.0.0.0/8",
      }),
    ).toBe("sg-db · tcp/5432: allow only 10.0.0.0/8");
    expect(describeChange({ ...base, action: "remove_ingress_rule" })).toBe(
      "sg-db · tcp/5432: remove the 0.0.0.0/0 entry",
    );
  });
});