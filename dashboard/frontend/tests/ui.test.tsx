import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { detailMessage } from "@/lib/api";
import { fmtNum, fmtTime, pct, severityClass } from "@/lib/format";
import { Empty, ErrorState, Severity, Table } from "@/components/ui";

describe("format helpers", () => {
  it("formats values and never invents data", () => {
    expect(fmtNum(null)).toBe("-");
    expect(pct(undefined)).toBe("-");
    expect(pct(0.5)).toBe("50.0%");
    expect(fmtTime(null)).toBe("-");
    expect(fmtTime("2026-01-02T03:04:05+00:00")).toBe("2026-01-02 03:04:05Z");
    expect(severityClass("critical")).toBe("sev-critical");
  });
  it("extracts FastAPI validation messages", () => {
    expect(detailMessage({ detail: "nope" }, "x")).toBe("nope");
    expect(detailMessage({ detail: [{ loc: ["body", "pid"], msg: "bad" }] }, "x")).toBe("pid: bad");
    expect(detailMessage(null, "fallback")).toBe("fallback");
  });
});

describe("ui states", () => {
  it("renders empty state for empty tables", () => {
    render(<Table rows={[]} columns={[{ key: "a", label: "A" }]} empty="Nothing here" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });
  it("renders rows", () => {
    render(<Table rows={[{ a: "hello" }]} columns={[{ key: "a", label: "A" }]} />);
    expect(screen.getByText("hello")).toBeInTheDocument();
  });
  it("error state is announced", () => {
    render(<ErrorState message="boom" />);
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
  });
  it("severity badge and empty", () => {
    render(<><Severity value="CRITICAL" /><Empty title="E" /></>);
    expect(screen.getByText("CRITICAL")).toHaveClass("sev-critical");
  });
});
