import { assertEquals } from "https://deno.land/std@0.122.0/testing/asserts.ts";
import { EnchantrixEntropyQuasi } from "./quasi.ts";

// Compact form: name and function
Deno.test("IN: Snider OUT: r3dinS", () => {
  const x = new EnchantrixEntropyQuasi("Snider").salty();
  assertEquals(x, "r3dinS");
});
// Compact form: name and function
Deno.test("IN: snider OUT: r3dinz", () => {
  const x = new EnchantrixEntropyQuasi("snider").salty();
  assertEquals(x, "r3dinz");
});

Deno.test("IN: a long string with spaces and workds and much letters and stuff OUT: ffu7zdn4zr37731hcumdn4zdkr0wdn4z3c4pzh7iwgnir7zgn014", () => {
  const x = new EnchantrixEntropyQuasi(
    "a long string with spaces and workds and much letters and stuff",
  ).salty();
  assertEquals(x, "ffu7zdn4zr37731hcumdn4zdkr0wdn4z3c4pzh7iwgnir7zgn014");
});
