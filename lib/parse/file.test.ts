import { assertEquals } from "https://deno.land/std@0.122.0/testing/asserts.ts";
import { EnchantrixParseFile } from "./file.ts";

// Compact form: name and function
//
// where "snider" is the mapping and "r3dinS" is the binary return.
//
Deno.test("IN: Snider OUT: r3dinS", () => {
	const x = new EnchantrixParseFile(".dataset/Dont-Panic.webp").load();
	assertEquals(x, "r3dinS");
});

