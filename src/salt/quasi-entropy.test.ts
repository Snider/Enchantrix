import { assertEquals } from "https://deno.land/std@0.122.0/testing/asserts.ts";
import {EnchantrixSaltQuasiEntropy} from "./quasi-entropy.ts";

// Compact form: name and function
Deno.test("IN: Snider OUT: redinS", () => {
	const x = new EnchantrixSaltQuasiEntropy('Snider').salty();
	assertEquals(x, 'redinS');
});
// Compact form: name and function
Deno.test("IN: snider OUT: redins", () => {
	const x = new EnchantrixSaltQuasiEntropy('snider').salty();
	assertEquals(x, 'redins');
});

Deno.test("Medium Input, Large Salt", () => {
	const x = new EnchantrixSaltQuasiEntropy('a long string with spaces and workds and much letters and stuff').salty();
	assertEquals(x, 'ffuts dna srettel hcum dna sdkrow dna secaps htiw gnirts gnol a');
});
