#!deno run --allow-read --allow-net

import * as path from "https://deno.land/std@0.122.0/path/mod.ts";
import { readableStreamFromReader } from "https://deno.land/std@0.122.0/streams/mod.ts";
import {EnchantrixLog} from '../log.ts';

export class EnchantrixParseFile {

	protected _input: string;
	protected _data: any;

	constructor(file: string) {
		this._input = file;
	}

	load() {

		try {
			this._data = Deno.openSync(this._input, { read: true });
			const stat = this._data.statSync();

		} catch {
			throw new EnchantrixLog('Failed to load file')
		}

// Build a readable stream so the file doesn't have to be fully loaded into
// memory while we send it
		const readableStream = readableStreamFromReader(this._data);

		return readableStream

	}
}
