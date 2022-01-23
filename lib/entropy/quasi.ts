/**
 * Reproducible salts from input without prior knowledge
 */
export class EnchantrixEntropyQuasi {

	/**
	 * Extend to enforce a custom mapping
	 *
	 * @protected
	 */
	// deno-lint-ignore no-explicit-any
	protected charMap:any = {
		' ': '',
		'o': '0',
		'l': "1",
		'e': "3",
		'a': "4",
		's': "z",
		't': "7",
	}

	/**
	 * @type {string} Origin Input
	 * @protected
	 */
	protected readonly _input: string = ''

	/**
	 * Initiate with input to work on
	 *
	 * @param input
	 */
	constructor(input: string) {
		this._input = input
	}

	/**
	 * Returns CharMap
	 *
	 * @returns {{'[char]': string}}
	 */
	// deno-lint-ignore no-explicit-any
	get keyMap():any {
		return this.charMap
	}

	/**
	 * Performs salt on input
	 *
	 * @returns {string} Salted Input
	 */
	salty(): string {
		if (!this._input) {
			return '';
		}

		let i: number = this._input.length

		const salt:string[] = []

		while (i--) {
			// If Char is in the map, use the replaced value; otherwise use original char
			salt.push(this.keyMap[this._input[i]] !== undefined ? this.keyMap[this._input[i]] : this._input[i])
		}

		return salt.join('')
	}

}
