/**
 * Reproducible salts from input without prior knowledge
 *
 * @example const salt = new EnchantrixSaltQuasiEntropy('Snider').salty()
 */
export class EnchantrixSaltQuasiEntropy {

	/**
	 * Extend to enforce a custom mapping
	 *
	 * @protected
	 */
	protected charMap = {
		'o': '0',
		'l': "1",
		'e': "3",
		'a': "4",
		's': "z",
		't': "7",
	}

	protected readonly _input: string = ''

	/**
	 * Supply the input
	 *
	 * @param input
	 */
	constructor(input: string) {
		this._input = input
	}

	get keyMap():any {
		return this.charMap
	}

	/**
	 *
	 * @param {string} input
	 * @returns {string}
	 */
	salty(): string {
		if (!this._input) {
			return '';
		}

		let i: number = this._input.length;
		let salt:string[] = []
		while (i--) {
			salt.push(this._input[i] === this.keyMap[this._input[i]] ? this.keyMap[this._input[i]] : this._input[i]);
		}

		return salt.join('');
	}

}
