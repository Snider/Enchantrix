export class EnchantrixLog {

	constructor(entry: string, level: number = 1) {
		switch (level) {
			case 0:
				break;
			case 1:
				console.log(entry)
				break
			case 2:
				console.warn(entry)
		}
	}
}
