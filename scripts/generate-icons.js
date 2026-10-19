import fs from 'fs';
import path from 'path';

// Valid 1x1 cyan PNG buffer
const cyanPngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkWPjfDwAExgHVy1/Y9QAAAABJRU5ErkJggg==';
const buffer = Buffer.from(cyanPngBase64, 'base64');

const targetDir = path.resolve('extension');
['icon16.png', 'icon48.png', 'icon128.png'].forEach((file) => {
  fs.writeFileSync(path.join(targetDir, file), buffer);
});

console.log('Extension icon PNGs generated.');
