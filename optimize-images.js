const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const ASSETS = path.join(__dirname, 'assets');
const images = ['orka-ai-frame.png', 'orka-logo.png', 'orka-symbol.png', 'orka-symbol-cream.png'];

(async () => {
  console.log('🖼️  Otimizando imagens...\n');
  for (const file of images) {
    const input = path.join(ASSETS, file);
    const base = path.basename(file, path.extname(file));
    const outWebP = path.join(ASSETS, base + '.webp');
    const before = fs.statSync(input).size;

    // WebP com qualidade 85 — ótimo custo/benefício
    await sharp(input)
      .webp({ quality: 85, effort: 6 })
      .toFile(outWebP);

    const after = fs.statSync(outWebP).size;
    const saving = ((1 - after / before) * 100).toFixed(1);
    console.log(`  ${file}`);
    console.log(`    PNG: ${(before/1024).toFixed(0)}KB  →  WebP: ${(after/1024).toFixed(0)}KB  (−${saving}%)`);
  }
  console.log('\n✅ Imagens convertidas para WebP');
})();
