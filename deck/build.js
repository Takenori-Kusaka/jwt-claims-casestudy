const fs = require('fs');
const { makeLib, prepIcons, THEME } = require('./lib');
const { applyTheme } = require('./theme');
const PARTS = ['p00', 'p01', 'p02', 'p03', 'p04', 'p05', 'p06'].filter((p) => fs.existsSync(p + '.js'));
(async () => {
  const src = ['lib.js', ...PARTS.map((p) => p + '.js')].map((f) => fs.readFileSync(f, 'utf8')).join('\n');
  const names = [...new Set(src.match(/'Md[A-Za-z]+'/g).map((s) => s.slice(1, -1)))];
  await prepIcons(names);
  const L = makeLib();
  PARTS.forEach((p) => require('./' + p)(L));
  const out = process.argv[2] || 'JWT_クレーム設計ケーススタディ.pptx';
  await L.pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log('wrote', out);
})().catch((e) => { console.error(e); process.exit(1); });
