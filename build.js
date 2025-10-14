const fs = require('fs');
const path = require('path');

console.log('🚀 Building SQLi Scanner Extension...');
console.log('');

// Create dist directory
const distDir = 'dist';
if (fs.existsSync(distDir)) {
    console.log('🗑️  Cleaning old dist folder...');
    fs.rmSync(distDir, { recursive: true, force: true });
}
fs.mkdirSync(distDir, { recursive: true });

// Copy manifest.json
console.log('📄 Copying manifest.json...');
try {
    fs.copyFileSync('src/manifest.json', path.join(distDir, 'manifest.json'));
    console.log('   ✓ manifest.json');
} catch (error) {
    console.error('   ❌ Failed to copy manifest.json:', error.message);
    process.exit(1);
}

// Create directory structure
const dirs = [
    'dist/background',
    'dist/content',
    'dist/devtools',
    'dist/panel',
    'dist/shared',
    'dist/utils',
    'dist/assets/icons'
];

console.log('');
console.log('📁 Creating directory structure...');
dirs.forEach(dir => {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`   ✓ ${dir}`);
});

// Copy icon files from root icons/ folder to dist/assets/icons/
console.log('');
console.log('🎨 Copying icon files...');
const iconSizes = [16, 48, 128];
iconSizes.forEach(size => {
    const iconFile = `icon${size}.png`;
    const srcPath = path.join('icons', iconFile);
    const destPath = path.join('dist', 'assets', 'icons', iconFile);

    try {
        if (fs.existsSync(srcPath)) {
            fs.copyFileSync(srcPath, destPath);
            console.log(`   ✓ ${iconFile}`);
        } else {
            console.warn(`   ⚠️  Icon not found: ${srcPath}`);
        }
    } catch (error) {
        console.error(`   ❌ Error copying ${iconFile}:`, error.message);
    }
});

// Copy files
const filesToCopy = [
    { src: 'src/background/sw.js', dest: 'dist/background/sw.js' },
    { src: 'src/content/content.js', dest: 'dist/content/content.js' },
    { src: 'src/devtools/devtools.html', dest: 'dist/devtools/devtools.html' },
    { src: 'src/devtools/devtools.js', dest: 'dist/devtools/devtools.js' },
    { src: 'src/panel/index.html', dest: 'dist/panel/index.html' },
    { src: 'src/panel/index.js', dest: 'dist/panel/index.js' },
    { src: 'src/panel/styles.css', dest: 'dist/panel/styles.css' },
    { src: 'src/shared/payloads.js', dest: 'dist/shared/payloads.js' },
    { src: 'src/shared/db_errors.js', dest: 'dist/shared/db_errors.js' },
    { src: 'src/shared/remediation.js', dest: 'dist/shared/remediation.js' },
    { src: 'src/shared/types.js', dest: 'dist/shared/types.js' },
    { src: 'src/utils/diff.js', dest: 'dist/utils/diff.js' },
    { src: 'src/utils/timing.js', dest: 'dist/utils/timing.js' },
    { src: 'src/utils/hash.js', dest: 'dist/utils/hash.js' },
    { src: 'src/utils/storage.js', dest: 'dist/utils/storage.js' },
    { src: 'src/utils/permissions.js', dest: 'dist/utils/permissions.js' }
];

console.log('');
console.log('📋 Copying extension files...');
let successCount = 0;
let failCount = 0;

filesToCopy.forEach(file => {
    try {
        if (fs.existsSync(file.src)) {
            fs.copyFileSync(file.src, file.dest);
            console.log(`   ✓ ${file.src}`);
            successCount++;
        } else {
            console.warn(`   ⚠️  File not found: ${file.src}`);
            failCount++;
        }
    } catch (error) {
        console.error(`   ❌ Error copying ${file.src}:`, error.message);
        failCount++;
    }
});

console.log('');
console.log('═══════════════════════════════════════════════');
if (failCount === 0) {
    console.log('✅ Build completed successfully!');
    console.log(`📊 Copied ${successCount} files + 3 icons`);
} else {
    console.log('⚠️  Build completed with warnings');
    console.log(`📊 Success: ${successCount} | Failed: ${failCount}`);
}
console.log('═══════════════════════════════════════════════');
console.log('');
console.log('📁 Extension ready in dist/ folder');
console.log('');
console.log('📋 Next steps:');
console.log('1. Open Chrome and go to chrome://extensions/');
console.log('2. Enable "Developer mode" (toggle in top-right)');
console.log('3. Click "Load unpacked"');
console.log('4. Select the dist/ folder');
console.log('5. Look for "SQLi Scanner" in DevTools!');
console.log('');
