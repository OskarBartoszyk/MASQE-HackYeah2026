import { chromium } from '/Users/oskar/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';
const browser = await chromium.launch({headless:true,channel:'chrome'});
try {
  const page=await browser.newPage({viewport:{width:1440,height:900},deviceScaleFactor:1.5});
  await page.addInitScript(()=>{
    localStorage.setItem('masqe-demo','false');
    localStorage.setItem('masqe-key',JSON.stringify('secops-demo-key'));
  });
  await page.goto(process.argv[2],{waitUntil:'domcontentloaded'});
  await page.getByRole('heading',{name:'Operations center',exact:true}).waitFor();
  await page.waitForTimeout(2500);
  await page.screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/console.png'});
  const main=await page.locator('main').boundingBox();
  await page.screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/console-main.png',clip:{x:main.x,y:0,width:main.width,height:760}});
  await page.getByRole('navigation').getByRole('button',{name:'Ghost Shell',exact:true}).click();
  await page.getByText('Chain verified',{exact:true}).waitFor();
  await page.screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/ghost.png'});
  await page.locator('.evidence-panel').screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/evidence.png'});
  await page.locator('.terminal-panel').screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/terminal.png'});
  const incident=await page.locator('.incident-status').boundingBox();
  const stats=await page.locator('.evidence-stats').boundingBox();
  await page.screenshot({path:'/Users/oskar/Desktop/HackYeah2026/tmp/pitch/evidence-top.png',clip:{x:incident.x,y:incident.y,width:incident.width,height:stats.y+stats.height-incident.y}});
  console.log('Captured actual operations console, Ghost Shell and incident evidence.');
} finally {await browser.close();}
