// Fixed, trusted feature checks; candidate functions execute ONLY in Chromium.
import {test,expect} from '/opt/bounty-judges/primary-fixtures.mjs';
import assert from 'node:assert/strict';

async function seed(page) {
  await page.goto('/apps/board/');
  await page.locator('[data-testid=board][data-ready=true]').waitFor();
  let saved=0;
  for(const [column,text] of [['todo','Alpha one'],['todo','unrelated'],['doing','ALPHA two'],['done','alpha three']]) {
    await page.getByTestId('new-'+column).fill(text);
    await page.getByTestId('add-'+column).click();
    await expect(page.getByTestId('board')).toHaveAttribute('data-saved',String(++saved));
  }
  await expect(page.getByTestId('card')).toHaveCount(4);
}
test('baseline-add-and-reload',async({page})=>{
  await seed(page);await page.reload();
  await page.locator('[data-testid=board][data-ready=true]').waitFor();
  await expect(page.getByTestId('card')).toHaveCount(4);
});
test('search-case-insensitive-all-columns',async({page})=>{
  await seed(page);await page.getByTestId('search').fill('AlPhA');
  for(const column of ['todo','doing','done'])await expect(page.getByTestId('column-'+column).getByTestId('card')).toHaveCount(1);
  for(const [column,text] of [['todo','1/2'],['doing','1/1'],['done','1/1']])
    await expect(page.getByTestId('column-'+column).locator('h2 span')).toHaveText(text);
});
test('search-trim-empty-and-view-only-persistence',async({page})=>{
  await seed(page);await page.getByTestId('search').fill('   alpha   ');
  await expect(page.getByTestId('card')).toHaveCount(3);
  await page.getByTestId('search').fill('   ');await expect(page.getByTestId('card')).toHaveCount(4);
  await page.getByTestId('search').fill('alpha');await page.reload();
  await page.locator('[data-testid=board][data-ready=true]').waitFor();
  await expect(page.getByTestId('card')).toHaveCount(4);
});
test('filtered-move-targets-original-card',async({page})=>{
  await seed(page);await page.getByTestId('search').fill('unrelated');
  await page.getByTestId('column-todo').getByTestId('card').locator('[data-action=right]').click();
  await expect(page.getByTestId('column-doing').getByTestId('card')).toHaveCount(1);
  await page.getByTestId('search').fill('');
  await expect(page.getByTestId('column-todo').getByTestId('card')).toHaveCount(1);
  await expect(page.getByTestId('column-doing').getByTestId('card')).toHaveCount(2);
});
test('logic-filter-ids-no-mutation',async({page})=>{
  await page.goto('/__primary_logic__/');
  const observed=await page.evaluate(async()=>{
    const logic=await import('/apps/board/logic.js');
    const board={nextId:4,columns:{todo:[{id:'c1',text:'Alpha'}],doing:[{id:'c2',text:'beta ALPHA'}],done:[{id:'c3',text:'other'}]}};
    const matched=logic.filterBoard(board,'  ALPHA  '),blank=logic.filterBoard(board,'  ');
    return {matched,blank,after:board};
  });
  // Expectations/authority stay outside the renderer. No self-reported pass.
  assert.deepEqual(observed,{matched:{todo:['c1'],doing:['c2'],done:[]},
    blank:{todo:['c1'],doing:['c2'],done:['c3']},
    after:{nextId:4,columns:{todo:[{id:'c1',text:'Alpha'}],doing:[{id:'c2',text:'beta ALPHA'}],done:[{id:'c3',text:'other'}]}}});
});
test('export-keeps-unfiltered-board',async({page})=>{
  await seed(page);await page.getByTestId('search').fill('no-matches');
  await expect(page.getByTestId('card')).toHaveCount(0);
  const pending=page.waitForEvent('download');await page.getByTestId('export').click();
  const stream=await (await pending).createReadStream();assert.ok(stream);
  const chunks=[];let size=0;
  for await(const chunk of stream) {size+=chunk.length;assert.ok(size<=65536,'download byte bound');chunks.push(chunk);}
  const board=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  assert.equal(Object.values(board.columns).flat().length,4);
  assert.deepEqual(Object.keys(board).sort(),['columns','nextId']);
  await page.getByTestId('search').fill('');
});
