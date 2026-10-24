import { test, expect } from '@playwright/test'

test('puzzle loads, solves level 1 with buttons and keys, and undoes', async ({ page }) => {
  const errors = []
  page.on('console', m => m.type() === 'error' && errors.push(m.text()))
  page.on('pageerror', e => errors.push(e.message))
  await page.goto('/apps/puzzle/')
  await expect(page.getByTestId('level').locator('option')).toHaveCount(6)
  await expect(page.locator('#board .player')).toHaveCount(1)
  await expect(page.locator('#board .box')).toHaveCount(1)
  await expect(page.getByRole('link', { name: /arcade/ })).toHaveAttribute('href', '../../')

  await page.getByTestId('move-r').click()
  await expect(page.getByTestId('moves')).toHaveText('1')
  await expect(page.getByTestId('pushes')).toHaveText('0')
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('ArrowRight')
  await expect(page.getByTestId('moves')).toHaveText('3')
  await expect(page.getByTestId('pushes')).toHaveText('2')
  await expect(page.locator('#board .box.goal')).toHaveCount(1)
  await expect(page.getByTestId('status')).toContainText('Solved')

  await page.getByTestId('undo').click()
  await expect(page.getByTestId('moves')).toHaveText('2')
  await expect(page.getByTestId('status')).toHaveText('')
  await expect(page.locator('#board .box.goal')).toHaveCount(0)
  expect(errors).toEqual([])
})
