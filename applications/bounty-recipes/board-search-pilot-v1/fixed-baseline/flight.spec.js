import { test, expect } from '@playwright/test'

test('flight loads, flies, and responds to throttle', async ({ page }) => {
  const errors = []
  page.on('console', m => m.type() === 'error' && errors.push(m.text()))
  page.on('pageerror', e => errors.push(e.message))
  await page.goto('/apps/flight/')
  await expect(page).toHaveTitle('Flight')
  await expect(page.locator('a[href="../../"]')).toBeVisible()
  await expect(page.getByTestId('game')).toHaveAttribute('data-status', 'flying')
  await expect(page.getByTestId('score')).toHaveText('0/12')
  const throttle = async () => parseInt(await page.getByTestId('throttle').textContent())
  const before = await throttle()
  await page.keyboard.down('ArrowRight')
  await page.waitForTimeout(800)
  await page.keyboard.up('ArrowRight')
  expect(await throttle()).toBeGreaterThan(before + 20)
  await page.keyboard.down('ArrowDown')
  await expect(page.getByTestId('game')).toHaveAttribute('data-status', 'crashed', { timeout: 10000 })
  await page.keyboard.up('ArrowDown')
  await page.keyboard.press('KeyR')
  await expect(page.getByTestId('game')).toHaveAttribute('data-status', 'flying')
  expect(errors).toEqual([])
})
