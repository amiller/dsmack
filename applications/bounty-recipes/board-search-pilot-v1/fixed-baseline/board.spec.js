import { test, expect } from '@playwright/test'

test('add a card, move it, and it survives reload', async ({ page }) => {
  const errors = []
  page.on('console', m => m.type() === 'error' && errors.push(m.text()))
  page.on('pageerror', e => errors.push(e.message))

  await page.goto('/apps/board/')
  const board = page.getByTestId('board')
  await expect(board).toHaveAttribute('data-ready', 'true')
  await expect(page.getByRole('link', { name: 'All apps' })).toHaveAttribute('href', '../../')

  await page.getByTestId('new-todo').fill('Write the checker')
  await page.getByTestId('add-todo').click()
  const todoCard = page.getByTestId('column-todo').getByTestId('card')
  await expect(todoCard).toHaveText(/Write the checker/)
  await expect(board).toHaveAttribute('data-saved', '1')

  await todoCard.locator('[data-action="right"]').click()
  await expect(page.getByTestId('column-todo').getByTestId('card')).toHaveCount(0)
  await expect(page.getByTestId('column-doing').getByTestId('card')).toHaveText(/Write the checker/)
  await expect(board).toHaveAttribute('data-saved', '2')

  await page.reload()
  await expect(board).toHaveAttribute('data-ready', 'true')
  await expect(page.getByTestId('column-doing').getByTestId('card')).toHaveText(/Write the checker/)
  await expect(page.getByTestId('column-todo').getByTestId('card')).toHaveCount(0)
  expect(errors).toEqual([])
})
