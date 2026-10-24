import { test, expect } from '@playwright/test'

test('routes loads a sample, switches samples and opens a file', async ({ page }) => {
  const errors = []
  page.on('console', m => m.type() === 'error' && errors.push(m.text()))
  page.on('pageerror', e => errors.push(e.message))
  await page.goto('/apps/routes/')

  await expect(page.getByTestId('stat-distance')).toHaveText('4.02 km')
  await expect(page.getByTestId('stat-gain')).toHaveText('865 m')
  await expect(page.locator('#route-name')).toHaveText('Alpine Switchback Climb')
  await expect(page.getByRole('link', { name: /all apps/ })).toHaveAttribute('href', '../../')

  await page.getByTestId('sample').selectOption('samples/riverside-loop.gpx')
  await expect(page.getByTestId('stat-distance')).toHaveText('9.11 km')
  await expect(page.getByTestId('stat-count')).toHaveText('301')
  await expect(page.locator('#route-name')).toHaveText('Riverside Loop')
  const n = await page.locator('#track polyline').getAttribute('points')
  expect(n.trim().split(/\s+/)).toHaveLength(301)
  await expect(page.locator('#profile polyline')).toHaveCount(1)

  const gpx = '<gpx><trk><trkseg><trkpt lat="0" lon="0"><ele>10</ele></trkpt><trkpt lat="0.01" lon="0"><ele>35</ele></trkpt></trkseg></trk></gpx>'
  await page.getByTestId('file').setInputFiles({ name: 'tiny.gpx', mimeType: 'application/gpx+xml', buffer: Buffer.from(gpx) })
  await expect(page.locator('#route-name')).toHaveText('tiny')
  await expect(page.getByTestId('stat-distance')).toHaveText('1.11 km')
  await expect(page.getByTestId('stat-gain')).toHaveText('25 m')

  expect(errors).toEqual([])
})
