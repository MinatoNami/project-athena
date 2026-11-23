/**
 * Fetch a JSON document through the BFF and hand it to the browser as a file.
 *
 * Done here rather than with a plain link because the proxy forwards a body and a
 * content type, not `Content-Disposition` — and a link that opens 4 MB of JSON in
 * a tab is not an export.
 */
export async function downloadJson(path: string, filename: string): Promise<number> {
  const document = await api<any>(path)
  const text = JSON.stringify(document, null, 2)
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const a = window.document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
  return text.length
}
