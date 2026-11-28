export async function downloadJson(path: string, filename: string): Promise<number> {
  const document = await api<any>(path)
  const text = JSON.stringify(document, null, 2)
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
  const a = window.document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  revokeLater(url)
  return text.length
}
