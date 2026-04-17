export function hasSqliPayloadSignal(value: string) {
  if (/%27(?:%20|\+)*(?:or|and|union|--|%2d%2d)/i.test(value)) return true
  return /('(?:\s*--|\s+or\s+|%27)|union\s+select|sleep\s*\(|waitfor\s+delay|\)\)\s*or\s*\()/i.test(value)
}

export function hasAuthSuccessSignal(value: string) {
  return /"authentication"\s*:|"token"\s*:|"session"\s*:|welcome|login succeeded|auth/i.test(value)
}

export function hasVerboseErrorSignal(value: string) {
  if (/\n\s*at\s+[^\n]+/i.test(value)) return true
  if (/sequelizedatabaseerror|sqlite_error|postgreserror|mysql/i.test(value)) return true
  if (/<pre>[\s\S]*error[\s\S]*<\/pre>/i.test(value)) return true
  return false
}
