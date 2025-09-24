import { createHmac } from 'crypto'

const maxRequestAgeInSeconds = 600 // 10 minutes

export const verifyRequest = async ({
  headers,
  body,
  method,
  url,
  secret,
}: {
  headers: Record<string, string>
  body: Buffer
  method: string
  url: string
  secret: string
}) => {
  const receivedSignature = headers['x-texterid-request-signature']
  const timestamp = headers['x-texterid-request-timestamp'] ?? '0'
  const nonce = headers['x-texterid-request-nonce']

  // Verify request age to prevent replay attacks
  if (Date.now() / 1000 - parseInt(timestamp) > maxRequestAgeInSeconds) {
    return false
  }

  // Optionally: you can store the already seen nonce values (temporarily, for the last 10 minutes) to prevent replay attacks

  const dataToVerify = [method, url, body.toString('base64'), timestamp, nonce].join('\n')
  const calculatedSignature = createHmac('sha256', secret).update(dataToVerify).digest('base64')

  return calculatedSignature === receivedSignature
}
