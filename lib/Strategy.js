const AbstractStrategy = require('passport-strategy')
const jwt = require('atlassian-jwt')

const StrategyError = require('./StrategyError')

class AtlassianConnectStrategy extends AbstractStrategy {
  constructor ({ product, localBaseUrl, handleKnownErrors = true }) {
    super()
    this.name = 'atlassian-connect'
    this.product = product
    this.localBaseUrl = localBaseUrl
    this.handleKnownErrors = handleKnownErrors
  }

  async authenticate (req, {skipQsh, onAuthenticated, saveCredentials, loadCredentials}) {
    try {
      if (!onAuthenticated) {
        await this._saveCredentials(req, {saveCredentials, loadCredentials})
        this.pass()
      } else {
        const payload = await this._validateCredentials(req, {skipQsh, onAuthenticated, loadCredentials})
        this.success(payload)
      }
    } catch (error) {
      this.handleKnownErrors && error instanceof StrategyError
        ? this.fail(error.message)
        : this.error(error)
    }
  }

  _extractToken (req) {
    const token = req.headers['authorization'] || ''
    return token.replace(/^JWT /, '')
  }

  _validateQsh (req, payload) {
    if (!payload.qsh) {
      return
    }

    const expectedHash = jwt.createQueryStringHash(req, false, this.localBaseUrl)

    if (payload.qsh !== expectedHash) {
      throw new StrategyError('Session invalid')
    }
  }

  _validateToken (token, sharedSecret) {
    let payload

    try {
      payload = jwt.decode(token, sharedSecret)
    } catch (error) {
      throw new StrategyError('Invalid signature')
    }

    const now = Math.floor(Date.now() / 1000)

    if (payload.exp && now > payload.exp) {
      throw new StrategyError('Token expired')
    }

    return payload
  }

  async _saveCredentials (req, store) {
    const id = this.product === 'bitbucket'
      ? req.body.principal.uuid
      : req.body.clientKey

    const storedCredentials = await store.loadCredentials(id)
    const token = this._extractToken(req)

    if (token && jwt.decode(token, '', true).iss !== id) {
      throw new StrategyError('Wrong issuer')
    }

    // Create allowed if nothing was found by id.
    // Sometimes request signed (but we can't validate), sometimes not.
    if (!storedCredentials) {
      await store.saveCredentials(id, req.body)
      return
    }

    // Update allowed only if request was signed
    if (storedCredentials && token) {
      const payload = this._validateToken(token, storedCredentials.sharedSecret)
      this._validateQsh(req, payload)

      await store.saveCredentials(id, req.body, storedCredentials)
      return
    }

    throw new StrategyError('Unauthorized update request')
  }

  async _validateCredentials (req, {skipQsh, onAuthenticated, loadCredentials}) {
    const token = this._extractToken(req)
    if (!token) {
      throw new StrategyError('Missed token')
    }

    const id = jwt.decode(token, '', true).iss
    const storedCredentials = await loadCredentials(id)

    if (!storedCredentials) {
      throw new StrategyError('Unknown issuer')
    }

    const payload = this._validateToken(token, storedCredentials.sharedSecret)
    if (!skipQsh) {
      this._validateQsh(req, payload)
    }

    onAuthenticated(payload, storedCredentials, req)
    return payload
  }
}

module.exports = AtlassianConnectStrategy
