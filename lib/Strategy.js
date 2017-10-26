const AbstractStrategy = require('passport-strategy')
const {Addon, AuthError} = require('atlassian-connect-auth')

class AtlassianConnectStrategy extends AbstractStrategy {
  constructor (options) {
    super()
    this.name = 'atlassian-connect'
    this.addon = new Addon(options)
  }

  async authenticate (req, {handleInstallation, skipQsh, saveCredentials, loadCredentials}) {
    try {
      const { credentials, payload } = handleInstallation
        ? await this.addon.install(req, {saveCredentials, loadCredentials})
        : await this.addon.auth(req, { skipQsh, loadCredentials })

      this.success(credentials, payload)
    } catch (error) {
      error instanceof AuthError
        ? this.fail(error.message)
        : this.error(error)
    }
  }
}

module.exports = AtlassianConnectStrategy
