# passport-atlassian-connect
Passport.js strategy for Atlassian products add-ons

```javascript
const strategy = new AtlassianConnectStrategy({
  baseUrl: 'https://your-addon-url.com',
  product: 'jira',
})

const handleInstall = passport.authenticate('atlassian-connect', {
  loadCredentials: clientKey => {
    return model.Credentials.findOne({ clientKey })
  },
  saveCredentials: (clientKey, newCredentials, storedCredentials) => {
    if (storedCredentials) {
      return storedCredentials.update(newCredentials)
    }

    return model.Credentials.create(newCredentials)
  }
})

const handleAuth = passport.authenticate('atlassian-connect', {
  loadCredentials: clientKey => {
    return model.Credentials.findOne({ clientKey })
  },
  onAuthenticated: (jwtPayload, storedCredentials, req) => {
    req.credentials = storedCredentials
  }
})

const app = express()
  .post('/api/hooks/jira/installed', handleInstall)
  .post('/api/hooks/jira/uninstalled', handleAuth, handleUninstall)
  .post('/api/hooks/jira/project/created', handleAuth, handleProjectCreated)

```