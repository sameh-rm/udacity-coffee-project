export const environment = {
  production: true,
  apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
  auth0: {
    url: 'urokai-auth.us', // the auth0 domain prefix
    audience: 'coffeeshop', // the audience set for the auth0 app
    clientId: 'vrr3RaMJu2mOItxKTvB2tpqCbOw74z6W', // the client id generated for the auth0 app
    callbackURL: '/', // the base url of the running ionic application. 
  }
};
