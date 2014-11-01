require 'sinatra'
require 'securerandom'
require 'json'

enable :sessions

get '/' do
  session[:challenge] = SecureRandom.urlsafe_base64(32)

  client_data = { 
    typ: 'navigator.id.getAssertion',
    challenge: session[:challenge],
    origin: 'http://u2f-sinatra.127.0.0.1.xip.io',
    cid_pubkey: ''
  }

  haml :index, locals: { client_data: client_data }
end
