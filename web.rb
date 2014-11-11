require 'sinatra'
# require 'better_errors'
require 'securerandom'
require 'json'
require 'haml'
require 'pp'

# configure :development do
#   use BetterErrors::Middleware
#   BetterErrors.application_root = __dir__
# end

require './lib/u2f/registration_request'
require './lib/u2f/registration_response'
require './lib/u2f/authentication_request'
include U2F

enable :sessions

ORIGIN = ENV['U2F_ORIGIN'] || 'http://u2f-sinatra.127.0.0.1.xip.io:9292'

get '/' do
  req = RegistrationRequest.new ORIGIN
  session[:challenge] = req.challenge

  haml :index, locals: { reg_req: req }
end

post '/register' do
  rrh = JSON.parse params[:registration_response]
  reg_resp = RegistrationResponse.new rrh, origin: ORIGIN, challenge: session[:challenge]

  raise "mismatched challenge" unless reg_resp.matching_challenge?

  raise "mismatched appid and origin" unless reg_resp.matching_appid_and_origin?

  session[:public_key] = reg_resp.user_public_key
  session[:key_handle] = reg_resp.key_handle

  req = AuthenticationRequest.new session[:key_handle], ORIGIN

  session[:challenge] = req.challenge

  haml :register, locals: { reg_resp: reg_resp, auth_req: req }
end
