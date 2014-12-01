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
require './lib/u2f/authentication_response'
include U2F

use Rack::Session::Cookie, secret: 'TODO FIXME CHANGEME LOL'
disable :protection

ORIGIN = ENV['U2F_ORIGIN'] || 'http://u2f-sinatra.127.0.0.1.xip.io:9292'

get '/' do
  req = RegistrationRequest.new ORIGIN
  session[:reg_challenge] = req.challenge

  haml :index, locals: { reg_req: req }
end

get '/huh' do
  content_type 'text/plain'
  ""
end

post '/register' do
  rrh = JSON.parse params[:registration_response]
  reg_resp = RegistrationResponse.new rrh, origin: ORIGIN, challenge: session[:reg_challenge]

  raise "mismatched challenge" unless reg_resp.matching_challenge?

  raise "mismatched appid and origin" unless reg_resp.matching_appid_and_origin?

  session[:public_key] = reg_resp.user_public_key
  session[:key_handle] = reg_resp.key_handle

  req = AuthenticationRequest.new session[:key_handle], ORIGIN

  session[:auth_challenge] = req.challenge

  haml :register, locals: { reg_resp: reg_resp, auth_req: req, session: session }
end

post '/sign' do
  arh = JSON.parse params[:authentication_response]
pp session[:auth_challenge]
  auth_resp = AuthenticationResponse.new arh, origin: ORIGIN, challenge: session[:auth_challenge], public_key: session[:public_key], key_handle: session[:key_handle]

  raise "mismatched challenge" unless auth_resp.matching_challenge?
  raise "mismatched appid and origin" unless auth_resp.matching_appid_and_origin?
  raise "mismatched key handle" unless auth_resp.matching_key_handle?
  raise "invalid signature" unless auth_resp.valid_signature?

  haml :signed, locals: {auth_resp: auth_resp}
end