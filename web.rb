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

require './lib/u2f/registration_response'
include U2F

enable :sessions

ORIGIN = ENV['U2F_ORIGIN'] || 'http://u2f-sinatra.127.0.0.1.xip.io:9292'

get '/' do
  session[:challenge] = SecureRandom.urlsafe_base64(32)

  client_data = { 
    typ: 'navigator.id.getAssertion',
    challenge: session[:challenge],
    origin: ORIGIN,
    cid_pubkey: ''
  }

  haml :index, locals: { client_data: client_data }
end

post '/register' do
  rrh_size = params[:registration_response_size].to_i
  raise "mis-sized" if params[:registration_response].length != rrh_size

  rrh = JSON.parse params[:registration_response]
  reg_resp = RegistrationResponse.new rrh, origin: ORIGIN, challenge: session[:challenge]
  haml :register, locals: { rrh: rrh, reg_resp: reg_resp }
end

get '/idk_try_something' do
  rr = RegistrationResponse.new JSON.parse('{"registrationData":"BQTLTuc3iRt8g63MVvA24Zc3m1YavO2rrv_9cDSqhlk4wmyC3yjxFd2ibfzlVdnSCzZ5ktgtLNIwQs4qRcwmqpouQLQ352ltNeYAc8MtW07oRhjUVhwe6XS-FyjhVlMTOMRhRymXxVqljpqzNsDj2VyarpGHEbNcnPPpGT3O7vQgyK8wggIcMIIBBqADAgECAgQk26tAMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKzEpMCcGA1UEAwwgWXViaWNvIFUyRiBFRSBTZXJpYWwgMTM1MDMyNzc4ODgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQCsJS-NH1HeUHEd46-xcpN7SpHn6oeb-w5r-veDCBwy1vUvWnJanjjv4dR_rV5G436ysKUAXUcsVe5fAnkORo2oxIwEDAOBgorBgEEAYLECgEBBAAwCwYJKoZIhvcNAQELA4IBAQCjY64OmDrzC7rxLIst81pZvxy7ShsPy2jEhFWEkPaHNFhluNsCacNG5VOITCxWB68OonuQrIzx70MfcqwYnbIcgkkUvxeIpVEaM9B7TI40ZHzp9h4VFqmps26QCkAgYfaapG4SxTK5k_lCPvqqTPmjtlS03d7ykkpUj9WZlVEN1Pf02aTVIZOHPHHJuH6GhT6eLadejwxtKDBTdNTv3V4UlvjDOQYQe9aL1jUNqtLDeBHso8pDvJMLc0CX3vadaI2UVQxM-xip4kuGouXYj0mYmaCbzluBDFNsrzkNyL3elg3zMMrKvAUhoYMjlX_-vKWcqQsgsQ0JtSMcWMJ-umeDMEYCIQD114BFu9aQWpvngkg-LjTN4NIMg4WXaIYF4PoD2VtWRQIhAMy6N8M5A8r2ehk4kAdbAcchRuiLD_asBvmgY3nLbCv8","challenge":"6Zjkgl6aGVDyJQ6ge-dlNDCPShM-h6oyuf6DCg2zOAE","version":"U2F_V2","appId":"http://demo.yubico.com","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjZaamtnbDZhR1ZEeUpRNmdlLWRsTkRDUFNoTS1oNm95dWY2RENnMnpPQUUiLCJvcmlnaW4iOiJodHRwOi8vZGVtby55dWJpY28uY29tIiwiY2lkX3B1YmtleSI6IiJ9"}')
  content_type 'text/plain'
  rr.decoded_registration_data.pretty_inspect
end