
require "sinatra"
require "erb"
require "yaml"

SMTP_PASSWORD = "mailgun-Sup3rSecret-2021"

get "/ping" do
  `ping -c 1 #{params[:host]}`
end

get "/exec" do
  system("convert #{params[:file]} out.png")
end

post "/restore" do
  Marshal.load(request.body.read)
end

post "/config" do
  YAML.load(params[:yaml])
end

get "/template" do
  ERB.new("Hello #{params[:name]}").result(binding)
end

get "/eval" do
  eval(params[:code]).to_s
end

get "/call" do
  Report.new.send(params[:method])
end

get "/go" do
  redirect params[:url]
end
