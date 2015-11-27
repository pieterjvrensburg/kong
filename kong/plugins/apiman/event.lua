-- Event generator module for Globetom API Management.

local cjson = require "cjson"
local http = require "resty_http"
local utils = require "kong.tools.utils"
local cache = require "kong.tools.database_cache"

local APIMAN_DETAILS = {
  host = "apiman.event.com",
  port = "80",
  path = "/apiman/api/v1/event",
  events = { "issue_token", "rate_limiting", "ip_restriction" }
}
local CLIENT_ID = "client_id"
local CLIENT_SECRET = "client_secret"

local _M = {}

local function retrieve_parameters(event)
  if event ~= "rate_limiting" then
    ngx.req.read_body()
  end

  -- OAuth2 parameters could be in both the querystring or body
  return utils.table_merge(ngx.req.get_uri_args(), ngx.req.get_post_args())
end

local function retrieve_client_credentials(parameters, event)
  local client_id, client_secret
  local authorization_header = ngx.req.get_headers()["authorization"]
  if parameters[CLIENT_ID] then
    client_id = parameters[CLIENT_ID]
    client_secret = parameters[CLIENT_SECRET]
  elseif authorization_header then
    local iterator, iter_err = ngx.re.gmatch(authorization_header, "\\s*[Bb]asic\\s*(.+)")
    if not iterator then
      ngx.log(ngx.ERR, iter_err)
      return
    end

    local m, err = iterator()
    if err then
      ngx.log(ngx.ERR, err)
      return
    end

    if m and table.getn(m) > 0 then
      local decoded_basic = ngx.decode_base64(m[1])
      if decoded_basic then
        local basic_parts = stringy.split(decoded_basic, ":")
        client_id = basic_parts[1]
        client_secret = basic_parts[2]
      end
    end
  end

  -- check if perhaps it is in the oauth token
  if not client_id then
    if ngx.ctx.authenticated_credential then
      client_id = ngx.ctx.authenticated_credential.client_id
      client_secret = ngx.ctx.authenticated_credential.client_secret
    end
  end

  return client_id, client_secret
end

local function send(pre, payload)
  ngx.log(ngx.DEBUG, "[apiman] sending payload: ", payload)

  -- create new http client
  local client = http:new()
  -- set timeout to 5s
  client:set_timeout(50000)

  -- connect
  local ok, err = client:connect(APIMAN_DETAILS.host, APIMAN_DETAILS.port)
  if ok then
    -- send
    local res, err = client:request({ method = "POST", path = APIMAN_DETAILS.path, body = payload })
    if not res then
      ngx.log(ngx.ERR, "[apiman] failed to send: ", err)
    elseif res.status == 200 then
      ngx.log(ngx.DEBUG, "[apiman] successfully sent event")
    elseif res.status == 400 then
      ngx.log(ngx.ERR, "[apiman] failed to send, refused: ", res.status)
    else
      ngx.log(ngx.ERR, "[apiman] failed to send: ", res.status)
    end

    -- close connection, or put it into the connection pool
    if not res or res.headers["connection"] == "close" then
      ok, err = client:close()
      if not ok then
      -- ngx.log(ngx.ERR, "[apiman] failed to close socket: ", err)
      end
    else
      client:set_keepalive()
    end
  else
    ngx.log(ngx.ERR, "[apiman] failed to connect to server: ", err)
  end
end

function _M.submit(conf, parameters)
  local e = parameters["event_type"]
  
  -- check if we support this type of event
  if not utils.table_contains(APIMAN_DETAILS.events, e) then
    ngx.log(ngx.ERR, "[apiman] unsupported event: ", e)
    return
  end
   
  -- get global values
  local params = retrieve_parameters(e)
  local client_id, client_secret = retrieve_client_credentials(params, e)

  local int = {
    api = ngx.ctx.api.name,
    remote_addr = ngx.var.remote_addr,
    uri = ngx.var.request_uri,
    client_id = client_id,
    client_secret = client_secret
  }

  -- merge with submitted parameters
  int = utils.table_merge(int, parameters)

  -- submit to backend
  local ok, err = ngx.timer.at(0, send, cjson.encode(int))
  if not ok then
    ngx.log(ngx.ERR, "[apiman] failed to create timer: ", err)
  end
end

return _M
