-- Analytics plugin handler.
--
-- How it works:
-- Keep track of calls made to configured APIs on a per-worker basis, using the ALF format
-- (alf_serializer.lua) and per-API buffers. `:access()` and `:body_filter()` are implemented to record some properties
-- required for the ALF entry.
--
-- When an API buffer is full (it reaches the `batch_size` configuration value or the maximum payload size), send the batch to the server.
--
-- In order to keep Analytics as real-time as possible, we also start a 'delayed timer' running in background.
-- If no requests are made during a certain period of time (the `delay` configuration value), the
-- delayed timer will fire and send the batch + flush the data, not waiting for the buffer to be full.
--
-- @see alf_serializer.lua
-- @see buffer.lua

local ALFBuffer = require "kong.plugins.mashape-analytics.buffer"
local BasePlugin = require "kong.plugins.base_plugin"
local ALFSerializer = require "kong.plugins.log-serializers.alf"

local ngx_now = ngx.now
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR

local ALF_BUFFERS = {} -- buffers per-api

local AnalyticsHandler = BasePlugin:extend()

function AnalyticsHandler:new()
  AnalyticsHandler.super.new(self, "mashape-analytics")
end

function AnalyticsHandler:access(conf)
  AnalyticsHandler.super.access(self)

  -- Retrieve and keep in memory the bodies for this request
  ngx.ctx.analytics = {
    req_body = "",
    res_body = "",
    req_post_args = {}
  }

  ngx.req.read_body()

  local status, res = pcall(ngx.req.get_post_args)
  if not status then
    if res == "requesty body in temp file not supported" then
      ngx_log(ngx_log_ERR, "[mashape-analytics] cannot read request body from temporary file. Try increasing the client_body_buffer_size directive.")
    else
      ngx_log(ngx_log_ERR, res)
    end
  else
    ngx.ctx.analytics.req_post_args = res
  end

  if conf.log_body then
    ngx.ctx.analytics.req_body = ngx.req.get_body_data()
  end
end

function AnalyticsHandler:body_filter(conf)
  AnalyticsHandler.super.body_filter(self)

  local chunk, eof = ngx.arg[1], ngx.arg[2]
  -- concatenate response chunks for ALF's `response.content.text`
  if conf.log_body then
    ngx.ctx.analytics.res_body = ngx.ctx.analytics.res_body..chunk
  end

  if eof then -- latest chunk
    ngx.ctx.analytics.response_received = ngx_now() * 1000
  end
end

function AnalyticsHandler:log(conf)
  AnalyticsHandler.super.log(self)

  local api_id = ngx.ctx.api.id

  -- Create the ALF buffer if not existing for this API
  if not ALF_BUFFERS[api_id] then
    ALF_BUFFERS[api_id] = ALFBuffer.new(conf)
  end

  local buffer = ALF_BUFFERS[api_id]

  -- Creating the ALF
  local alf = ALFSerializer.new_alf(ngx, conf.service_token, conf.environment)
  if alf then
    -- Simply adding the ALF to the buffer, it will decide if it is necessary to flush itself
    buffer:add_alf(alf)
  end
end

return AnalyticsHandler
